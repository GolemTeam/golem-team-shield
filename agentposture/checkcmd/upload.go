package checkcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

// -upload sends a repository's findings to Golem (docs/design-agent-posture.md,
// "Repositories, from CI"), so a security team sees them in the console beside
// each machine's. It is opt-in, and the credential is a CI token minted in the
// console, read from the environment and never from a flag, so it stays out of
// shell history and process lists. A failure prints one line and leaves the
// exit code alone: the check gates the build the same with or without Golem.
const (
	TokenEnv   = "GOLEM_CHECK_TOKEN"
	URLEnv     = "GOLEM_URL"
	DefaultURL = "https://relay.golem.team"

	maxUploadItems = 200
)

var (
	uploadRepoRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$`)
	uploadCommitRe = regexp.MustCompile(`^([a-f0-9]{40}|[a-f0-9]{64})$`)
)

type uploadTarget struct {
	url, repo, commit, ref string
}

// resolve fills what the flags left empty from the environment: GOLEM_URL,
// then GitHub Actions' variables, then GitLab CI's.
func (t uploadTarget) resolve() uploadTarget {
	if t.url == "" {
		t.url = firstEnv(URLEnv)
	}
	if t.url == "" {
		t.url = DefaultURL
	}
	if t.repo == "" {
		t.repo = firstEnv("GITHUB_REPOSITORY", "CI_PROJECT_PATH")
	}
	if t.commit == "" {
		t.commit = firstEnv("GITHUB_SHA", "CI_COMMIT_SHA")
	}
	if t.ref == "" {
		t.ref = firstEnv("GITHUB_REF")
	}
	if t.ref == "" {
		if b := firstEnv("CI_COMMIT_BRANCH"); b != "" {
			t.ref = "refs/heads/" + b
		} else if tag := firstEnv("CI_COMMIT_TAG"); tag != "" {
			t.ref = "refs/tags/" + tag
		}
	}
	return t
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// baseURL accepts https anywhere and plain http only on this machine, so the
// token never crosses a network in the clear.
func baseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the Golem URL is not a plain https address")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("the Golem URL must be https")
		}
	default:
		return "", errors.New("the Golem URL must be https")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

var uploadClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func upload(stderr io.Writer, name string, t uploadTarget, res agentposture.Result) {
	if err := sendUpload(t.resolve(), res, stderr, name); err != nil {
		fmt.Fprintf(stderr, "%s: not sent to Golem: %s\n", name, err)
	}
}

func sendUpload(t uploadTarget, res agentposture.Result, stderr io.Writer, name string) error {
	cred := strings.TrimSpace(os.Getenv(TokenEnv))
	if cred == "" {
		return fmt.Errorf("%s is not set", TokenEnv)
	}
	clientID, secret, ok := strings.Cut(cred, ":")
	if !ok || clientID == "" || secret == "" {
		return fmt.Errorf("%s is not a CI token from the Golem console", TokenEnv)
	}
	if !uploadRepoRe.MatchString(t.repo) || len(t.repo) > 255 {
		return errors.New("name the repository as owner/name with -upload-repo")
	}
	if t.commit != "" && !uploadCommitRe.MatchString(t.commit) {
		return errors.New("-upload-commit is not a full commit SHA")
	}
	base, err := baseURL(t.url)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	access, err := exchangeToken(ctx, base, clientID, secret)
	if err != nil {
		return err
	}
	items := res.Items
	if items == nil {
		items = []agentposture.Item{}
	}
	if len(items) > maxUploadItems {
		items = items[:maxUploadItems]
	}
	body, err := json.Marshal(map[string]any{
		"repository": t.repo, "commit_sha": t.commit, "ref": t.ref, "items": items,
	})
	if err != nil {
		return errors.New("could not encode the findings")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/golem.v1.GolemService/RecordRepositoryPosture", bytes.NewReader(body))
	if err != nil {
		return errors.New("could not build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("X-Golem-Access-Token", access)
	resp, err := uploadClient.Do(req)
	if err != nil {
		return errors.New("could not reach " + hostOf(base))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		switch e.Code {
		case "permission_denied":
			return errors.New("the token cannot report repository findings; mint a CI token in the Golem console")
		case "unauthenticated":
			return errors.New("Golem refused the token; it may have been revoked")
		case "invalid_argument":
			return errors.New("Golem refused the report: " + oneLine(e.Message))
		}
		return fmt.Errorf("Golem answered %d", resp.StatusCode)
	}
	var out struct {
		Recorded bool  `json:"recorded"`
		Items    int32 `json:"items"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return errors.New("Golem's answer did not parse")
	}
	if !out.Recorded {
		fmt.Fprintf(stderr, "%s: agent settings checks are off in this Golem workspace, so nothing was recorded\n", name)
		return nil
	}
	fmt.Fprintf(stderr, "%s: sent %d findings for %s to Golem\n", name, out.Items, t.repo)
	return nil
}

// exchangeToken trades the CI token for a five-minute access token. The secret
// goes only here, in the request body.
func exchangeToken(ctx context.Context, base, clientID, secret string) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("could not build the request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := uploadClient.Do(req)
	if err != nil {
		return "", errors.New("could not reach " + hostOf(base))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest:
		return "", errors.New("Golem refused the CI token; it may have been revoked")
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("the token exchange answered %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("the token exchange's answer did not parse")
	}
	return tok.AccessToken, nil
}

func hostOf(base string) string {
	if u, err := url.Parse(base); err == nil {
		return u.Host
	}
	return "Golem"
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
