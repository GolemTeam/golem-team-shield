package checkcmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

const (
	testCIToken = "gac_ci:gla_do-not-print-this"
	testSHA     = "0123456789abcdef0123456789abcdef01234567"
)

type fakeGolem struct {
	mu       sync.Mutex
	exchange formValues
	report   map[string]any
	access   string
	calls    int
	status   int
	body     string
}

type formValues = map[string]string

func (f *fakeGolem) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			f.exchange = formValues{"grant_type": r.PostForm.Get("grant_type"), "client_id": r.PostForm.Get("client_id"), "client_secret": r.PostForm.Get("client_secret")}
			_, _ = io.WriteString(w, `{"access_token":"jws-five-minutes","token_type":"Bearer","expires_in":300}`)
		case "/golem.v1.GolemService/RecordRepositoryPosture":
			f.access = r.Header.Get("X-Golem-Access-Token")
			_ = json.NewDecoder(r.Body).Decode(&f.report)
			if f.status != 0 {
				w.WriteHeader(f.status)
				_, _ = io.WriteString(w, f.body)
				return
			}
			n := len(f.report["items"].([]any))
			_, _ = io.WriteString(w, `{"recorded":true,"items":`+itoa(n)+`}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func clearCIEnv(t *testing.T) {
	for _, k := range []string{TokenEnv, URLEnv, "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF",
		"CI_PROJECT_PATH", "CI_COMMIT_SHA", "CI_COMMIT_BRANCH", "CI_COMMIT_TAG"} {
		t.Setenv(k, "")
	}
}

func TestUploadSendsTheRepositorysFindingsWithAFiveMinuteToken(t *testing.T) {
	clearCIEnv(t)
	f := &fakeGolem{}
	srv := f.server(t)
	t.Setenv(TokenEnv, testCIToken)
	t.Setenv("GITHUB_REPOSITORY", "acme-co/app")
	t.Setenv("GITHUB_SHA", testSHA)
	t.Setenv("GITHUB_REF", "refs/heads/main")

	code, out, errs := run(t, options(agentposture.Result{}), "-repo", riskyRepo(t), "-sarif", "-fail-on", "suspicious", "-upload", "-golem-url", srv.URL)
	if code != 3 {
		t.Errorf("exit %d, want 3: -fail-on decides it, uploading or not", code)
	}
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Error("the SARIF report is still what standard output holds")
	}
	if f.exchange["grant_type"] != "client_credentials" || f.exchange["client_id"] != "gac_ci" || f.exchange["client_secret"] != "gla_do-not-print-this" {
		t.Errorf("token exchange %v", f.exchange)
	}
	if f.access != "jws-five-minutes" {
		t.Errorf("the report carried %q, want the exchanged token", f.access)
	}
	if f.report["repository"] != "acme-co/app" || f.report["commit_sha"] != testSHA || f.report["ref"] != "refs/heads/main" {
		t.Errorf("identity %v", f.report)
	}
	items, _ := f.report["items"].([]any)
	if len(items) == 0 {
		t.Fatal("no findings sent")
	}
	first := items[0].(map[string]any)
	if first["client"] != "claude-code" || first["check"] != "bypass_default" || first["scope"] != "project" || first["location"] != ".claude/settings.json" {
		t.Errorf("first finding %v", first)
	}
	if !strings.Contains(errs, "sent 1 findings for acme-co/app to Golem") || strings.Count(strings.TrimSpace(errs), "\n") != 0 {
		t.Errorf("stderr %q, want one line", errs)
	}
	if strings.Contains(out+errs, "gla_do-not-print-this") || strings.Contains(out+errs, "jws-five-minutes") {
		t.Error("a credential was printed")
	}
}

func TestNothingIsSentUnlessAsked(t *testing.T) {
	clearCIEnv(t)
	f := &fakeGolem{}
	srv := f.server(t)
	t.Setenv(TokenEnv, testCIToken)
	t.Setenv(URLEnv, srv.URL)
	t.Setenv("GITHUB_REPOSITORY", "acme-co/app")
	if code, _, errs := run(t, options(agentposture.Result{}), "-repo", riskyRepo(t), "-sarif"); code != 0 || errs != "" {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if f.calls != 0 {
		t.Errorf("%d requests without -upload", f.calls)
	}
}

func TestAFailedUploadIsOneLineAndLeavesTheExitCode(t *testing.T) {
	refused := &fakeGolem{status: http.StatusForbidden, body: `{"code":"permission_denied","message":"a grant of posture.write is required"}`}
	refusedURL := refused.server(t).URL
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = io.WriteString(w, `{"access_token":"jws"}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(off.Close)
	revoked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
	}))
	t.Cleanup(revoked.Close)

	for _, tc := range []struct {
		name, token, url, repo, commit, want string
	}{
		{"no token", "", refusedURL, "acme-co/app", "", TokenEnv + " is not set"},
		{"not a CI token", "glk_workspace-key", refusedURL, "acme-co/app", "", "is not a CI token"},
		{"no repository", testCIToken, refusedURL, "", "", "owner/name"},
		{"a short commit", testCIToken, refusedURL, "acme-co/app", "abc123", "full commit SHA"},
		{"plain http off this machine", testCIToken, "http://golem.acme.io", "acme-co/app", "", "must be https"},
		{"nothing listening", testCIToken, "http://127.0.0.1:1", "acme-co/app", "", "could not reach"},
		{"revoked", testCIToken, revoked.URL, "acme-co/app", "", "refused the CI token"},
		{"no posture.write", testCIToken, refusedURL, "acme-co/app", "", "cannot report repository findings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearCIEnv(t)
			t.Setenv(TokenEnv, tc.token)
			args := []string{"-repo", riskyRepo(t), "-json", "-upload", "-golem-url", tc.url, "-upload-repo", tc.repo}
			if tc.commit != "" {
				args = append(args, "-upload-commit", tc.commit)
			}
			code, out, errs := run(t, options(agentposture.Result{}), args...)
			if code != 0 {
				t.Errorf("exit %d, want 0", code)
			}
			if !strings.HasPrefix(out, "[") {
				t.Error("the report is still written")
			}
			if !strings.HasPrefix(errs, "golem-check: not sent to Golem: ") || !strings.Contains(errs, tc.want) ||
				strings.Count(strings.TrimSpace(errs), "\n") != 0 {
				t.Errorf("stderr %q, want one line naming %q", errs, tc.want)
			}
			if strings.Contains(errs, "gla_do-not-print-this") {
				t.Error("the secret was printed")
			}
		})
	}

	clearCIEnv(t)
	t.Setenv(TokenEnv, testCIToken)
	_, _, errs := run(t, options(agentposture.Result{}), "-repo", riskyRepo(t), "-upload", "-golem-url", off.URL, "-upload-repo", "acme-co/app")
	if !strings.Contains(errs, "checks are off") {
		t.Errorf("switched off: %q", errs)
	}
}

func TestUploadGoesWithRepo(t *testing.T) {
	clearCIEnv(t)
	if code, _, errs := run(t, options(agentposture.Result{}), "-upload"); code != 2 || !strings.Contains(errs, "goes with -repo") {
		t.Errorf("exit %d, %q", code, errs)
	}
}

func TestTheIdentityComesFromGitLabToo(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("CI_PROJECT_PATH", "acme-co/group/app")
	t.Setenv("CI_COMMIT_SHA", testSHA)
	t.Setenv("CI_COMMIT_BRANCH", "main")
	got := uploadTarget{}.resolve()
	if got.repo != "acme-co/group/app" || got.commit != testSHA || got.ref != "refs/heads/main" || got.url != DefaultURL {
		t.Errorf("%+v", got)
	}
	flags := uploadTarget{url: "https://golem.acme.io/", repo: "acme-co/other"}.resolve()
	if flags.repo != "acme-co/other" || flags.url != "https://golem.acme.io/" {
		t.Errorf("flags win: %+v", flags)
	}
	if b, err := baseURL(flags.url); err != nil || b != "https://golem.acme.io" {
		t.Errorf("base %q %v", b, err)
	}
}
