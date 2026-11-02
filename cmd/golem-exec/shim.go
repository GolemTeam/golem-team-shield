package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/GolemTeam/golem-team-shield/shield"
)

const (
	policyTimeout = 250 * time.Millisecond
	reportTimeout = 300 * time.Millisecond
)

var sessionIDRE = regexp.MustCompile(`^[\w\-.:]{1,255}$`)

type shim struct {
	witness  string
	client   *http.Client
	env      []string
	home     string
	cwd      string
	cacheDir string
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	// canJail reports whether this platform's jail can be applied here.
	canJail func() bool
	now     func() time.Time
}

func newShim(witness string) *shim {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	return &shim{
		witness:  witness,
		client:   &http.Client{},
		env:      os.Environ(),
		home:     home,
		cwd:      cwd,
		cacheDir: filepath.Join(home, ".golem", "shield", "sessions"),
		stdin:    os.Stdin,
		stdout:   os.Stdout,
		stderr:   os.Stderr,
		canJail:  canJail,
		now:      time.Now,
	}
}

func (s *shim) getenv(name string) string {
	for _, kv := range s.env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

func (s *shim) run(shell string, args []string) int {
	sessionID := s.getenv("CLAUDE_CODE_SESSION_ID")
	if !sessionIDRE.MatchString(sessionID) {
		sessionID = ""
	}
	agentID := ""
	if s.getenv("CLAUDECODE") == "1" {
		agentID = "claude-code"
	}
	tag := newRunTag()
	policy, fromWitness := s.policy(shield.PolicyRequest{SessionID: sessionID, AgentID: agentID, RunTag: tag, CWD: s.cwd})

	if !policy.Enforce {
		return s.exec(append([]string{shell}, args...), s.env)
	}

	tmp, err := os.MkdirTemp("", "golem-turn-")
	if err != nil {
		fmt.Fprintln(s.stderr, "golem-exec: can't create the command's temp directory; not running it")
		return 126
	}
	defer os.RemoveAll(tmp)
	tmp = realPath(tmp)

	env, dropped := shield.FilterEnv(s.env, policy, tmp)
	rec := shield.RunRecord{
		SessionID: sessionID, AgentID: agentID, RunTag: tag,
		State: policy.State, Grants: policy.Effective(), FromWitness: fromWitness, DroppedEnv: dropped,
	}
	argv := append([]string{shell}, args...)
	start := s.now()
	if !s.jailed(&rec, policy, tmp, argv, env) {
		fmt.Fprintln(s.stderr, "golem-exec: can't build the Golem shield for this command; not running it")
		return 126
	}
	rec.DurationMS = s.now().Sub(start).Milliseconds()
	if fromWitness {
		s.report(rec)
	}
	return rec.ExitCode
}

// context is what the shim sees for itself about this command: the
// workspace, the turn's temp directory and what in ~/.ssh isn't a key.
func (s *shim) context(tmp, tag string) shield.Context {
	c := shield.Context{
		Home:        realPath(s.home),
		TurnTmp:     tmp,
		AgentSocket: agentSocket(s.getenv("SSH_AUTH_SOCK")),
		RunTag:      tag,
	}
	c.SSHReadable = shield.SSHReadable(c.Home)
	ws := shield.FindWorkspace(realPath(s.cwd))
	for _, w := range ws.Writable {
		// A repository at or above home (a dotfiles repo in ~) is no
		// workspace: it would open every credential store to a tainted write.
		if !holds(w, c.Home) {
			c.Workspace = append(c.Workspace, realPath(w))
		}
	}
	for _, w := range ws.Protected {
		c.WorkspaceProtected = append(c.WorkspaceProtected, realPath(w))
	}
	if s.getenv("CLAUDECODE") == "1" {
		harness := s.getenv("CLAUDE_CODE_TMPDIR")
		if harness == "" {
			harness = "/tmp"
		}
		c.HarnessTmp = realPath(harness)
	}
	return c
}

// withoutWorkspace is the context to compile when this machine's paths didn't
// validate. The jail without a workspace still holds everything but tainted
// workspace writes.
func withoutWorkspace(c shield.Context) shield.Context {
	c.Workspace, c.WorkspaceProtected, c.HarnessTmp, c.HarnessFiles = nil, nil, "", nil
	return c
}

// policy asks the witness. It keeps the answer per session, so a witness
// restart can't forget a taint, and per machine, so a profile's switch-off or
// revoked grant still holds for a session the shim hasn't seen before. With no
// witness ever, the machine's own ~/.golem/shield.json decides, then the
// baseline: the witness's cached decisions outrank the file, so one left from
// before the agent cannot loosen an agent machine.
func (s *shim) policy(req shield.PolicyRequest) (shield.Policy, bool) {
	cached, haveCache := s.loadCache(s.cachePath(req.SessionID))
	live, err := s.fetch(req)
	if err != nil {
		if haveCache {
			return cached, false
		}
		if host, ok := s.loadCache(s.hostCachePath()); ok {
			host.State = shield.Clean
			return host, false
		}
		return s.configPolicy(), false
	}
	if haveCache && cached.Tainted() {
		live.State = shield.Tainted
	}
	s.storeCache(s.cachePath(req.SessionID), live)
	machine := live
	machine.State = shield.Clean
	s.storeCache(s.hostCachePath(), machine)
	return live, true
}

// configPolicy is what ~/.golem/shield.json asks for, or the baseline with no
// file. A file that cannot be followed gets lockdown, and says so on every
// command until it is fixed.
func (s *shim) configPolicy() shield.Policy {
	c, found, err := shield.LoadConfig(shield.ConfigPath(s.home))
	if !found {
		return shield.Baseline()
	}
	if err != nil {
		fmt.Fprintf(s.stderr, "golem-exec: ~/.golem/shield.json is not valid (%v); every command is locked down until it is fixed\n", err)
		return shield.Unreadable()
	}
	return c.Policy()
}

func (s *shim) fetch(req shield.PolicyRequest) (shield.Policy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), policyTimeout)
	defer cancel()
	var p shield.Policy
	if err := s.post(ctx, "/api/v1/shield/policy", req, &p); err != nil {
		return shield.Policy{}, err
	}
	if p.State == "" {
		return shield.Policy{}, errors.New("policy without a state")
	}
	return p, nil
}

func (s *shim) report(rec shield.RunRecord) {
	ctx, cancel := context.WithTimeout(context.Background(), reportTimeout)
	defer cancel()
	_ = s.post(ctx, "/api/v1/shield/run", rec, nil)
}

func (s *shim) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.witness, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the Golem agent answered %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(out)
}

func (s *shim) cachePath(sessionID string) string {
	if sessionID == "" || s.cacheDir == "" {
		return ""
	}
	return filepath.Join(s.cacheDir, sessionID+".json")
}

func (s *shim) hostCachePath() string {
	if s.cacheDir == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.cacheDir), "host.json")
}

func (s *shim) loadCache(path string) (shield.Policy, bool) {
	if path == "" {
		return shield.Policy{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64<<10 {
		return shield.Policy{}, false
	}
	var p shield.Policy
	if json.Unmarshal(raw, &p) != nil || p.State == "" {
		return shield.Policy{}, false
	}
	return p, true
}

func (s *shim) storeCache(path string, p shield.Policy) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil || tmp.Chmod(0o600) != nil || tmp.Close() != nil {
		return
	}
	_ = os.Rename(tmp.Name(), path)
}

// child runs argv and forwards the signals the agent sends the shell it
// thinks it started.
func (s *shim) child(argv []string, env []string) int {
	return s.start(exec.Command(argv[0], argv[1:]...), env, nil)
}

// start runs cmd as child does; started, if set, runs once it has.
func (s *shim) start(cmd *exec.Cmd, env []string, started func()) int {
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, s.stdin, s.stdout, s.stderr
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(s.stderr, "golem-exec: can't start the shell")
		return 127
	}
	if started != nil {
		started()
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	return exitCode(cmd, err)
}

func exitCode(cmd *exec.Cmd, err error) int {
	if cmd.ProcessState == nil {
		if err != nil {
			return 127
		}
		return 0
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return cmd.ProcessState.ExitCode()
}

// exec replaces the shim with the shell; only for a workspace that switched
// the shield off, where there is nothing to report.
func (s *shim) exec(argv []string, env []string) int {
	if runtime.GOOS == "windows" {
		return s.child(argv, env)
	}
	err := syscall.Exec(argv[0], argv, env)
	fmt.Fprintf(s.stderr, "golem-exec: exec failed: %v\n", err)
	return 127
}

func newRunTag() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func realPath(p string) string {
	if p == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// agentSocket resolves SSH_AUTH_SOCK, and keeps it only if it is a socket:
// the profile lets the agent read it, and a jailed command that replaced it
// with a link to a key would otherwise have that key let back.
func agentSocket(p string) string {
	r := realPath(p)
	if r == "" {
		return ""
	}
	if fi, err := os.Stat(r); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return ""
	}
	return r
}

// holds reports whether dir is path or one of its ancestors.
func holds(dir, path string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	sep := string(filepath.Separator)
	return path == dir || dir == sep || strings.HasPrefix(path, strings.TrimSuffix(dir, sep)+sep)
}
