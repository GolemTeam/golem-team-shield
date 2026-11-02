package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/GolemTeam/golem-team-shield/shield"
)

type fakeWitness struct {
	*httptest.Server
	mu       sync.Mutex
	policy   shield.Policy
	requests []shield.PolicyRequest
	runs     []shield.RunRecord
}

func newFakeWitness(t *testing.T, p shield.Policy) *fakeWitness {
	t.Helper()
	w := &fakeWitness{policy: p}
	w.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		defer w.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/shield/policy":
			var req shield.PolicyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.requests = append(w.requests, req)
			_ = json.NewEncoder(rw).Encode(w.policy)
		case "/api/v1/shield/run":
			var rec shield.RunRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			w.runs = append(w.runs, rec)
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(w.Close)
	return w
}

func testShim(t *testing.T, witness string) (*shim, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	var stdout, stderr bytes.Buffer
	return &shim{
		witness:  witness,
		client:   &http.Client{},
		env:      []string{"HOME=" + home, "PATH=/usr/bin:/bin", "CLAUDE_CODE_SESSION_ID=sess-1", "GITHUB_TOKEN=ghp_secret"},
		home:     home,
		cwd:      root,
		cacheDir: filepath.Join(home, ".golem", "shield", "sessions"),
		stdin:    bytes.NewReader(nil),
		stdout:   &stdout,
		stderr:   &stderr,
		canJail:  canJail,
		now:      time.Now,
	}, &stdout, &stderr
}

func TestPolicyUsesTheWitnessAndCachesIt(t *testing.T) {
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.Grants{Docker: true}})
	s, _, _ := testShim(t, w.URL)
	p, live := s.policy(shield.PolicyRequest{SessionID: "sess-1", RunTag: "t1"})
	if !live || !p.Grants.Docker {
		t.Fatalf("policy %+v live=%v", p, live)
	}
	if cached, ok := s.loadCache(s.cachePath("sess-1")); !ok || !cached.Grants.Docker {
		t.Fatalf("cache %+v %v", cached, ok)
	}
	fi, err := os.Stat(s.cachePath("sess-1"))
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("cache mode %v %v", fi.Mode(), err)
	}
}

// A witness restart forgets its in-memory taint; the cache must not.
func TestACachedTaintOutlivesAWitnessThatForgotIt(t *testing.T) {
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean})
	s, _, _ := testShim(t, w.URL)
	s.storeCache(s.cachePath("sess-1"), shield.Policy{Enforce: true, State: shield.Tainted})
	if p, _ := s.policy(shield.PolicyRequest{SessionID: "sess-1"}); !p.Tainted() {
		t.Fatal("the witness's clean answer untainted a tainted session")
	}
	if p, _ := s.loadCache(s.cachePath("sess-1")); !p.Tainted() {
		t.Fatal("the cache lost the taint")
	}
}

func TestWitnessDownFallsBackToCacheThenBaseline(t *testing.T) {
	s, _, _ := testShim(t, "http://127.0.0.1:1")
	if p, live := s.policy(shield.PolicyRequest{SessionID: "sess-1"}); live || !reflect.DeepEqual(p, shield.Baseline()) {
		t.Fatalf("no cache: %+v live=%v", p, live)
	}
	s.storeCache(s.cachePath("sess-1"), shield.Policy{Enforce: false, State: shield.Clean})
	if p, _ := s.policy(shield.PolicyRequest{SessionID: "sess-1"}); p.Enforce {
		t.Fatal("a workspace's cached switch-off was forgotten")
	}
}

// With no witness ever, the machine's own settings decide, and the witness's
// cached decisions outrank them.
func TestWithNoWitnessTheConfigDecides(t *testing.T) {
	s, _, _ := testShim(t, "http://127.0.0.1:1")
	if err := shield.WriteConfig(shield.ConfigPath(s.home), shield.Config{Lockdown: true}); err != nil {
		t.Fatal(err)
	}
	if p, live := s.policy(shield.PolicyRequest{SessionID: "sess-1"}); live || !p.Tainted() || !p.Enforce {
		t.Fatalf("the config's lockdown was not applied: %+v", p)
	}
	s.storeCache(s.hostCachePath(), shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.Grants{Docker: true}})
	if p, _ := s.policy(shield.PolicyRequest{SessionID: "sess-2"}); p.Tainted() || !p.Grants.Docker {
		t.Fatalf("the config outranked the agent's cached decision: %+v", p)
	}
}

func TestABrokenConfigIsLockedDownAndSaysSo(t *testing.T) {
	s, _, stderr := testShim(t, "http://127.0.0.1:1")
	path := shield.ConfigPath(s.home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"enforce": false, "typo": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.policy(shield.PolicyRequest{}); !reflect.DeepEqual(p, shield.Unreadable()) {
		t.Fatalf("a broken config did not lock down: %+v", p)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("locked down until it is fixed")) {
		t.Errorf("no warning: %q", stderr.String())
	}
}

// A profile that revoked a grant must not hand it back to a new session just
// because the witness is down.
func TestWitnessDownKeepsTheMachinesLastGrants(t *testing.T) {
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.Grants{Agent: true}})
	s, _, _ := testShim(t, w.URL)
	s.policy(shield.PolicyRequest{SessionID: "sess-1"})
	s.witness = "http://127.0.0.1:1"
	p, live := s.policy(shield.PolicyRequest{SessionID: "sess-new"})
	if live || p.Grants != (shield.Grants{Agent: true}) || p.Tainted() {
		t.Fatalf("new session with the witness down: %+v", p)
	}
}

func TestTheMachineCacheNeverCarriesTaint(t *testing.T) {
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Tainted})
	s, _, _ := testShim(t, w.URL)
	s.policy(shield.PolicyRequest{SessionID: "sess-1"})
	if p, _ := s.loadCache(s.hostCachePath()); p.Tainted() {
		t.Fatal("one session's taint leaked into the machine's cache")
	}
}

func TestNoSessionMeansNoCache(t *testing.T) {
	s, _, _ := testShim(t, "http://127.0.0.1:1")
	s.storeCache(s.cachePath(""), shield.Policy{Enforce: false, State: shield.Clean})
	if _, ok := s.loadCache(s.cachePath("")); ok {
		t.Fatal("cached a policy for no session")
	}
}

func TestWitnessOverrideOnlyOnLoopback(t *testing.T) {
	for in, want := range map[string]string{
		"":                                defaultWitness,
		"http://127.0.0.1:40000":          "http://127.0.0.1:40000",
		"http://localhost:40000":          "http://localhost:40000",
		"http://evil.example:39393":       defaultWitness,
		"http://127.0.0.1:1@evil.example": defaultWitness,
		"https://127.0.0.1:39393":         defaultWitness,
	} {
		if got := witnessURL(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}

func TestAWorkspaceHoldingHomeIsDropped(t *testing.T) {
	if !holds("/Users/dev", "/Users/dev") || !holds("/Users", "/Users/dev") || holds("/Users/dev/src", "/Users/dev") {
		t.Fatal("holds")
	}
}

// A strip list the workspace set still holds for a new session when the
// Golem agent is down: the machine cache carries it with the grants.
func TestWitnessDownKeepsTheMachinesStripList(t *testing.T) {
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, EnvDeny: []string{"MYCO_SIGNING"}})
	s, _, _ := testShim(t, w.URL)
	s.policy(shield.PolicyRequest{SessionID: "sess-1"})
	s.witness = "http://127.0.0.1:1"
	if p, _ := s.policy(shield.PolicyRequest{SessionID: "sess-new"}); !reflect.DeepEqual(p.EnvDeny, []string{"MYCO_SIGNING"}) || p.Tainted() {
		t.Fatalf("%+v", p)
	}
}

func TestOnlyARealSocketIsTakenAsTheAgentSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent socket is a Unix path")
	}
	dir, err := os.MkdirTemp("/tmp", "gsock")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "Listeners")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}

	if got, want := agentSocket(sock), realPath(sock); got != want {
		t.Errorf("a real socket: got %q, want %q", got, want)
	}
	if got := agentSocket(link); got != "" {
		t.Errorf("a link to a key was taken as the agent socket: %q", got)
	}
	if got := agentSocket(key); got != "" {
		t.Errorf("a regular file was taken as the agent socket: %q", got)
	}
	if got := agentSocket(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("a missing path was taken as the agent socket: %q", got)
	}
}
