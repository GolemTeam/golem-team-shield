package shield

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func grokBotHome(t *testing.T, daemon string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".grokbot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if daemon != "" {
		if err := os.WriteFile(GrokBotDaemonFile(home), []byte(daemon), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func environOf(pid int, env ...string) func(int) ([]string, bool) {
	return func(p int) ([]string, bool) {
		if p != pid {
			return nil, false
		}
		return env, true
	}
}

func TestReadGrokBotDaemon(t *testing.T) {
	home := grokBotHome(t, `{"pid":4242,"startedAt":1,"servingAt":2,"inflightCount":2}`)
	d, ok := ReadGrokBotDaemon(home, environOf(4242, "SHELL=/bin/zsh", "SAND_LOCAL_EXEC_GENERATION=7", "SAND_LOCAL_EXEC_ROOT=/Users/x/GrokBot"))
	if !ok || d.PID != 4242 || d.Inflight != 2 || d.Shell != "/bin/zsh" || d.Root != "/Users/x/GrokBot" {
		t.Fatalf("got %+v ok=%v", d, ok)
	}
	if _, ok := ReadGrokBotDaemon(home, environOf(4242, "SHELL=/bin/zsh")); ok {
		t.Error("a pid now held by a program without the daemon's marker read as the daemon")
	}
	if _, ok := ReadGrokBotDaemon(home, environOf(1)); ok {
		t.Error("a pid whose environment can't be read read as the daemon")
	}
	home = grokBotHome(t, `{"pid":4242}`)
	if d, ok := ReadGrokBotDaemon(home, environOf(4242, "SAND_LOCAL_EXEC_GENERATION=7")); !ok || d.Inflight != -1 {
		t.Errorf("a daemon file with no inflightCount read as %d in flight", d.Inflight)
	}
}

func TestGrokBotCoverage(t *testing.T) {
	ready := func(string) bool { return true }
	line := func(t *testing.T, env CoverageEnv) AgentCoverage {
		t.Helper()
		for _, c := range CoverageOf(env) {
			if c.Client == GrokBotClient {
				return c
			}
		}
		t.Fatal("no line for Grok Bot")
		return AgentCoverage{}
	}
	daemon := `{"pid":4242,"inflightCount":0}`
	for _, tc := range []struct {
		name, daemon string
		environ      func(int) ([]string, bool)
		want         Coverage
		via, detail  string
	}{
		{"wrapped", daemon, nil, Jailed, AttachLaunch, "run in the Golem jail (its daemon's shell is " + filepath.Join("~", ".golem", "bin", "golem-zsh") +
			"), and its file tools reach only " + filepath.Join("~", "GrokBot")},
		{"wrapped without the file root", daemon, nil, Jailed, AttachLaunch, "but its file tools reach every file you can"},
		{"plain shell", daemon, environOf(4242, "SHELL=/bin/zsh", "SAND_LOCAL_EXEC_GENERATION=1"), NotJailed, "", "its daemon's shell is /bin/zsh"},
		{"not running", "", environOf(4242), NotJailed, "", "isn't running"},
		{"unread", daemon, nil, NotJailed, "", "`golem doctor` reads it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := grokBotHome(t, tc.daemon)
			env := CoverageEnv{Home: home, GOOS: "darwin", ShimReady: ready, ProcessEnviron: tc.environ}
			shim := "SHELL=" + filepath.Join(ShimDir(home), "golem-zsh")
			switch tc.name {
			case "wrapped":
				env.ProcessEnviron = environOf(4242, shim, "SAND_LOCAL_EXEC_GENERATION=1", "SAND_LOCAL_EXEC_ROOT="+GrokBotFileRoot(home))
			case "wrapped without the file root":
				env.ProcessEnviron = environOf(4242, shim, "SAND_LOCAL_EXEC_GENERATION=1")
			}
			c := line(t, env)
			if c.Coverage != tc.want || c.Via != tc.via || !strings.Contains(c.Detail, tc.detail) {
				t.Errorf("got %s via %q: %s", c.Coverage, c.Via, c.Detail)
			}
		})
	}
	if cov := CoverageOf(CoverageEnv{Home: t.TempDir(), GOOS: "darwin", ShimReady: ready}); len(cov) != 0 {
		t.Errorf("a machine without ~/.grokbot has lines %v", cov)
	}
}
