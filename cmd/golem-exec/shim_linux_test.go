package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// The jail stage re-executes /proc/self/exe, which under test is this binary.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == jailStage {
		os.Exit(runJailStage(os.Args[1:]))
	}
	if addr := os.Getenv("GOLEM_EXEC_DIAL"); addr != "" {
		network, address, _ := strings.Cut(addr, ":")
		c, err := net.Dial(network, address)
		if err != nil {
			os.Exit(7)
		}
		c.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const testKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n"

func needLandlock(t *testing.T) {
	t.Helper()
	if landlockABI() < shield.LandlockMinABI {
		t.Skip("this kernel has no Landlock")
	}
}

func plant(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func linuxShim(t *testing.T, p shield.Policy) (*shim, *fakeWitness, *bytes.Buffer) {
	t.Helper()
	needLandlock(t)
	w := newFakeWitness(t, p)
	s, stdout, _ := testShim(t, w.URL)
	s.cwd = filepath.Join(s.cwd, "repo")
	if err := os.MkdirAll(filepath.Join(s.cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(s.cwd); err != nil {
		t.Fatal(err)
	}
	return s, w, stdout
}

func TestLinuxShimJailsTheCommandAndReportsTheRun(t *testing.T) {
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	plant(t, filepath.Join(s.home, ".ssh", "config"), "Host x\n")

	script := `/bin/sh -c "cat $HOME/.ssh/id_ed25519" && echo LEAKED; cat $HOME/.ssh/config; echo "token=[$GITHUB_TOKEN]"; exit 3`
	if code := s.run("/bin/bash", []string{"-c", script}); code != 3 {
		t.Fatalf("exit %d, want the command's own 3", code)
	}
	got := out.String()
	if strings.Contains(got, "PRIVATE") || strings.Contains(got, "LEAKED") {
		t.Errorf("key read through an absolute /bin/sh: %s", got)
	}
	if !strings.Contains(got, "Host x") {
		t.Errorf("ssh config wasn't readable: %s", got)
	}
	if !strings.Contains(got, "token=[]") {
		t.Errorf("GITHUB_TOKEN reached the command: %s", got)
	}
	if len(w.runs) != 1 {
		t.Fatalf("runs %d", len(w.runs))
	}
	rec := w.runs[0]
	if rec.Jail != shield.JailLandlock || rec.ExitCode != 3 || len(rec.PolicyHash) != 64 || rec.RunTag != w.requests[0].RunTag {
		t.Errorf("run record %+v", rec)
	}
}

func TestLinuxCleanSessionWritesButNotStartupFiles(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	plant(t, filepath.Join(s.home, ".bashrc"), "# rc\n")
	plant(t, filepath.Join(s.home, ".cache", "keep"), "")
	script := `echo x >> $HOME/.bashrc && echo RC; echo x > $HOME/.bash_profile && echo PROFILE;` +
		` echo x > $HOME/.cache/new && echo CACHE; echo x > new.go && echo WS; echo done`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	if strings.Contains(got, "RC") || strings.Contains(got, "PROFILE") {
		t.Errorf("a startup file was written: %s", got)
	}
	if !strings.Contains(got, "CACHE") || !strings.Contains(got, "WS") {
		t.Errorf("ordinary writes failed: %s", got)
	}
}

func TestLinuxTaintedSessionCantConnectOrWriteOutsideTheWorkspace(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s, w, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Tainted, Grants: shield.AllGrants()})
	script := `(exec 3<>/dev/tcp/127.0.0.1/` + port + `) 2>/dev/null && echo CONNECTED;` +
		` touch $HOME/x 2>/dev/null && echo HOMEWRITE; echo x > ws.txt && echo WS; echo x > $TMPDIR/t && echo TMP; true`
	s.run("/bin/bash", []string{"-c", script})
	got := out.String()
	if strings.Contains(got, "CONNECTED") || strings.Contains(got, "HOMEWRITE") {
		t.Errorf("tainted command escaped: %s", got)
	}
	if !strings.Contains(got, "WS") || !strings.Contains(got, "TMP") {
		t.Errorf("tainted command lost its workspace or temp dir: %s", got)
	}
	if len(w.runs) != 1 || w.runs[0].State != shield.Tainted {
		t.Fatalf("runs %+v", w.runs)
	}
}

func TestLinuxTaintedSessionStillWritesTheHarnessCwdFile(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Tainted})
	harness := t.TempDir()
	s.env = append(s.env, "CLAUDECODE=1", "CLAUDE_CODE_TMPDIR="+harness)
	cwdFile := filepath.Join(harness, "claude-ab12-cwd")
	s.run("/bin/bash", []string{"-c", "pwd -P >| " + cwdFile + " && echo OK; echo x > " + filepath.Join(harness, "other") + " && echo OTHER; true"})
	if got := out.String(); !strings.Contains(got, "OK") || strings.Contains(got, "OTHER") {
		t.Errorf("harness file: %s", got)
	}
	if b, _ := os.ReadFile(cwdFile); strings.TrimSpace(string(b)) != realPath(s.cwd) {
		t.Errorf("cwd file holds %q", b)
	}
}

func TestLinuxGrantsOffCloseUnixSockets(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	self, _ := os.Executable()

	s, _, _ := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s.env = append(s.env, "GOLEM_EXEC_DIAL=unix:"+sock)
	if code := s.run(self, nil); code != 0 {
		t.Fatalf("with every grant the socket was refused: exit %d", code)
	}
	s, _, _ = linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.Grants{Agent: true, Cloud: true}})
	s.env = append(s.env, "GOLEM_EXEC_DIAL=unix:"+sock)
	if code := s.run(self, nil); code != 7 {
		t.Fatalf("Docker grant off, exit %d, want the dial to fail", code)
	}
}

func TestLinuxBackgroundChildStaysJailed(t *testing.T) {
	s, _, out := linuxShim(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	marker := filepath.Join(s.cwd, "bg.out")
	s.run("/bin/bash", []string{"-c", `nohup sh -c "cat $HOME/.ssh/id_ed25519 > ` + marker + ` 2>&1" >/dev/null 2>&1 & wait`})
	b, _ := os.ReadFile(marker)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatalf("a background child read the key: %s %s", b, out.String())
	}
}

func TestLinuxWithoutAWitnessStillJails(t *testing.T) {
	needLandlock(t)
	s, out, _ := testShim(t, "http://127.0.0.1:1")
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	s.run("/bin/bash", []string{"-c", "cat $HOME/.ssh/id_ed25519"})
	if strings.Contains(out.String(), "PRIVATE") {
		t.Fatal("the baseline jail didn't hold without a witness")
	}
}

func TestLinuxJailStageRefusesWithoutASpec(t *testing.T) {
	needLandlock(t)
	self, _ := os.Executable()
	cmd := exec.Command(self)
	cmd.Args = []string{jailStage, "/bin/sh", "-c", "echo RAN"}
	b, err := cmd.CombinedOutput()
	if strings.Contains(string(b), "RAN") {
		t.Fatalf("the stage ran a command without its rules: %s", b)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 126 {
		t.Fatalf("exit %v, want 126", err)
	}
}
