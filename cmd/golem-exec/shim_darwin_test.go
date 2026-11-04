package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// Seatbelt doesn't nest: inside a sandbox (an agent's own jailed shell) the
// shim can't apply a profile, so these tests say so instead of failing.
var nested = exec.Command(shield.SandboxExec, "-p", "(version 1)(allow default)", "/usr/bin/true").Run() != nil

func skipIfNested(t *testing.T) {
	t.Helper()
	if nested {
		t.Skip("already inside a sandbox; Seatbelt profiles don't nest")
	}
}

// The jail tells a key by its header, as every real one has; the body says
// PRIVATE so a leak shows in the output.
const testKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n"

func plant(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestShimJailsTheCommandAndReportsTheRun(t *testing.T) {
	skipIfNested(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean})
	s, stdout, _ := testShim(t, w.URL)
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)

	script := `/bin/bash -c "cat $HOME/.ssh/id_ed25519" && echo LEAKED; echo "token=[$GITHUB_TOKEN]"; exit 3`
	if code := s.run("/bin/zsh", []string{"-c", script}); code != 3 {
		t.Fatalf("exit %d, want the command's own 3", code)
	}
	out := stdout.String()
	if strings.Contains(out, "PRIVATE") || strings.Contains(out, "LEAKED") {
		t.Errorf("key read through an absolute /bin/bash: %s", out)
	}
	if !strings.Contains(out, "token=[]") {
		t.Errorf("GITHUB_TOKEN reached the command: %s", out)
	}
	if len(w.runs) != 1 || len(w.requests) != 1 {
		t.Fatalf("runs %d requests %d", len(w.runs), len(w.requests))
	}
	rec := w.runs[0]
	if rec.Jail != shield.JailSeatbelt || rec.ExitCode != 3 || len(rec.PolicyHash) != 64 || rec.RunTag != w.requests[0].RunTag || rec.SessionID != "sess-1" {
		t.Errorf("run record %+v", rec)
	}
	if len(rec.DroppedEnv) != 1 || rec.DroppedEnv[0] != "GITHUB_TOKEN" {
		t.Errorf("dropped %v", rec.DroppedEnv)
	}
}

func TestShimTaintedCommandCantConnect(t *testing.T) {
	skipIfNested(t)
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
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Tainted})
	s, _, _ := testShim(t, w.URL)
	if code := s.run("/bin/zsh", []string{"-c", "nc -z -G 2 127.0.0.1 " + port}); code == 0 {
		t.Fatal("a tainted command connected")
	}
	if len(w.runs) != 1 || w.runs[0].State != shield.Tainted {
		t.Fatalf("runs %+v", w.runs)
	}
}

func TestShimWithoutAWitnessStillJails(t *testing.T) {
	skipIfNested(t)
	s, stdout, _ := testShim(t, "http://127.0.0.1:1")
	plant(t, filepath.Join(s.home, ".ssh", "id_ed25519"), testKey)
	s.run("/bin/zsh", []string{"-c", "cat $HOME/.ssh/id_ed25519"})
	if strings.Contains(stdout.String(), "PRIVATE") {
		t.Fatal("the baseline jail didn't hold without a witness")
	}
}

func TestShimSwitchedOffRunsUnjailed(t *testing.T) {
	// exec replaces the process, so this runs in a child test binary.
	if os.Getenv("GOLEM_EXEC_SWITCHED_OFF") == "1" {
		w := newFakeWitness(t, shield.Policy{Enforce: false, State: shield.Clean})
		s, _, _ := testShim(t, w.URL)
		s.stdout = os.Stdout
		s.run("/bin/sh", []string{"-c", `echo "token=[$GITHUB_TOKEN]"`})
		return
	}
	out, _ := runSelf(t, "TestShimSwitchedOffRunsUnjailed", "GOLEM_EXEC_SWITCHED_OFF=1")
	if !strings.Contains(out, "token=[ghp_secret]") {
		t.Fatalf("switched-off shield still filtered: %s", out)
	}
}

// A jailed command can replace SSH_AUTH_SOCK's path when it sits outside
// ~/.ssh (the launchd default is under /private/tmp). Linking it to a key
// must not get the key let back on the next command.
func TestALinkedAgentSocketDoesNotReopenAKey(t *testing.T) {
	skipIfNested(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s, stdout, _ := testShim(t, w.URL)
	key := filepath.Join(s.home, ".ssh", "id_ed25519")
	plant(t, key, testKey)
	link := filepath.Join(s.cwd, "Listeners")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	s.env = append(s.env, "SSH_AUTH_SOCK="+link)

	s.run("/bin/zsh", []string{"-c", `cat "$HOME/.ssh/id_ed25519" && echo LEAKED`})
	if out := stdout.String(); strings.Contains(out, "PRIVATE") || strings.Contains(out, "LEAKED") {
		t.Errorf("the key was read through a linked agent socket: %s", out)
	}
}

func TestShimKeepsBrowserChatAndMailStoresFromTheCommand(t *testing.T) {
	skipIfNested(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s, stdout, _ := testShim(t, w.URL)
	lib := filepath.Join(s.home, "Library")
	for _, f := range []string{
		"Application Support/Firefox/Profiles/x.default/cookies.sqlite",
		"Application Support/Google/Chrome/Default/Cookies",
		"Application Support/Slack/storage/x",
		"Messages/chat.db",
		"Mail/V10/x",
	} {
		plant(t, filepath.Join(lib, f), "SECRET\n")
	}
	plant(t, filepath.Join(s.home, "vault.kdbx"), "SECRET\n")
	plant(t, filepath.Join(lib, "Application Support/Firefox/Profiles/x.default/extensions/evil.xpi"), "")
	script := `cd "$HOME/Library"; cat "Application Support/Firefox/Profiles/x.default/cookies.sqlite" "Application Support/Google/Chrome/Default/Cookies"` +
		` "Application Support/Slack/storage/x" Messages/chat.db Mail/V10/x "$HOME/vault.kdbx";` +
		` echo x > "Application Support/Firefox/Profiles/x.default/extensions/evil.xpi" && echo PLANTED; echo done`
	s.run("/bin/zsh", []string{"-c", script})
	out := stdout.String()
	if strings.Contains(out, "SECRET") || strings.Contains(out, "PLANTED") || !strings.Contains(out, "done") {
		t.Errorf("an app's store was reachable: %s", out)
	}
}

func TestShimAllowlistedNetworkGoesOnlyThroughItsProxy(t *testing.T) {
	skipIfNested(t)
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
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(),
		Network: shield.NetworkAllowlist, AllowedHosts: []string{"example.com"}})
	s, stdout, stderr := testShim(t, w.URL)
	online := true
	if _, err := net.LookupHost("example.com"); err != nil {
		online = false
	}
	script := `nc -z -G 2 127.0.0.1 ` + other + ` 2>/dev/null && echo DIRECT; nc -z -G 2 1.1.1.1 443 2>/dev/null && echo PUBLIC;` +
		` echo "proxy=[$HTTPS_PROXY] node=[$NODE_USE_ENV_PROXY]";` +
		` curl -s -o /dev/null -w 'evil=%{http_code}\n' https://evil.test/;` +
		` curl -s -o /dev/null -w 'allowed=%{http_code}\n' --max-time 10 https://example.com/; true`
	s.run("/bin/zsh", []string{"-c", script})
	out := stdout.String()
	if strings.Contains(out, "DIRECT") || strings.Contains(out, "PUBLIC") {
		t.Errorf("a connection went around the proxy: %s", out)
	}
	if !strings.Contains(out, "proxy=[http://127.0.0.1:") || !strings.Contains(out, "node=[1]") {
		t.Errorf("proxy variables: %s", out)
	}
	if !strings.Contains(stderr.String(), "the shield refused evil.test:443: not in the allowed hosts.") {
		t.Errorf("the refusal wasn't named on stderr: %s", stderr)
	}
	if online && !strings.Contains(out, "allowed=200") {
		t.Errorf("an allowed host didn't load through the proxy: %s", out)
	}
	if len(w.runs) != 1 {
		t.Fatalf("runs %d", len(w.runs))
	}
	rec := w.runs[0]
	if rec.Net != shield.NetSeatbelt || len(rec.Egress) == 0 || rec.Egress[0].Host != "evil.test" || rec.Egress[0].Allowed {
		t.Errorf("run record net %q egress %+v", rec.Net, rec.Egress)
	}
}

func TestShimWorkspaceWritesStayInTheRoots(t *testing.T) {
	skipIfNested(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Writes: shield.WritesWorkspace})
	s, stdout, _ := testShim(t, w.URL)
	plant(t, filepath.Join(s.home, "notes"), "")
	plant(t, filepath.Join(s.home, "Library", "Preferences", "x.plist"), "")
	s.cwd = filepath.Join(s.cwd, "repo")
	plant(t, filepath.Join(s.cwd, ".git", "HEAD"), "ref: refs/heads/main\n")
	script := `cd "` + s.cwd + `"; echo x > ws.txt && echo WS; echo x > $TMPDIR/t && echo TMP; mkdir -p $HOME/Library/Caches/x && echo CACHE;` +
		` echo x >> $HOME/notes && echo HOMEWRITE; true`
	s.run("/bin/zsh", []string{"-c", script})
	got := stdout.String()
	for _, want := range []string{"WS", "TMP", "CACHE"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s wasn't writable: %s", want, got)
		}
	}
	if strings.Contains(got, "HOMEWRITE") {
		t.Errorf("a write left the roots: %s", got)
	}
	if len(w.runs) != 1 || w.runs[0].Writes != "workspace" {
		t.Errorf("runs %+v", w.runs)
	}
}

func TestShimConfinedWritesOutsideARepository(t *testing.T) {
	skipIfNested(t)
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants(), Writes: shield.WritesWorkspace})
	s, stdout, _ := testShim(t, w.URL)
	s.cwd = filepath.Join(s.cwd, "plain")
	plant(t, filepath.Join(s.cwd, "README"), "")
	plant(t, filepath.Join(s.home, "notes"), "")
	s.run("/bin/zsh", []string{"-c", `cd "` + s.cwd + `"; echo x > inside.txt && echo INSIDE; echo x >> $HOME/notes && echo HOMEWRITE; true`})
	if got := stdout.String(); !strings.Contains(got, "INSIDE") || strings.Contains(got, "HOMEWRITE") {
		t.Errorf("writes: %s", got)
	}
}
