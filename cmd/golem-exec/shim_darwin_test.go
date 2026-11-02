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
