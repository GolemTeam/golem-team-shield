package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
