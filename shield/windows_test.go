package shield

import (
	"path/filepath"
	"strings"
	"testing"
)

func winDeny(j WindowsJail, path string) (WindowsACE, bool) {
	for _, e := range j.Files {
		if e.Path == path {
			return e, true
		}
	}
	return WindowsACE{}, false
}

func TestWindowsCleanDeniesKeysStoresAndStartupFiles(t *testing.T) {
	tr := newLLTree(t)
	plantFile(t, filepath.Join(tr.home, ".bashrc"))
	plantFile(t, filepath.Join(tr.home, ".claude", "hooks", "x"))
	plantFile(t, filepath.Join(tr.home, ".claude", "settings.local.json"))
	plantFile(t, filepath.Join(tr.home, ".claude.json"))
	plantFile(t, filepath.Join(tr.home, ".cursor", "mcp.json"))
	plantFile(t, filepath.Join(tr.home, ".cursor", "hooks.json"))
	plantFile(t, filepath.Join(tr.home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "x"))
	plantFile(t, filepath.Join(tr.home, "Documents", "x"))
	c := tr.context()
	j, err := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants()}, c)
	if err != nil {
		t.Fatal(err)
	}
	h := func(p string) string { return filepath.Join(tr.home, p) }

	key, ok := winDeny(j, h(".ssh/id_ed25519"))
	if !ok || key.Deny&WinDenyRead != WinDenyRead {
		t.Errorf("the key isn't denied: %+v", key)
	}
	for _, p := range []string{".ssh/config", ".ssh/known_hosts"} {
		if e, ok := winDeny(j, h(p)); ok && e.Deny&WinDenyRead != 0 {
			t.Errorf("%s is unreadable", p)
		}
	}
	if e, ok := winDeny(j, h(".ssh")); !ok || !e.Inherit || e.Deny&winWriteData == 0 || e.Deny&WinDenyRead != 0 {
		t.Errorf("~/.ssh: %+v", e)
	}
	if e, ok := winDeny(j, h(".golem")); !ok || !e.Inherit || e.Deny&WinDenyRead == 0 {
		t.Errorf("~/.golem: %+v", e)
	}
	if e, ok := winDeny(j, h(".bashrc")); !ok || e.Deny&winWriteDAC == 0 || e.Deny&WinDenyRead != 0 {
		t.Errorf("~/.bashrc: %+v", e)
	}
	if e, ok := winDeny(j, tr.home); !ok || e.Inherit || e.Deny&winWriteData == 0 || e.Deny&winAppendData == 0 {
		t.Errorf("home should refuse new entries: %+v", e)
	}
	if e, ok := winDeny(j, h("Documents")); ok && e.Deny&winAppendData == 0 {
		t.Errorf("Documents/PowerShell is missing, so Documents should refuse new folders: %+v", e)
	}
	if _, ok := winDeny(j, h(".gnupg")); ok {
		t.Error("a missing credential store guarded its parent")
	}
	if _, ok := winDeny(j, h(".aws/credentials")); ok {
		t.Error("the Cloud grant is on, yet ~/.aws is denied")
	}
	if len(j.Registry) != len(windowsPersistenceKeys) || j.Refuse || len(j.DropGroups) != 0 {
		t.Errorf("jail %+v", j)
	}
}

func TestWindowsMissingStartupFileDeniesItsParent(t *testing.T) {
	tr := newLLTree(t)
	c := tr.context()
	j, err := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants()}, c)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := winDeny(j, filepath.Join(tr.home, ".claude")); !ok || e.Deny&winAppendData == 0 {
		t.Errorf("~/.claude/hooks is missing, so ~/.claude should refuse new entries: %+v", e)
	}
}

func TestWindowsGrantsOffAndTaint(t *testing.T) {
	tr := newLLTree(t)
	j, err := CompileWindows(Policy{Enforce: true, State: Clean}, tr.context())
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := winDeny(j, filepath.Join(tr.home, ".aws")); !ok || e.Deny&WinDenyRead == 0 {
		t.Errorf("~/.aws without the Cloud grant: %+v", e)
	}
	if len(j.DropGroups) != 1 || j.DropGroups[0] != "docker-users" {
		t.Errorf("drop groups %v", j.DropGroups)
	}
	tj, err := CompileWindows(Policy{Enforce: true, State: Tainted, Grants: AllGrants()}, tr.context())
	if err != nil || !tj.Refuse {
		t.Fatalf("tainted: %+v %v", tj, err)
	}
}

func TestWindowsDeniesAppStoresWithoutFailingCommands(t *testing.T) {
	tr := newLLTree(t)
	h := func(p string) string { return filepath.Join(tr.home, filepath.FromSlash(p)) }
	plantFile(t, h("AppData/Local/Google/Chrome/User Data/Default/Cookies"))
	plantFile(t, h("AppData/Roaming/Mozilla/Firefox/Profiles/x/logins.json"))
	plantFile(t, h("AppData/Roaming/Slack/storage/x"))
	j, err := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants()}, tr.context())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"AppData/Local/Google/Chrome", "AppData/Roaming/Mozilla/Firefox", "AppData/Roaming/Slack"} {
		e, ok := winDeny(j, h(p))
		if !ok || !e.Inherit || e.Deny&WinDenyRead != WinDenyRead || e.Deny&winWriteData == 0 || !e.Optional {
			t.Errorf("%s: %+v", p, e)
		}
	}
	if e, ok := winDeny(j, h(".golem")); !ok || e.Optional {
		t.Errorf("a credential store became optional: %+v", e)
	}
	if _, ok := winDeny(j, h("AppData/Roaming/Signal")); ok {
		t.Error("an app that isn't installed got an entry")
	}
}

func TestWindowsWorkspaceWritesRunAtLowIntegrity(t *testing.T) {
	tr := newLLTree(t)
	plantFile(t, filepath.Join(tr.home, "AppData", "Local", "npm-cache", "x"))
	open, err := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants()}, tr.context())
	if err != nil {
		t.Fatal(err)
	}
	if open.LowIntegrity || len(open.LowRoots) != 0 {
		t.Errorf("anywhere ran at low integrity: %+v", open)
	}
	j, err := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants(), Writes: WritesWorkspace}, tr.context())
	if err != nil {
		t.Fatal(err)
	}
	if !j.LowIntegrity {
		t.Fatal("workspace writes didn't lower the shell's integrity")
	}
	roots := strings.Join(j.LowRoots, "|")
	for _, want := range []string{tr.ws, tr.tmp, filepath.Join(tr.home, "AppData", "Local", "npm-cache"), filepath.Join(tr.home, ".cache")} {
		if !strings.Contains("|"+roots+"|", "|"+want+"|") {
			t.Errorf("low roots %v lack %s", j.LowRoots, want)
		}
	}
	if strings.Contains(roots, filepath.Join(tr.home, ".npm")) {
		t.Error("a cache that isn't there was labelled")
	}
	if j.Hash() == open.Hash() {
		t.Error("the policy hash doesn't tell the two apart")
	}
}
