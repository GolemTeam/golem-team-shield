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

func TestWindowsHoldsTheAgentsProjectFiles(t *testing.T) {
	tr := newLLTree(t)
	for _, f := range []string{".claude/settings.json", ".claude/commands/x.md", ".mcp.json", ".github/workflows/ci.yml", "sub/main.go"} {
		plantFile(t, filepath.Join(tr.ws, f))
	}
	c := tr.context()
	c.WorkingDir = filepath.Join(tr.ws, "sub")
	for _, p := range []Policy{{Enforce: true, State: Clean, Grants: AllGrants()}, {Enforce: true, State: Clean, Grants: AllGrants(), Writes: WritesWorkspace}} {
		j, err := CompileWindows(p, c)
		if err != nil {
			t.Fatal(err)
		}
		w := func(rel string) (WindowsACE, bool) { return winDeny(j, filepath.Join(tr.ws, rel)) }
		for _, f := range []string{".claude/settings.json", ".mcp.json"} {
			if e, ok := w(f); !ok || e.Deny&WinDenyWrite != WinDenyWrite || e.Deny&WinDenyRead != 0 {
				t.Errorf("%s: %+v", f, e)
			}
		}
		if e, ok := w(".claude"); !ok || e.Deny&winDenyEntry != winDenyEntry || e.Deny&winWriteData == 0 || e.Deny&winAppendData != 0 || e.Inherit {
			t.Errorf(".claude should stay in place and refuse new files, settings.local.json being missing: %+v", e)
		}
		if e, ok := w(".github"); !ok || e.Deny&winDenyEntry != winDenyEntry || e.Deny&winAppendData == 0 || e.Deny&winWriteData != 0 {
			t.Errorf(".github should stay in place and refuse new folders, hooks and copilot being missing: %+v", e)
		}
		if e, ok := w(""); !ok || e.Deny&winDeleteChild == 0 || e.Deny&(winWriteData|winAppendData|winDelete) != 0 || e.Inherit {
			t.Errorf("the root should refuse removing entries through it, and nothing else: %+v", e)
		}
		if e, ok := w("sub"); !ok || e.Deny&winDenyEntry != winDenyEntry || e.Deny&(winWriteData|winAppendData) != 0 {
			t.Errorf("the folder on the way to the working directory should stay in place: %+v", e)
		}
		for _, free := range []string{".github/workflows", ".github/workflows/ci.yml", ".claude/commands", "sub/main.go", ".mcp.json/x"} {
			if e, ok := w(free); ok {
				t.Errorf("%s would stop ordinary work: %+v", free, e)
			}
		}
		held := map[string]bool{}
		for _, h := range j.Hold {
			held[h] = true
		}
		for _, rel := range []string{".cursor", ".vscode", "sub/.claude", "sub/.github", "sub/.gemini"} {
			if !held[filepath.Join(tr.ws, rel)] {
				t.Errorf("%s is missing and wasn't made to be held: %v", rel, j.Hold)
			}
		}
		for _, rel := range []string{".claude", ".github", ".mcp.json", "sub/.mcp.json", "sub/main.go"} {
			if held[filepath.Join(tr.ws, rel)] {
				t.Errorf("%s was made", rel)
			}
		}
		if e, ok := w(".cursor"); !ok || e.Deny&winDenyEntry != winDenyEntry || e.Deny&winWriteData == 0 {
			t.Errorf("a made .cursor should stay in place and refuse new files: %+v", e)
		}
	}
}

func TestWindowsMakesTheMissingAgentFoldersToHoldThem(t *testing.T) {
	tr := newLLTree(t)
	c := tr.context()
	j, err := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants()}, c)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, d := range []string{".agents", ".claude", ".codex", ".cursor", ".devin", ".gemini", ".github", ".vscode"} {
		want = append(want, filepath.Join(tr.ws, d))
	}
	if strings.Join(j.Hold, "|") != strings.Join(want, "|") {
		t.Fatalf("hold %v, want %v", j.Hold, want)
	}
	if e, ok := winDeny(j, filepath.Join(tr.ws, ".claude")); !ok || e.Deny&winDenyEntry != winDenyEntry || e.Deny&winWriteData == 0 {
		t.Errorf(".claude: %+v", e)
	}
	if e, ok := winDeny(j, filepath.Join(tr.ws, ".github")); !ok || e.Deny&winAppendData == 0 || e.Deny&winWriteData != 0 {
		t.Errorf(".github should refuse new folders, not new files: %+v", e)
	}
	if e, ok := winDeny(j, tr.ws); !ok || e.Deny&winDeleteChild == 0 || e.Deny&(winWriteData|winAppendData) != 0 {
		t.Errorf("root: %+v", e)
	}
	c.Workspace = []string{filepath.Join(tr.root, "outside")}
	if j, _ := CompileWindows(Policy{Enforce: true, State: Clean, Grants: AllGrants()}, c); len(j.Hold) != 0 {
		t.Errorf("made folders in a workspace that is no work tree: %v", j.Hold)
	}
}
