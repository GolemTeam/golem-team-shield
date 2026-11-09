package agentposture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

const fakeToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func applyForTest(t *testing.T, plan FixPlan) {
	t.Helper()
	for _, f := range plan.Files {
		if f.New != nil {
			if err := os.WriteFile(f.Path, f.New, f.NewMode); err != nil {
				t.Fatal(err)
			}
		}
		chmod(t, f.Path, f.NewMode)
	}
}

func riskyHome(t *testing.T) (Env, string) {
	t.Helper()
	env := postureTestEnv(t)
	project := filepath.Join(t.TempDir(), "repo")
	projects, _ := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{}}})
	writePostureFile(t, filepath.Join(env.Home, ".claude.json"), string(projects))
	shared := filepath.Join(t.TempDir(), "shared")
	guard := filepath.Join(shared, "guard.sh")
	writePostureFile(t, guard, "#!/bin/sh\nexit 0\n")
	chmod(t, guard, 0o666)
	settings := filepath.Join(env.Home, ".claude", "settings.json")
	writePostureFile(t, settings, `{
  "env": {"GITHUB_TOKEN": "`+fakeToken+`"},
  "permissions": {
    "defaultMode": "bypassPermissions",
    "allow": ["Read", "Bash(*)", "Bash", "Write(*)", "WebFetch", "mcp__*", "mcp__github"]
  },
  "skipDangerousModePermissionPrompt": true,
  "enableAllProjectMcpServers": true,
  "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "bash `+guard+` && echo ok"}]}]},
  "cleanupPeriodDays": 1786000000000
}
`)
	chmod(t, settings, 0o644)
	writePostureFile(t, filepath.Join(project, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	writePostureFile(t, filepath.Join(env.ManagedDir, "managed-settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "settings.json"),
		`{"tools":{"allowed":["read_file","run_shell_command","write_file","web_fetch"]},"security":{"folderTrust":{"enabled":false}}}`)
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"),
		`{"approvalMode":"unrestricted","permissions":{"allow":["Read(**)","Write(**)"]}}`)
	writePostureFile(t, filepath.Join(env.Home, ".config", "devin", "config.json"),
		`{"permissions":{"allow":["exec","Exec(git status)"]}}`)
	writePostureFile(t, filepath.Join(env.Home, ".config", "Code", "User", "settings.json"),
		"{\n    \"editor.fontSize\": 14,\n    \"chat.tools.global.autoApprove\": true,\n    \"security.workspace.trust.enabled\": false\n}\n")
	writePostureFile(t, filepath.Join(env.Home, ".codex", "config.toml"),
		"model = \"o3\"\nsandbox_mode = \"danger-full-access\" # wide open\napproval_policy = \"never\"\n\n[profiles.fast]\nsandbox_mode = \"danger-full-access\"\nmodel = \"o4\"\n")
	writePostureFile(t, filepath.Join(env.Home, ".codex", "auth.json"), `{"token":"x"}`)
	chmod(t, filepath.Join(env.Home, ".codex", "auth.json"), 0o644)
	return env, project
}

var fixedChecks = map[string]bool{
	"bypass_default": true, "bypass_accepted": true, "shell_allowed": true, "write_allowed": true,
	"fetch_allowed": true, "mcp_all_allowed": true, "project_mcp_auto": true, "folder_trust_off": true,
	"run_everything": true, "tools_auto_approve": true, "workspace_trust_off": true, "full_access": true,
	"credential_file_readable": true, "config_plaintext_secret": true, "hook_script_writable": true,
}

func TestEveryFixUndoesItsFindingAndKeepsTheRest(t *testing.T) {
	env, project := riskyHome(t)
	before := ScanAll(env)
	plan := PlanFixes(env)
	if len(plan.Files) == 0 {
		t.Fatal("no plan")
	}
	for _, f := range plan.Files {
		if strings.HasPrefix(f.Path, project) || strings.HasPrefix(f.Path, env.ManagedDir) {
			t.Errorf("planned a change outside the person's own settings: %s", f.Location)
		}
		if len(f.Changes) == 0 || len(f.Items) == 0 {
			t.Errorf("%s: a change with nothing to say for it: %+v", f.Location, f)
		}
	}
	applyForTest(t, plan)
	after := ScanAll(env)

	for _, it := range after.Items {
		own := it.Scope == "user" && !strings.HasPrefix(it.Location, "/")
		if own && fixedChecks[it.Check] && Rank(it.Severity) <= Rank(Suspicious) {
			t.Errorf("still there after -fix: %+v", it)
		}
	}
	if Score(after).Score <= Score(before).Score {
		t.Errorf("score %d -> %d", Score(before).Score, Score(after).Score)
	}
	var stillProject, stillManaged bool
	for _, it := range after.Items {
		if it.Check == "bypass_default" {
			stillProject = stillProject || it.Scope == "project"
			stillManaged = stillManaged || it.Scope == "managed"
		}
	}
	if !stillProject || !stillManaged {
		t.Error("a repository's or the managed policy's setting was changed")
	}

	claude := readFile(t, filepath.Join(env.Home, ".claude", "settings.json"))
	for _, kept := range []string{`"Read"`, `"mcp__github"`, fakeToken, `1786000000000`, `&& echo ok`, `"cleanupPeriodDays"`} {
		if !strings.Contains(claude, kept) {
			t.Errorf("lost %s:\n%s", kept, claude)
		}
	}
	if strings.Index(claude, `"env"`) > strings.Index(claude, `"permissions"`) {
		t.Errorf("key order changed:\n%s", claude)
	}
	if vs := readFile(t, filepath.Join(env.Home, ".config", "Code", "User", "settings.json")); vs != "{\n    \"editor.fontSize\": 14\n}\n" {
		t.Errorf("VS Code settings keep their indent and other keys:\n%q", vs)
	}
	if codex := readFile(t, filepath.Join(env.Home, ".codex", "config.toml")); codex != "model = \"o3\"\napproval_policy = \"never\"\n\n[profiles.fast]\nmodel = \"o4\"\n" {
		t.Errorf("codex:\n%s", codex)
	}
	if g := readFile(t, filepath.Join(env.Home, ".gemini", "settings.json")); !strings.Contains(g, `"allowed":["read_file"]`) || !strings.Contains(g, `"enabled":true`) {
		t.Errorf("gemini: %s", g)
	}
	if d := readFile(t, filepath.Join(env.Home, ".config", "devin", "config.json")); !strings.Contains(d, `"Exec(git status)"`) || strings.Contains(d, `"exec"`) {
		t.Errorf("devin: %s", d)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{
			filepath.Join(env.Home, ".claude", "settings.json"): 0o600,
			filepath.Join(env.Home, ".codex", "auth.json"):      0o600,
		} {
			if info, _ := os.Stat(path); info.Mode().Perm() != want {
				t.Errorf("%s mode %o", path, info.Mode().Perm())
			}
		}
	}
}

func TestPlanSaysWhatItLeavesAlone(t *testing.T) {
	env, _ := riskyHome(t)
	reasons := map[string]bool{}
	for _, s := range PlanFixes(env).Skipped {
		if s.Item.Check == "bypass_default" {
			reasons[s.Item.Scope+": "+s.Reason] = true
		}
	}
	var managed, project bool
	for r := range reasons {
		managed = managed || strings.HasPrefix(r, "managed: managed policy")
		project = project || strings.HasPrefix(r, "project: in a repository's files")
	}
	if !managed || !project {
		t.Errorf("skipped: %v", reasons)
	}
}

func TestFilesItCannotEditSafelyAreLeftAlone(t *testing.T) {
	env := postureTestEnv(t)
	settings := filepath.Join(env.Home, ".claude", "settings.json")
	writePostureFile(t, settings, "{\n  // mine\n  \"permissions\": {\"defaultMode\": \"bypassPermissions\"},\n}\n")
	writePostureFile(t, filepath.Join(env.Home, ".codex", "config.toml"), "instructions = \"\"\"\nsandbox_mode = \"danger-full-access\"\n\"\"\"\nsandbox_mode = \"danger-full-access\"\n")
	real := filepath.Join(t.TempDir(), "cli-config.json")
	writePostureFile(t, real, `{"approvalMode":"unrestricted"}`)
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "keep"), "")
	if err := os.Symlink(real, filepath.Join(env.Home, ".cursor", "cli-config.json")); err != nil {
		t.Skip("no symlinks here")
	}

	plan := PlanFixes(env)
	if len(plan.Files) != 0 {
		t.Errorf("planned %d changes to files it should leave alone: %+v", len(plan.Files), plan.Files)
	}
	why := map[string]string{}
	for _, s := range plan.Skipped {
		why[s.Item.Check] = s.Reason
	}
	for check, want := range map[string]string{"bypass_default": "not plain JSON", "full_access": "multi-line", "run_everything": "symbolic link"} {
		if !strings.Contains(why[check], want) {
			t.Errorf("%s: %q, want %q", check, why[check], want)
		}
	}
}

func TestAHookScriptInAFolderOthersCanWriteIsOnlyReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	env := postureTestEnv(t)
	shared := filepath.Join(t.TempDir(), "shared")
	guard := filepath.Join(shared, "guard.sh")
	writePostureFile(t, guard, "#!/bin/sh\n")
	chmod(t, guard, 0o755)
	chmod(t, shared, 0o777)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":`+mustJSON(guard)+`}]}]}}`)
	plan := PlanFixes(env)
	if len(plan.Files) != 0 {
		t.Errorf("changed %+v", plan.Files)
	}
	if len(plan.Skipped) != 1 || !strings.Contains(plan.Skipped[0].Reason, "changes no folder") {
		t.Errorf("skipped %+v", plan.Skipped)
	}
}

func TestTheDiffNeverShowsASecret(t *testing.T) {
	env, _ := riskyHome(t)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "settings.json"),
		"{\n  \"apiKey\": \"Zx9fQ2mVb7LkP4sTqW8rY1uN\",\n  \"tools\": {\n    \"allowed\": [\"run_shell_command\"]\n  },\n  \"x\": [\"--token="+fakeToken+"\"]\n}\n")
	var diffs strings.Builder
	for _, f := range PlanFixes(env).Files {
		diffs.WriteString(f.Diff())
	}
	d := diffs.String()
	if strings.Contains(d, fakeToken) || strings.Contains(d, "Zx9fQ2mVb7LkP4sTqW8rY1uN") {
		t.Fatalf("a secret reached the diff:\n%s", d)
	}
	for _, want := range []string{`-    "defaultMode": "bypassPermissions",`, `"apiKey": "<redacted>"`, "--- ~/.claude/settings.json"} {
		if !strings.Contains(d, want) {
			t.Errorf("diff lacks %q:\n%s", want, d)
		}
	}
}

func TestFormatLikeKeepsTheLayout(t *testing.T) {
	for _, orig := range []string{
		`{"a":1,"b":"x && y"}`,
		"{\r\n\t\"a\": 1,\r\n\t\"b\": \"x && y\"\r\n}\r\n",
		"{\n    \"a\": 1,\n    \"b\": \"x && y\"\n}",
	} {
		doc, err := jsonobject.Parse([]byte(orig))
		if err != nil {
			t.Fatal(err)
		}
		got, err := formatLike([]byte(orig), doc)
		if err != nil || string(got) != orig {
			t.Errorf("%q came back as %q (%v)", orig, got, err)
		}
	}
}

func TestAHomeLocationResolvesWithEitherSeparator(t *testing.T) {
	home := filepath.Join(t.TempDir(), "h")
	want := filepath.Join(home, ".claude", "settings.json")
	native := "~" + string(filepath.Separator) + filepath.Join(".claude", "settings.json")
	for _, loc := range []string{"~/.claude/settings.json", native} {
		if got := realPath(home, loc); got != want {
			t.Errorf("realPath(%q) = %q, want %q", loc, got, want)
		}
	}
}
