package agentposture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeRepo(t *testing.T, parent, name string) string {
	t.Helper()
	root := filepath.Join(parent, name)
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestARepoCanTurnPromptsOffForCursorGeminiAndCodex(t *testing.T) {
	env := postureTestEnv(t)
	repo := makeRepo(t, t.TempDir(), "cloned")
	writePostureFile(t, filepath.Join(repo, ".cursor", "cli.json"), `{"approvalMode": "unrestricted"}`)
	writePostureFile(t, filepath.Join(repo, ".gemini", "settings.json"), `{"tools": {"allowed": ["run_shell_command"]}}`)
	writePostureFile(t, filepath.Join(repo, ".codex", "config.toml"), `sandbox_mode = "danger-full-access"`)
	env.Projects = []string{repo}

	got := postureByKey(Scan(env))
	if it := got[postureKey{"cursor", "run_everything", "project"}]; it.Severity != Dangerous ||
		it.Location != filepath.Join(repo, ".cursor", "cli.json") {
		t.Errorf("cursor project = %v", it)
	}
	if got[postureKey{"gemini-cli", "shell_allowed", "project"}].Severity != Suspicious {
		t.Errorf("gemini project = %v", got)
	}
	if got[postureKey{"codex", "full_access", "project"}].Severity != Dangerous {
		t.Errorf("codex project = %v", got)
	}
}

func TestDevinConfigsThatAllowEveryCommand(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".config", "devin", "config.json"),
		`{"permissions": {"allow": ["read", "exec"]}}`)
	repo := makeRepo(t, t.TempDir(), "infra")
	writePostureFile(t, filepath.Join(repo, ".devin", "config.local.json"), `{"permissions": {"allow": ["Exec"]}}`)
	writePostureFile(t, filepath.Join(repo, ".devin", "config.json"), `{"permissions": {"allow": ["Exec(npm test)"]}}`)
	env.Projects = []string{repo}

	got := postureByKey(Scan(env))
	if got[postureKey{"devin", "shell_allowed", "user"}].Severity != Suspicious {
		t.Errorf("user config = %v", got)
	}
	if it := got[postureKey{"devin", "shell_allowed", "local"}]; !strings.Contains(it.Detail, "infra") {
		t.Errorf("repo local config = %v", it)
	}
	if has(got, postureKey{"devin", "shell_allowed", "project"}) {
		t.Error("an Exec(<command>) rule allows one command, not every one")
	}
}
