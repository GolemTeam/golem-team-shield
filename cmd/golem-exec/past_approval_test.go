package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

func TestOnWindowsAllAgentsJailsCodexGeminiAndCopilot(t *testing.T) {
	f := newFakeSetup(t, "windows")
	hooks := withCodex(t, f)
	writeFile(t, filepath.Join(f.home, ".gemini", "installation_id"), "x")
	writeFile(t, filepath.Join(f.home, ".copilot", "config.json"), "{}")
	writeFile(t, shield.ConfigPath(f.home), `{"network": "open"}`)

	if code := f.install(false, false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	if b, _ := os.ReadFile(hooks); strings.Contains(string(b), "hook codex") {
		t.Fatalf("Codex was hooked without the switch: %s", b)
	}
	if _, err := os.Stat(shield.CopilotHooksFile(f.home)); err == nil {
		t.Fatal("Copilot CLI was hooked without the switch")
	}

	if code := runCommand(f.setup, []string{"install", "--all-agents"}); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	cfg, _ := os.ReadFile(shield.ConfigPath(f.home))
	if !strings.Contains(string(cfg), `"network": "open"`) || !strings.Contains(string(cfg), `"jail_past_approval": true`) || strings.Contains(string(cfg), "null") {
		t.Fatalf("shield.json: %s", cfg)
	}
	quoted, _ := json.Marshal(f.hookCommand("codex"))
	if b, _ := os.ReadFile(hooks); !strings.Contains(string(b), string(quoted)) || !strings.Contains(f.hookCommand("codex"), "golem-exec.exe hook codex") {
		t.Fatalf("hooks.json: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(f.home, ".gemini", "settings.json")); !strings.Contains(string(b), "hook gemini-cli") {
		t.Fatalf("Gemini settings: %s", b)
	}
	copilot, _ := os.ReadFile(shield.CopilotHooksFile(f.home))
	if !strings.Contains(string(copilot), `"powershell"`) || strings.Contains(string(copilot), `"bash"`) {
		t.Fatalf("Copilot hook file: %s", copilot)
	}

	shim := shield.WindowsHookShim(f.home)
	for client, in := range map[string]map[string]any{
		"codex":      {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "Remove-Item x"}},
		"gemini-cli": {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": map[string]any{"command": "Remove-Item x"}},
		"copilot":    {"sessionId": "cp-1", "cwd": f.home, "toolName": "powershell", "toolArgs": map[string]any{"command": "Remove-Item x"}},
	} {
		b, _ := json.Marshal(in)
		f.stdin = strings.NewReader(string(b))
		f.out.Reset()
		if code := runCommand(f.setup, []string{"hook", client}); code != 0 {
			t.Fatalf("%s: exit %d", client, code)
		}
		var want map[string]any
		switch client {
		case "codex":
			want = shield.CodexRewrite(shim, in)
		case "gemini-cli":
			want = shield.GeminiRewrite(shim, in)
		case "copilot":
			want = shield.CopilotRewrite(shim, in)
		}
		wantJSON, _ := json.Marshal(want)
		if got := strings.TrimSpace(f.out.String()); got != string(wantJSON) {
			t.Errorf("%s: %s, want %s", client, got, wantJSON)
		}
		if runtime.GOOS == "windows" && strings.Contains(string(wantJSON), "deny") {
			t.Errorf("%s: a Windows home's shim was refused: %s", client, wantJSON)
		}
	}

	if code := f.uninstall(false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	if b, _ := os.ReadFile(hooks); strings.Contains(string(b), "hook codex") || !strings.Contains(string(b), "mine.sh") {
		t.Fatalf("hooks.json after uninstall: %s", b)
	}
	if _, err := os.Stat(shield.CopilotHooksFile(f.home)); err == nil {
		t.Fatal("the Copilot hook file is still there")
	}
}

func TestWithoutTheSwitchTheWindowsHookLeavesTheCommand(t *testing.T) {
	f := newFakeSetup(t, "windows")
	if code := f.install(false, false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	f.stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	f.out.Reset()
	if code := runCommand(f.setup, []string{"hook", "codex"}); code != 0 || f.out.Len() != 0 {
		t.Fatalf("exit %d: %s", code, f.out.String())
	}
}

func TestAllAgentsJailsDevinAndUninstallTakesItOut(t *testing.T) {
	if hostLayout() == "windows" {
		t.Skip("the Unix shim layout")
	}
	f := newFakeSetup(t, "darwin")
	writeFile(t, filepath.Join(f.home, ".codeium", "windsurf", "x"), "")
	writeFile(t, shield.DevinConfig(f.home), `{"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "mine.sh"}]}]}}`)
	if code := f.install(false, false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	if b, _ := os.ReadFile(shield.DevinConfig(f.home)); strings.Contains(string(b), "hook devin") {
		t.Fatalf("Devin was hooked without the switch: %s", b)
	}
	if code := f.install(false, true); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	if b, _ := os.ReadFile(shield.DevinConfig(f.home)); !strings.Contains(string(b), f.hookCommand("devin")) || !strings.Contains(string(b), "mine.sh") {
		t.Fatalf("Devin's config: %s", b)
	}
	f.out.Reset()
	f.status()
	if !strings.Contains(f.out.String(), "Devin's shell commands run in the Golem jail") {
		t.Errorf("status:\n%s", f.out.String())
	}
	if code := f.uninstall(false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	if b, _ := os.ReadFile(shield.DevinConfig(f.home)); strings.Contains(string(b), "hook devin") || !strings.Contains(string(b), "mine.sh") {
		t.Fatalf("Devin's config after uninstall: %s", b)
	}
}
