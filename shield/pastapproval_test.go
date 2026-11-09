package shield

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTheAgentsSwitchOutranksShieldJSON(t *testing.T) {
	home := t.TempDir()
	if JailsPastApproval(home) {
		t.Fatal("on with nothing set")
	}
	if err := WriteConfig(ConfigPath(home), Config{JailPastApproval: true}); err != nil {
		t.Fatal(err)
	}
	if !JailsPastApproval(home) {
		t.Fatal("shield.json's switch was not read")
	}
	if err := SetPastApproval(home, false); err != nil {
		t.Fatal(err)
	}
	if JailsPastApproval(home) {
		t.Fatal("the Golem agent's off lost to shield.json")
	}
	if err := SetPastApproval(home, true); err != nil {
		t.Fatal(err)
	}
	if !JailsPastApproval(home) {
		t.Fatal("the Golem agent's on was not read")
	}
	if fi, err := os.Stat(PastApprovalPath(home)); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("%v %v", fi, err)
	}
}

func TestWrapCommandWrapsForTheShimsShell(t *testing.T) {
	pwsh := `C:\Users\x\.golem\bin\hook\pwsh.exe`
	got, err := WrapCommand(pwsh, "Get-ChildItem")
	want, _ := WrapPowerShell(pwsh, "Get-ChildItem")
	if err != nil || got != want {
		t.Fatalf("%q %v", got, err)
	}
	got, err = WrapCommand("/h/.golem/bin/hook/bash", "ls")
	want, _ = Wrap("/h/.golem/bin/hook/bash", "ls")
	if err != nil || got != want {
		t.Fatalf("%q %v", got, err)
	}
}

func TestRewritesOnWindowsRunPowerShellThroughTheShim(t *testing.T) {
	shim := `C:\Users\x\.golem\bin\hook\pwsh.exe`
	want, _ := WrapPowerShell(shim, "Remove-Item x")

	codex := CodexRewrite(shim, map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "Remove-Item x"}})
	if got := codex["hookSpecificOutput"].(map[string]any)["updatedInput"].(map[string]any)["command"]; got != want {
		t.Errorf("codex: %v", got)
	}
	gemini := GeminiRewrite(shim, map[string]any{"tool_name": "run_shell_command", "tool_input": map[string]any{"command": "Remove-Item x"}})
	if got := gemini["hookSpecificOutput"].(map[string]any)["tool_input"].(map[string]any)["command"]; got != want {
		t.Errorf("gemini: %v", got)
	}
	copilot := CopilotRewrite(shim, map[string]any{"toolName": "powershell", "toolArgs": `{"command":"Remove-Item x","description":"d"}`})
	args := copilot["modifiedArgs"].(map[string]any)
	if args["command"] != want || args["description"] != "d" {
		t.Errorf("copilot: %v", args)
	}
	if CopilotRewrite(shim, map[string]any{"toolName": "bash", "toolArgs": `{"command":"ls"}`}) != nil {
		t.Error("a bash call was rewritten for PowerShell")
	}
	if CopilotRewrite("/h/.golem/bin/hook/bash", map[string]any{"toolName": "powershell", "toolArgs": `{"command":"ls"}`}) != nil {
		t.Error("a powershell call was rewritten for bash")
	}
}

func TestGolemExecsPowerShellHookIsItsOwn(t *testing.T) {
	cmd := PowerShellHook(`C:\Users\o'neil\.golem\bin\golem-exec.exe`, "hook", "copilot")
	if cmd != `& 'C:\Users\o''neil\.golem\bin\golem-exec.exe' hook copilot` {
		t.Fatal(cmd)
	}
	if !IsCopilotJailHook(cmd) || !isGolemExecHook(cmd, "copilot") {
		t.Fatal("golem-exec's PowerShell hook was not recognised")
	}
	for _, c := range []string{`& 'C:\x\golem-exec.exe' hook copilot extra`, `& 'C:\x\other.exe' hook copilot`, `& 'C:\x\golem-exec.exe hook copilot`} {
		if isGolemExecHook(c, "copilot") {
			t.Errorf("%q was taken for golem-exec's hook", c)
		}
	}
}

func TestOnWindowsTheHookClientsAreJailedOnlyWithTheSwitch(t *testing.T) {
	ready := func(string) bool { return true }
	for _, tc := range []struct{ client string }{{"codex"}, {"gemini-cli"}, {"copilot"}} {
		for _, on := range []bool{false, true} {
			home := t.TempDir()
			codexDir := filepath.Join(home, ".codex")
			hooksJSON := filepath.Join(codexDir, "hooks.json")
			files := map[string]string{
				".codex/config.toml":        "[hooks.state." + quoteTOMLKey(hooksJSON+":pre_tool_use:0:0") + "]\ntrusted_hash = \"abc\"\n",
				".codex/hooks.json":         `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"C:\\g\\golem.exe codex-hook PreToolUse"}]}]}}`,
				".gemini/installation_id":   "x",
				".gemini/settings.json":     `{"hooks":{"BeforeTool":[{"matcher":".*","hooks":[{"command":"C:\\g\\golem.exe gemini-hook BeforeTool"}]}]}}`,
				".copilot/config.json":      "{}",
				".copilot/hooks/golem.json": `{"hooks":{"preToolUse":[{"bash":"if [ -x '/g' ]; then '/g' copilot-hook preToolUse; fi","powershell":"& 'C:\\g\\golem.exe' copilot-hook preToolUse"}]}}`,
			}
			for p, body := range files {
				plantBody(t, filepath.Join(home, p), body)
			}
			if err := SetPastApproval(home, on); err != nil {
				t.Fatal(err)
			}
			var c *AgentCoverage
			for _, l := range CoverageOf(CoverageEnv{Home: home, GOOS: "windows", ShimReady: ready, CodexHomes: []string{codexDir}}) {
				if l.Client == tc.client {
					c = &l
				}
			}
			switch {
			case c == nil:
				t.Fatalf("%s: no line", tc.client)
			case !on && (c.Coverage != NotJailed || !c.PastApproval || !strings.Contains(c.Detail, "would jail them anyway")):
				t.Errorf("%s off: %s %q", tc.client, c.Coverage, c.Detail)
			case on && (c.Coverage != Jailed || c.PastApproval || !strings.Contains(c.Detail, "past its own approval")):
				t.Errorf("%s on: %s %q", tc.client, c.Coverage, c.Detail)
			}
		}
	}
}

func quoteTOMLKey(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func plantBody(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
