package shield

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Copilot CLI runs its bash tool in a long-lived bash over a pty and has no
// setting that names it for the jail (COPILOT_BASH_PATH replaces the bash the
// session itself runs in). Its preToolUse hook can answer modifiedArgs, which
// replaces the call's arguments, so the hook hands back the arguments with
// the command run through the hook shim (docs/design-local-shield.md, Other
// clients). The answer carries no permissionDecision, so Copilot's own
// approval is untouched. The hook file is also read by VS Code's Local
// harness, which sends Claude Code's snake_case payload and reads a different
// answer; that one is left alone until VS Code's ordering is known.

// CopilotRewrite is Copilot CLI's preToolUse answer that runs a bash call's
// command through shim, or nil for any other call or payload. A command Wrap
// refuses is denied.
func CopilotRewrite(shim string, in map[string]any) map[string]any {
	if _, snake := in["hook_event_name"]; snake {
		return nil
	}
	if name, _ := in["toolName"].(string); name != copilotShellTool(shim) {
		return nil
	}
	args := map[string]any{}
	switch a := in["toolArgs"].(type) {
	case map[string]any:
		for k, v := range a {
			args[k] = v
		}
	case string:
		_ = json.Unmarshal([]byte(a), &args)
	}
	command, _ := args["command"].(string)
	wrapped, err := WrapCommand(shim, command)
	if err != nil {
		return map[string]any{"permissionDecision": "deny", "permissionDecisionReason": "Golem can't run this command in its shell jail, so it was not run"}
	}
	args["command"] = wrapped
	return map[string]any{"modifiedArgs": args}
}

// copilotShellTool is the tool a shim's rewrite is for: bash, or powershell
// on Windows.
func copilotShellTool(shim string) string {
	if strings.HasSuffix(strings.ToLower(shim), ".exe") {
		return "powershell"
	}
	return "bash"
}

// NoteCopilotSession leaves the hook's session for the shim. Copilot's
// commands carry COPILOT_AGENT_SESSION_ID, but whether it is the id the hook
// is told is not established, and the hook's is the one the Golem agent keys
// a session's taint by, so the shim takes this note first.
func NoteCopilotSession(home string, in map[string]any) {
	session, _ := in["sessionId"].(string)
	cwd, _ := in["cwd"].(string)
	_ = NoteHookSession(home, "copilot", cwd, session)
}

// IsCopilotJailHook reports whether a hook command rewrites Copilot CLI's
// commands into the jail: the Golem agent's preToolUse hook (guarded by an
// `if [ -x … ]`), or golem-exec's.
func IsCopilotJailHook(command string) bool {
	return strings.Contains(command, " copilot-hook preToolUse") || isGolemExecHook(command, "copilot")
}

// CopilotHooksFile is golem-exec's own hook file, beside the Golem agent's
// golem.json in the directory Copilot reads every file of.
func CopilotHooksFile(home string) string {
	return filepath.Join(home, ".copilot", "hooks", "golem-shield.json")
}

// CopilotHookFile is the content of CopilotHooksFile for a golem-exec at exe.
// Copilot runs a hook's powershell command on Windows, and its bash one
// elsewhere.
func CopilotHookFile(exe string, windows bool) []byte {
	hook := map[string]any{"type": "command", "bash": exe + " hook copilot", "timeoutSec": codexHookTimeout}
	if windows {
		hook = map[string]any{"type": "command", "powershell": PowerShellHook(exe, "hook", "copilot"), "timeoutSec": codexHookTimeout}
	}
	b, _ := json.MarshalIndent(map[string]any{"version": 1, "hooks": map[string]any{
		"preToolUse": []map[string]any{hook},
	}}, "", "  ")
	return append(b, '\n')
}

// CopilotInstalled reads the files Copilot CLI writes, not ~/.copilot, which
// Golem's own wiring creates.
func CopilotInstalled(home string) bool {
	c := filepath.Join(home, ".copilot")
	return exists(filepath.Join(c, "config.json")) || exists(filepath.Join(c, "settings.json")) || exists(filepath.Join(c, "session-state"))
}

func copilotCoverage(env CoverageEnv) (AgentCoverage, bool) {
	if !CopilotInstalled(env.Home) {
		return AgentCoverage{}, false
	}
	dir := filepath.Join(env.Home, ".copilot", "hooks")
	c := AgentCoverage{Client: "copilot", Label: "Copilot CLI", Coverage: NotJailed, Location: tilde(env.Home, dir)}
	shim, past := hookShimFor(env, filepath.Join(HookShimDir(env.Home), "bash"))
	if shim == "" {
		c.Detail = "On Windows Golem doesn't rewrite Copilot CLI's PowerShell commands: approving one for the session would approve every command" + pastApprovalHint
		c.PastApproval = true
		return c, true
	}
	hooked := false
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			Hooks struct {
				PreToolUse []struct {
					Bash       string `json:"bash"`
					PowerShell string `json:"powershell"`
				} `json:"preToolUse"`
			} `json:"hooks"`
		}
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		for _, h := range doc.Hooks.PreToolUse {
			cmd := h.Bash
			if env.GOOS == "windows" {
				cmd = h.PowerShell
			}
			hooked = hooked || IsCopilotJailHook(cmd)
		}
	}
	switch {
	case !hooked:
		c.Detail = "Copilot CLI's shell commands run without the Golem jail: no preToolUse hook rewrites them"
	case !env.ShimReady(shim):
		c.Detail = "Copilot CLI's hook would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, "pre-tool hook"
		c.Detail = "Copilot CLI's shell commands run in the Golem jail through its preToolUse hook" + past
	}
	return c, true
}
