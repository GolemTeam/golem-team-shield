package shield

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Antigravity's agent runs `bash -c` and has no setting for it. Its PreToolUse
// answer takes an overwrite, merged key by key into the call's arguments, and
// a decision, which it requires (docs/design-local-shield.md, Other clients).
// The Golem agent's hook already answers every call with a decision, so it
// adds the overwrite to that. golem-exec has no hook of its own for
// Antigravity: any decision it gave would change whether Antigravity asks.

var antigravityShellTools = map[string]bool{"run_command": true, "run_terminal_command": true}

var antigravityCommandKeys = []string{"CommandLine", "commandLine", "command", "Command", "command_line", "cmd", "Cmd"}

// AntigravityOverwrite is the overwrite that runs a shell call's command
// through shim, or nil for any other call; refused is a command Wrap refuses,
// which the hook denies.
func AntigravityOverwrite(shim, tool string, args map[string]any) (overwrite map[string]any, refused bool) {
	if !antigravityShellTools[tool] {
		return nil, false
	}
	for _, k := range antigravityCommandKeys {
		if command, ok := args[k].(string); ok {
			wrapped, err := Wrap(shim, command)
			if err != nil {
				return nil, true
			}
			return map[string]any{k: wrapped}, false
		}
	}
	return nil, true
}

// IsAntigravityJailHook reports whether a hook command is the Golem agent's
// Antigravity PreToolUse hook, which rewrites its shell calls.
func IsAntigravityJailHook(command string) bool {
	return strings.Contains(command, " antigravity-hook PreToolUse")
}

// AntigravityInstalled reads the directories Antigravity's three surfaces
// keep under ~/.gemini.
func AntigravityInstalled(home string) bool {
	g := filepath.Join(home, ".gemini")
	return exists(filepath.Join(g, "antigravity")) || exists(filepath.Join(g, "antigravity-ide")) || exists(filepath.Join(g, "antigravity-cli")) || exists(filepath.Join(g, "config", "config.json"))
}

func antigravityCoverage(env CoverageEnv) (AgentCoverage, bool) {
	if !AntigravityInstalled(env.Home) {
		return AgentCoverage{}, false
	}
	path := filepath.Join(env.Home, ".gemini", "config", "hooks.json")
	c := AgentCoverage{Client: "antigravity", Label: "Antigravity", Coverage: NotJailed, Location: tilde(env.Home, path)}
	if env.GOOS == "windows" {
		c.Detail = "Antigravity's shell commands on Windows aren't covered by the Golem jail yet"
		return c, true
	}
	hooked := false
	var plugins map[string]json.RawMessage
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &plugins) == nil {
		for _, raw := range plugins {
			var block struct {
				PreToolUse []json.RawMessage `json:"PreToolUse"`
			}
			_ = json.Unmarshal(raw, &block)
			for _, g := range block.PreToolUse {
				for _, cmd := range codexGroupCommands(g) {
					hooked = hooked || IsAntigravityJailHook(cmd)
				}
			}
		}
	}
	shim := filepath.Join(HookShimDir(env.Home), "bash")
	switch {
	case !hooked:
		c.Detail = "Antigravity's shell commands run without the Golem jail: the Golem agent's PreToolUse hook isn't registered"
	case !env.ShimReady(shim):
		c.Detail = "Antigravity's hook would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, "pre-tool hook"
		c.Detail = "Antigravity's shell commands run in the Golem jail through its PreToolUse hook"
	}
	return c, true
}
