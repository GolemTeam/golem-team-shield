package shield

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// Codex runs every command with the passwd login shell and has no setting for
// it, so the jail reaches it through PreToolUse: the hook answers allow with
// updatedInput.command, which Codex substitutes for the call's cmd before its
// own review (docs/design-local-shield.md, Other clients). Codex accepts
// updatedInput only alongside allow; the allow carries no approval of its own.

// HookShim is the hook shim for an agent whose commands are written for
// loginShell: zsh for a zsh user, bash otherwise.
func HookShim(home, loginShell string) string {
	name := "bash"
	if strings.Contains(filepath.Base(loginShell), "zsh") {
		name = "zsh"
	}
	return filepath.Join(HookShimDir(home), name)
}

// CodexRewrite is Codex's PreToolUse answer that runs the call's command
// through shim, or nil for a call that is not a shell command. A command Wrap
// refuses is denied, never passed through unjailed.
func CodexRewrite(shim string, in map[string]any) map[string]any {
	if name, _ := in["tool_name"].(string); name != "Bash" {
		return nil
	}
	input, _ := in["tool_input"].(map[string]any)
	command, _ := input["command"].(string)
	wrapped, err := Wrap(shim, command)
	if err != nil {
		return map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": "Golem can't run this command in its shell jail, so it was not run",
		}}
	}
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":      "PreToolUse",
		"permissionDecision": "allow",
		"updatedInput":       map[string]any{"command": wrapped},
	}}
}

// IsCodexJailHook reports whether a hook command is one that rewrites Codex's
// commands into the jail: the Golem agent's PreToolUse hook, or golem-exec's.
func IsCodexJailHook(command string) bool {
	f := strings.Fields(command)
	switch {
	case len(f) >= 3 && f[1] == "codex-hook" && f[2] == "PreToolUse":
		return true
	case isGolemExecHook(command, "codex"):
		return true
	}
	return false
}

// CodexHook is golem-exec's own PreToolUse entry in a Codex hooks.json, for a
// machine with no Golem agent, whose hooks would otherwise do the rewrite.
type CodexHook struct {
	// Command runs golem-exec as the hook: "<golem-exec> hook codex".
	Command string
}

const codexHookTimeout = 10

// Wire adds the hook beside the person's own, and returns what it changed.
func (h CodexHook) Wire(doc *jsonobject.Object) ([]string, error) {
	return h.edit(doc, false)
}

// Unwire removes only golem-exec's hook.
func (h CodexHook) Unwire(doc *jsonobject.Object) ([]string, error) {
	return h.edit(doc, true)
}

func (h CodexHook) edit(doc *jsonobject.Object, remove bool) ([]string, error) {
	ours := func(c string) bool { return strings.HasSuffix(c, " hook codex") && IsCodexJailHook(c) }
	group := map[string]any{"hooks": []map[string]any{{"type": "command", "command": h.Command, "timeout": codexHookTimeout}}}
	changed, err := editHookGroup(doc, "PreToolUse", ours, group, remove)
	switch {
	case err != nil || !changed:
		return nil, err
	case remove:
		return []string{"removed the hook that runs its shell commands in the Golem shield"}, nil
	}
	return []string{"its shell commands run in the Golem shield, once you approve the new hook in Codex"}, nil
}

// editHookGroup adds group to doc's hooks.<event> list, or with remove takes
// out the group holding a hook command ours matches, leaving every other
// group as it was. Codex and Gemini CLI share this layout.
func editHookGroup(doc *jsonobject.Object, event string, ours func(command string) bool, group map[string]any, remove bool) (bool, error) {
	hooks := jsonobject.New()
	if raw, ok := doc.Get("hooks"); ok {
		var err error
		if hooks, err = jsonobject.Parse(raw); err != nil {
			return false, fmt.Errorf("hooks is not an object: %w", err)
		}
	}
	var groups []json.RawMessage
	if raw, ok := hooks.Get(event); ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return false, fmt.Errorf("hooks.%s is not a list: %w", event, err)
		}
	}
	found := -1
	for i, g := range groups {
		for _, c := range codexGroupCommands(g) {
			if ours(c) {
				found = i
			}
		}
	}
	switch {
	case remove && found < 0, !remove && found >= 0:
		return false, nil
	case remove:
		groups = append(groups[:found], groups[found+1:]...)
	default:
		g, err := json.Marshal(group)
		if err != nil {
			return false, err
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		hooks.Remove(event)
	} else {
		raw, _ := json.Marshal(groups)
		hooks.Set(event, raw)
	}
	if hooks.Empty() {
		doc.Remove("hooks")
	} else {
		raw, _ := json.Marshal(hooks)
		doc.Set("hooks", raw)
	}
	return true, nil
}

func codexGroupCommands(group json.RawMessage) []string {
	var g struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	_ = json.Unmarshal(group, &g)
	var out []string
	for _, h := range g.Hooks {
		out = append(out, h.Command)
	}
	return out
}

// CodexHomes are the directories a Codex here may use: codexHome (Codex's
// $CODEX_HOME), then ~/.codex.
func CodexHomes(home, codexHome string) []string {
	dirs := []string{filepath.Join(home, ".codex")}
	if d := codexHome; d != "" && filepath.Clean(d) != dirs[0] {
		dirs = append([]string{filepath.Clean(d)}, dirs...)
	}
	return dirs
}

// CodexInstalled reads Codex's own files, not hooks.json, which an installer
// may have written.
func CodexInstalled(dir string) bool {
	return exists(filepath.Join(dir, "config.toml")) || exists(filepath.Join(dir, "auth.json")) || exists(filepath.Join(dir, "sessions"))
}

func codexCoverage(env CoverageEnv) (AgentCoverage, bool) {
	homes := env.CodexHomes
	if homes == nil {
		homes = CodexHomes(env.Home, os.Getenv("CODEX_HOME"))
	}
	var dir string
	for _, d := range homes {
		if CodexInstalled(d) {
			dir = d
			break
		}
	}
	if dir == "" {
		return AgentCoverage{}, false
	}
	hooksPath := filepath.Join(dir, "hooks.json")
	c := AgentCoverage{Client: "codex", Label: "Codex", Coverage: NotJailed, Location: tilde(env.Home, hooksPath)}
	if env.GOOS == "windows" {
		c.Detail = "On Windows Golem doesn't rewrite Codex's PowerShell commands: Codex's own dangerous-command checks would no longer see them"
		return c, true
	}
	group := -1
	if doc := readJSON(hooksPath); doc != nil {
		var hooks struct {
			PreToolUse []json.RawMessage `json:"PreToolUse"`
		}
		if raw, ok := doc.Get("hooks"); ok {
			_ = json.Unmarshal(raw, &hooks)
		}
		for i, g := range hooks.PreToolUse {
			for _, cmd := range codexGroupCommands(g) {
				if IsCodexJailHook(cmd) && group < 0 {
					group = i
				}
			}
		}
	}
	config, _ := os.ReadFile(filepath.Join(dir, "config.toml"))
	shim := HookShim(env.Home, env.LoginShell)
	switch {
	case group < 0:
		c.Detail = "Codex's shell commands run without the Golem jail: no PreToolUse hook rewrites them"
	case !strings.Contains(string(config), fmt.Sprintf("[hooks.state.%q]", fmt.Sprintf("%s:pre_tool_use:%d:0", hooksPath, group))):
		c.Detail = "Codex skips the hook that jails its shell commands until you approve it in Codex"
	case !env.ShimReady(shim):
		c.Detail = "Codex's hook would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, "pre-tool hook"
		c.Detail = "Codex's shell commands run in the Golem jail through its PreToolUse hook"
	}
	return c, true
}
