package shield

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// Devin (Devin Desktop, formerly Windsurf, and the Devin CLI) takes Claude
// Code's hook payloads and answers under its own tool names: its shell tool is
// exec, and a PreToolUse answer's hookSpecificOutput.updatedInput is merged
// into the call's input (its hook docs; docs/design-local-shield.md, Other
// clients). Its permission rules are word prefixes, Exec(git), and its docs
// don't say whether they run before or after the hook, so its approval may
// see only the jail's wrapper: it is rewritten only with jail_past_approval.
// The answer carries no decision, so Devin still asks as it would.

const devinShellTool = "exec"

// DevinRewrite is Devin's PreToolUse answer that runs an exec call's command
// through shim, or nil for any other call. A command the wrap refuses is
// blocked.
func DevinRewrite(shim string, in map[string]any) map[string]any {
	if name, _ := in["tool_name"].(string); name != devinShellTool {
		return nil
	}
	input, _ := in["tool_input"].(map[string]any)
	command, _ := input["command"].(string)
	wrapped, err := WrapCommand(shim, command)
	if err != nil {
		return map[string]any{"decision": "block", "reason": "Golem can't run this command in its shell jail, so it was not run"}
	}
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse",
		"updatedInput":  map[string]any{"command": wrapped},
	}}
}

// NoteDevinSession leaves the call's session for the shim: Devin's commands
// carry none that is known.
func NoteDevinSession(home string, in map[string]any) {
	if name, _ := in["tool_name"].(string); name != devinShellTool {
		return
	}
	session, _ := in["session_id"].(string)
	cwd, _ := in["cwd"].(string)
	if input, _ := in["tool_input"].(map[string]any); input != nil {
		if dir, _ := input["cwd"].(string); filepath.IsAbs(dir) {
			cwd = dir
		}
	}
	_ = NoteHookSession(home, "devin", cwd, session)
}

// DevinConfig is the file Devin reads its user hooks from. It is
// ~/.config/devin whatever XDG_CONFIG_HOME says, as the Golem agent runs
// without a shell's environment and must name the same file.
func DevinConfig(home string) string {
	return filepath.Join(home, ".config", "devin", "config.json")
}

// IsDevinJailHook reports whether a hook command rewrites Devin's commands
// into the jail: the Golem agent's PreToolUse hook, or golem-exec's.
func IsDevinJailHook(command string) bool {
	return strings.Contains(command, " devin-hook PreToolUse") || isGolemExecHook(command, "devin")
}

// DevinHook is golem-exec's own PreToolUse entry in DevinConfig.
type DevinHook struct {
	// Command runs golem-exec as the hook: "<golem-exec> hook devin".
	Command string
}

func (h DevinHook) Wire(doc *jsonobject.Object) ([]string, error)   { return h.edit(doc, false) }
func (h DevinHook) Unwire(doc *jsonobject.Object) ([]string, error) { return h.edit(doc, true) }

func (h DevinHook) edit(doc *jsonobject.Object, remove bool) ([]string, error) {
	ours := func(c string) bool { return strings.HasSuffix(c, " hook devin") && IsDevinJailHook(c) }
	group := map[string]any{"matcher": devinShellTool, "hooks": []map[string]any{{
		"type": "command", "command": h.Command, "timeout": codexHookTimeout,
	}}}
	changed, err := editHookGroup(doc, "PreToolUse", ours, group, remove)
	switch {
	case err != nil || !changed:
		return nil, err
	case remove:
		return []string{"removed the hook that runs its shell commands in the Golem shield"}, nil
	}
	return []string{"its shell commands run in the Golem shield, past its own approval"}, nil
}

// DevinInstalled looks for Devin Desktop's and the Devin CLI's own files, or
// the hooks file the Golem agent writes only where it found Devin.
func DevinInstalled(home string) bool {
	return exists(filepath.Join(home, ".codeium", "windsurf")) || exists(filepath.Join(home, ".local", "bin", "devin")) ||
		exists(filepath.Join(home, "Applications", "Devin.app")) || exists(DevinConfig(home))
}

func devinCoverage(env CoverageEnv) (AgentCoverage, bool) {
	if !DevinInstalled(env.Home) {
		return AgentCoverage{}, false
	}
	path := DevinConfig(env.Home)
	c := AgentCoverage{Client: "devin", Label: "Devin", Coverage: NotJailed, Location: tilde(env.Home, path)}
	if !JailsPastApproval(env.Home) {
		c.Detail = "Golem doesn't rewrite Devin's shell commands: its own approval rules would then see only the jail" + pastApprovalHint
		c.PastApproval = true
		return c, true
	}
	hooked := false
	if doc := readJSON(path); doc != nil {
		var hooks struct {
			PreToolUse []json.RawMessage `json:"PreToolUse"`
		}
		if raw, ok := doc.Get("hooks"); ok {
			_ = json.Unmarshal(raw, &hooks)
		}
		for _, g := range hooks.PreToolUse {
			var m struct {
				Matcher string `json:"matcher"`
			}
			_ = json.Unmarshal(g, &m)
			if m.Matcher != "" && m.Matcher != ".*" && m.Matcher != "*" && m.Matcher != devinShellTool {
				continue
			}
			for _, cmd := range codexGroupCommands(g) {
				hooked = hooked || IsDevinJailHook(cmd)
			}
		}
	}
	shim := HookShim(env.Home, env.LoginShell)
	if env.GOOS == "windows" {
		shim = WindowsHookShim(env.Home)
	}
	switch {
	case !hooked:
		c.Detail = "Devin's shell commands run without the Golem jail: no PreToolUse hook rewrites them"
	case !env.ShimReady(shim):
		c.Detail = "Devin's hook would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, "pre-tool hook"
		c.Detail = "Devin's shell commands run in the Golem jail through its PreToolUse hook, past its own approval, which would see only the jail"
	}
	return c, true
}
