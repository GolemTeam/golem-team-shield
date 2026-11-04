package shield

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// Gemini CLI runs `bash -c` with bash from PATH and has no setting for it, so
// the jail reaches it through BeforeTool: the hook's
// hookSpecificOutput.tool_input is merged into the call's params, and Gemini
// strips a "<path>/bash -c '…'" wrapper before its own rules see the command
// (docs/design-local-shield.md, Other clients). Its commands' env names no
// session, so the hook notes one for the shim.

const geminiShellTool = "run_shell_command"

// GeminiRewrite is Gemini CLI's BeforeTool answer that runs the call's
// command through shim, or nil for a call that is not a shell command. A
// command Wrap refuses is denied.
func GeminiRewrite(shim string, in map[string]any) map[string]any {
	if name, _ := in["tool_name"].(string); name != geminiShellTool {
		return nil
	}
	input, _ := in["tool_input"].(map[string]any)
	command, _ := input["command"].(string)
	wrapped, err := WrapCommand(shim, command)
	if err != nil {
		return map[string]any{"decision": "deny", "reason": "Golem can't run this command in its shell jail, so it was not run"}
	}
	return map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "BeforeTool",
		"tool_input":    map[string]any{"command": wrapped},
	}}
}

// NoteGeminiSession leaves the call's session where the shim will look for it:
// keyed by the directory the command runs in, which is the call's dir_path
// under the project when it names one.
func NoteGeminiSession(home string, in map[string]any) {
	if name, _ := in["tool_name"].(string); name != geminiShellTool {
		return
	}
	session, _ := in["session_id"].(string)
	cwd, _ := in["cwd"].(string)
	if input, _ := in["tool_input"].(map[string]any); input != nil {
		if dir, _ := input["dir_path"].(string); dir != "" && cwd != "" {
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(cwd, dir)
			}
			cwd = dir
		}
	}
	_ = NoteHookSession(home, "gemini-cli", cwd, session)
}

// IsGeminiJailHook reports whether a hook command rewrites Gemini CLI's
// commands into the jail: the Golem agent's BeforeTool hook (guarded by an
// `if [ -x … ]` on POSIX), or golem-exec's.
func IsGeminiJailHook(command string) bool {
	if strings.Contains(command, " gemini-hook BeforeTool") {
		return true
	}
	return isGolemExecHook(command, "gemini-cli")
}

// GeminiHook is golem-exec's own BeforeTool entry in ~/.gemini/settings.json.
type GeminiHook struct {
	// Command runs golem-exec as the hook: "<golem-exec> hook gemini-cli".
	Command string
}

func (h GeminiHook) Wire(doc *jsonobject.Object) ([]string, error)   { return h.edit(doc, false) }
func (h GeminiHook) Unwire(doc *jsonobject.Object) ([]string, error) { return h.edit(doc, true) }

func (h GeminiHook) edit(doc *jsonobject.Object, remove bool) ([]string, error) {
	ours := func(c string) bool { return strings.HasSuffix(c, " hook gemini-cli") && IsGeminiJailHook(c) }
	group := map[string]any{"matcher": geminiShellTool, "hooks": []map[string]any{{
		"type": "command", "name": "golem-shield", "command": h.Command, "timeout": codexHookTimeout * 1000,
	}}}
	changed, err := editHookGroup(doc, "BeforeTool", ours, group, remove)
	switch {
	case err != nil || !changed:
		return nil, err
	case remove:
		return []string{"removed the hook that runs its shell commands in the Golem shield"}, nil
	}
	return []string{"its shell commands run in the Golem shield"}, nil
}

// GeminiInstalled looks only at files Gemini CLI writes: ~/.gemini is shared
// with Antigravity, and settings.json is one an installer may create.
func GeminiInstalled(home string) bool {
	dir := filepath.Join(home, ".gemini")
	return exists(filepath.Join(dir, "installation_id")) || exists(filepath.Join(dir, "oauth_creds.json")) || exists(filepath.Join(dir, "google_accounts.json"))
}

func geminiCoverage(env CoverageEnv) (AgentCoverage, bool) {
	if !GeminiInstalled(env.Home) {
		return AgentCoverage{}, false
	}
	settings := filepath.Join(env.Home, ".gemini", "settings.json")
	c := AgentCoverage{Client: "gemini-cli", Label: "Gemini CLI", Coverage: NotJailed, Location: tilde(env.Home, settings)}
	shim, past := hookShimFor(env, filepath.Join(HookShimDir(env.Home), "bash"))
	if shim == "" {
		c.Detail = "On Windows Golem doesn't rewrite Gemini CLI's PowerShell commands: one \"always allow\" would then approve every command" + pastApprovalHint
		return c, true
	}
	hooked := false
	if doc := readJSON(settings); doc != nil {
		var hooks struct {
			BeforeTool []json.RawMessage `json:"BeforeTool"`
		}
		if raw, ok := doc.Get("hooks"); ok {
			_ = json.Unmarshal(raw, &hooks)
		}
		for _, g := range hooks.BeforeTool {
			var m struct {
				Matcher string `json:"matcher"`
			}
			_ = json.Unmarshal(g, &m)
			if m.Matcher != "" && m.Matcher != ".*" && m.Matcher != "*" && m.Matcher != geminiShellTool {
				continue
			}
			for _, cmd := range codexGroupCommands(g) {
				hooked = hooked || IsGeminiJailHook(cmd)
			}
		}
	}
	switch {
	case !hooked:
		c.Detail = "Gemini CLI's shell commands run without the Golem jail: no BeforeTool hook rewrites them"
	case !env.ShimReady(shim):
		c.Detail = "Gemini CLI's hook would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, "pre-tool hook"
		c.Detail = "Gemini CLI's shell commands run in the Golem jail through its BeforeTool hook" + past
	}
	return c, true
}
