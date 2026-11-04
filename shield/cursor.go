package shield

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// Cursor's agent (the IDE's and cursor-agent) runs $SHELL or the terminal's
// default profile, so the jail reaches it through preToolUse: the hook's
// updated_input.command replaces a Shell call's command, and a hook entry
// marked failClosed stops the call when the hook crashes or times out
// (docs/design-local-shield.md, Other clients). The Golem agent's hook is
// cursor-hook.sh, which does the same rewrite in Python.

// CursorRewrite is Cursor's preToolUse answer that runs a Shell call's command
// through shim, or nil for any other call. A command Wrap refuses is denied.
// It carries only the keys preToolUse's schema has, since Cursor blocks a call
// whose answer doesn't match it.
func CursorRewrite(shim string, in map[string]any) map[string]any {
	if name, _ := in["tool_name"].(string); name != "Shell" && name != "shell" {
		return nil
	}
	input, _ := in["tool_input"].(map[string]any)
	command, _ := input["command"].(string)
	wrapped, err := Wrap(shim, command)
	if err != nil {
		reason := "Golem can't run this command in its shell jail, so it was not run"
		return map[string]any{"permission": "deny", "user_message": reason, "agent_message": reason}
	}
	return map[string]any{"permission": "allow", "updated_input": map[string]any{"command": wrapped}}
}

// cursorScriptRewrites is what marks a cursor-hook.sh that rewrites Shell
// calls; one from before it is registered the same way but doesn't.
const cursorScriptRewrites = "def shield_rewrite("

func isGolemExecHook(command, client string) bool {
	f := strings.Fields(command)
	return len(f) == 3 && strings.TrimSuffix(filepath.Base(f[0]), ".exe") == "golem-exec" && f[1] == "hook" && f[2] == client
}

// CursorHook is golem-exec's own preToolUse entry in ~/.cursor/hooks.json.
type CursorHook struct {
	// Command runs golem-exec as the hook: "<golem-exec> hook cursor".
	Command string
}

func (h CursorHook) Wire(doc *jsonobject.Object) ([]string, error)   { return h.edit(doc, false) }
func (h CursorHook) Unwire(doc *jsonobject.Object) ([]string, error) { return h.edit(doc, true) }

func (h CursorHook) edit(doc *jsonobject.Object, remove bool) ([]string, error) {
	hooks := jsonobject.New()
	if raw, ok := doc.Get("hooks"); ok {
		var err error
		if hooks, err = jsonobject.Parse(raw); err != nil {
			return nil, fmt.Errorf("hooks is not an object: %w", err)
		}
	}
	var entries []json.RawMessage
	if raw, ok := hooks.Get("preToolUse"); ok {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("hooks.preToolUse is not a list: %w", err)
		}
	}
	found := -1
	for i, e := range entries {
		var entry struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(e, &entry)
		if isGolemExecHook(entry.Command, "cursor") {
			found = i
		}
	}
	switch {
	case remove && found < 0, !remove && found >= 0:
		return nil, nil
	case remove:
		entries = append(entries[:found], entries[found+1:]...)
	default:
		e, _ := json.Marshal(map[string]any{"command": h.Command, "matcher": "Shell", "timeout": codexHookTimeout, "failClosed": true})
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		hooks.Remove("preToolUse")
	} else {
		raw, _ := json.Marshal(entries)
		hooks.Set("preToolUse", raw)
	}
	if hooks.Empty() {
		doc.Remove("hooks")
	} else {
		raw, _ := json.Marshal(hooks)
		doc.Set("hooks", raw)
		if _, ok := doc.Get("version"); !ok {
			doc.Set("version", json.RawMessage("1"))
		}
	}
	if remove {
		return []string{"removed the hook that runs its shell commands in the Golem shield"}, nil
	}
	return []string{"its shell commands run in the Golem shield"}, nil
}

// CursorInstalled is ~/.cursor, which the IDE and cursor-agent both keep.
func CursorInstalled(home string) bool { return exists(filepath.Join(home, ".cursor")) }

func cursorCoverage(env CoverageEnv) (AgentCoverage, bool) {
	if !CursorInstalled(env.Home) {
		return AgentCoverage{}, false
	}
	path := filepath.Join(env.Home, ".cursor", "hooks.json")
	c := AgentCoverage{Client: "cursor", Label: "Cursor", Coverage: NotJailed, Location: tilde(env.Home, path)}
	if env.GOOS == "windows" {
		c.Detail = "Cursor's shell commands on Windows aren't covered by the Golem jail yet"
		return c, true
	}
	var hooked, stale bool
	if doc := readJSON(path); doc != nil {
		var hooks struct {
			PreToolUse []struct {
				Command string `json:"command"`
				Matcher string `json:"matcher"`
			} `json:"preToolUse"`
		}
		if raw, ok := doc.Get("hooks"); ok {
			_ = json.Unmarshal(raw, &hooks)
		}
		for _, e := range hooks.PreToolUse {
			if e.Matcher != "" && e.Matcher != "Shell" && e.Matcher != ".*" && e.Matcher != "*" {
				continue
			}
			switch {
			case isGolemExecHook(e.Command, "cursor"):
				hooked = true
			case filepath.Base(e.Command) == "cursor-hook.sh":
				script, err := os.ReadFile(e.Command)
				if err == nil && strings.Contains(string(script), cursorScriptRewrites) {
					hooked = true
				} else if err == nil {
					stale = true
				}
			}
		}
	}
	name := "bash"
	if strings.Contains(filepath.Base(env.LoginShell), "zsh") {
		name = "zsh"
	}
	shim := filepath.Join(HookShimDir(env.Home), name)
	switch {
	case !hooked && stale:
		c.Detail = "Cursor's Golem hook predates the jail: run `golem setup-client` to update it"
	case !hooked:
		c.Detail = "Cursor's shell commands run without the Golem jail: no preToolUse hook rewrites them"
	case !env.ShimReady(shim):
		c.Detail = "Cursor's hook would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, "pre-tool hook"
		c.Detail = "Cursor's shell commands run in the Golem jail through its preToolUse hook"
	}
	return c, true
}
