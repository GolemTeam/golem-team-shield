package shield

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// ClaudeShell points Claude Code's Bash tool at the shim, through the env block
// of its user settings (~/.claude/settings.json). The Golem agent and
// `golem-exec install` both wire it with this, so they agree on what they
// leave alone: a shell the user set to something else stays, because
// overriding a person's shell choice is worse than an unshielded shell they
// chose.
type ClaudeShell struct {
	// Windows: Claude Code runs Git Bash there and takes it from
	// CLAUDE_CODE_GIT_BASH_PATH when the file is named bash.exe; its
	// PowerShell tool is turned off, since those commands never reach the shim.
	Windows bool
	// Shim is the path to set when Claude Code has no shell set.
	Shim string
	// Ours reports whether a set path is a shim, which may be kept or removed.
	Ours func(path string) bool
	// Ready reports whether a path can run. A shim that can't is never set,
	// since Claude Code would then have no working shell.
	Ready func(path string) bool
}

const claudePowerShellVar = "CLAUDE_CODE_USE_POWERSHELL_TOOL"

// Var is the setting Claude Code reads its shell from.
func (c ClaudeShell) Var() string {
	if c.Windows {
		return "CLAUDE_CODE_GIT_BASH_PATH"
	}
	return "CLAUDE_CODE_SHELL"
}

// Wire sets the shim as Claude Code's shell in settings, and returns what it
// changed.
func (c ClaudeShell) Wire(settings *jsonobject.Object) ([]string, error) {
	env, err := claudeEnv(settings)
	if err != nil {
		return nil, err
	}
	current := envString(env, c.Var())
	if current != "" && !c.Ours(current) {
		return nil, nil
	}
	want := c.Shim
	if current != "" {
		want = current
	}
	if !c.Ready(want) {
		return nil, nil
	}
	var changes []string
	if current != want {
		blob, _ := json.Marshal(want)
		env.Set(c.Var(), blob)
		changes = append(changes, "Bash runs in the Golem shield ("+filepath.Base(want)+")")
	}
	if c.Windows && envString(env, claudePowerShellVar) == "" {
		env.Set(claudePowerShellVar, json.RawMessage(`"0"`))
		changes = append(changes, "the PowerShell tool is off, so every command goes through the shield")
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return changes, storeClaudeEnv(settings, env)
}

// Unwire removes the shim Wire set, and returns what it changed. A shell that
// is not a shim is left alone.
func (c ClaudeShell) Unwire(settings *jsonobject.Object) ([]string, error) {
	env, err := claudeEnv(settings)
	if err != nil {
		return nil, err
	}
	current := envString(env, c.Var())
	if current == "" || !c.Ours(current) {
		return nil, nil
	}
	env.Remove(c.Var())
	if c.Windows && envString(env, claudePowerShellVar) == "0" {
		env.Remove(claudePowerShellVar)
	}
	return []string{"removed the Golem shield shell"}, storeClaudeEnv(settings, env)
}

func claudeEnv(settings *jsonobject.Object) (*jsonobject.Object, error) {
	raw, ok := settings.Get("env")
	if !ok {
		return jsonobject.New(), nil
	}
	env, err := jsonobject.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("env is not an object: %w", err)
	}
	return env, nil
}

func storeClaudeEnv(settings, env *jsonobject.Object) error {
	if env.Empty() {
		settings.Remove("env")
		return nil
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	settings.Set("env", raw)
	return nil
}

func envString(env *jsonobject.Object, name string) string {
	var v string
	if raw, ok := env.Get(name); ok {
		_ = json.Unmarshal(raw, &v)
	}
	return v
}
