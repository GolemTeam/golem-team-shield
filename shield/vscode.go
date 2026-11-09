package shield

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// VS Code's agent types its commands into a terminal it keeps open, started
// from the profile chat.tools.terminal.terminalProfile.<os> names, so the jail
// reaches it as that terminal's shell: one jail per terminal rather than per
// command, with the machine's policy, as nothing in the terminal names the
// chat session. Its hook can't carry the rewrite: its terminal tool finds
// commands with tree-sitter and doesn't look inside bash -c, so every
// auto-approve rule would stop matching (docs/design-local-shield.md, Other
// clients). The profile leaves its rules intact, but it changes a setting of
// the person's editor and is unverified with VS Code's shell integration, so
// it waits on jail_past_approval too.

var vscodeEditions = []string{"Code", "Code - Insiders"}

// VSCodeSettings are the user settings files of the VS Code editions
// installed here.
func VSCodeSettings(home, goos string) []string {
	var out []string
	for _, ed := range vscodeEditions {
		var dir string
		switch goos {
		case "darwin":
			dir = filepath.Join(home, "Library", "Application Support", ed, "User")
		case "windows":
			dir = filepath.Join(home, "AppData", "Roaming", ed, "User")
		default:
			dir = filepath.Join(home, ".config", ed, "User")
		}
		if exists(dir) {
			out = append(out, filepath.Join(dir, "settings.json"))
		}
	}
	return out
}

// VSCodeProfileKey is the setting that names the agent's terminal profile.
func VSCodeProfileKey(goos string) string {
	switch goos {
	case "darwin":
		return "chat.tools.terminal.terminalProfile.osx"
	case "windows":
		return "chat.tools.terminal.terminalProfile.windows"
	}
	return "chat.tools.terminal.terminalProfile.linux"
}

// VSCodeShim is the shell the profile names: the hook shim for the person's
// shell, or PowerShell's on Windows.
func VSCodeShim(home, goos, loginShell string) string {
	if goos == "windows" {
		return WindowsHookShim(home)
	}
	return HookShim(home, loginShell)
}

// VSCodeProfilePath is the shell the profile in a settings file names, if any.
func VSCodeProfilePath(settings []byte, goos string) (string, bool) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(jsonobject.StripJSONC(settings), &doc) != nil {
		return "", false
	}
	var profile struct {
		Path string `json:"path"`
	}
	if raw, ok := doc[VSCodeProfileKey(goos)]; !ok || json.Unmarshal(raw, &profile) != nil || profile.Path == "" {
		return "", false
	}
	return profile.Path, true
}

// SameShim compares shell paths as goos does: without case on Windows.
func SameShim(goos, a, b string) bool {
	if goos == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func vscodeCoverage(env CoverageEnv) (AgentCoverage, bool) {
	files := VSCodeSettings(env.Home, env.GOOS)
	if len(files) == 0 {
		return AgentCoverage{}, false
	}
	c := AgentCoverage{Client: "vscode", Label: "VS Code", Coverage: NotJailed, Location: tilde(env.Home, files[0])}
	shim := VSCodeShim(env.Home, env.GOOS, env.LoginShell)
	b, _ := os.ReadFile(files[0])
	cur, set := VSCodeProfilePath(b, env.GOOS)
	ours := set && SameShim(env.GOOS, cur, shim)
	switch {
	case ours && env.ShimReady(shim):
		c.Coverage, c.Via = Partial, "terminal profile"
		c.Detail = "VS Code's agent runs its commands in terminals whose shell is the Golem jail: one jail per terminal, with this machine's policy rather than its session's"
	case ours:
		c.Detail = "VS Code's agent's terminal profile names " + tilde(env.Home, shim) + ", which is not installed"
	case set:
		c.Detail = "VS Code's agent's terminal profile is set to " + cur + ", so it was left alone"
	case !JailsPastApproval(env.Home):
		c.Detail = "VS Code's agent runs its commands without the Golem jail: its hook would hide them from its own approval rules" + pastApprovalHint + ", through its terminal profile"
		c.PastApproval = true
	default:
		c.Detail = "VS Code's agent runs its commands without the Golem jail: no terminal profile names the Golem shim"
	}
	return c, true
}
