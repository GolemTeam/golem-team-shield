package shield

import (
	"os"
	"path/filepath"
	"strings"
)

// Some agents would approve the jail's rewrite rather than the command inside
// it: Codex, Gemini CLI and Copilot CLI on Windows, where their approval reads
// PowerShell, and Devin. Rewriting them is a trade a workspace opts into
// ("Also jail agents that would approve the jail", jail_past_approval), as one
// "always allow" in them could then approve every later command
// (docs/design-local-shield.md, Past their own approval).

// PastApprovalPath is where the Golem agent leaves that switch, "on" or "off",
// for its hooks, which run as processes of their own. It is under ~/.golem,
// which a jailed command can't write.
func PastApprovalPath(home string) string {
	return filepath.Join(home, ".golem", "shield", "past-approval")
}

// JailsPastApproval reports whether the hooks jail those agents too: the
// Golem agent's switch where it left one, and shield.json's otherwise.
func JailsPastApproval(home string) bool {
	if b, err := os.ReadFile(PastApprovalPath(home)); err == nil {
		return strings.TrimSpace(string(b)) == "on"
	}
	c, found, err := LoadConfig(ConfigPath(home))
	return found && err == nil && c.JailPastApproval
}

// SetPastApproval records the Golem agent's switch for its hooks.
func SetPastApproval(home string, on bool) error {
	v := "off\n"
	if on {
		v = "on\n"
	}
	path := PastApprovalPath(home)
	if b, err := os.ReadFile(path); err == nil && string(b) == v {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(v), 0o600)
}

// WindowsHookShim is the hook shim a rewrite names on Windows. As pwsh.exe it
// runs PowerShell 7, or the 5.1 every Windows has where 7 isn't installed.
func WindowsHookShim(home string) string {
	return filepath.Join(HookShimDir(home), WindowsHookShells[0])
}

// WrapCommand wraps command for shim's shell: PowerShell for a shim named as
// one, and sh otherwise.
func WrapCommand(shim, command string) (string, error) {
	switch strings.ToLower(filepath.Base(strings.ReplaceAll(shim, `\`, "/"))) {
	case "pwsh.exe", "powershell.exe":
		return WrapPowerShell(shim, command)
	}
	return Wrap(shim, command)
}

// PowerShellHook is a hook command for a client that runs its hooks in
// PowerShell: the call operator, as a quoted path alone is only a string.
func PowerShellHook(exe string, args ...string) string {
	return strings.Join(append([]string{"&", QuotePowerShell(exe)}, args...), " ")
}

// hookArgs splits a hook command into the program and its arguments, reading
// PowerShellHook's form as well as a plain one.
func hookArgs(command string) []string {
	rest, ok := strings.CutPrefix(command, "& '")
	if !ok {
		return strings.Fields(command)
	}
	var exe strings.Builder
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\'' {
			if i+1 < len(rest) && rest[i+1] == '\'' {
				exe.WriteByte('\'')
				i++
				continue
			}
			return append([]string{exe.String()}, strings.Fields(rest[i+1:])...)
		}
		exe.WriteByte(rest[i])
	}
	return nil
}

// hookShimFor is the shim a hook client's rewrite names on env's machine, and
// what its coverage line adds: posix off Windows, the PowerShell shim there
// once the switch is on, and "" where the client isn't rewritten.
func hookShimFor(env CoverageEnv, posix string) (shim, detail string) {
	if env.GOOS != "windows" {
		return posix, ""
	}
	if !JailsPastApproval(env.Home) {
		return "", ""
	}
	return WindowsHookShim(env.Home), ", past its own approval, which would see only the jail"
}

const pastApprovalHint = ". Jailing agents past their own approval would jail them anyway"
