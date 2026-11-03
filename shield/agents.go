package shield

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Agents other than Claude Code don't let the shell be named, so their
// commands reach the shim through their pre-tool hook, which hands the client
// the command rewritten to run through it (docs/design-local-shield.md, Other
// clients). The Golem agent's hooks and golem-exec's own both rewrite with
// Wrap, so they agree on what a wrapped command is.

// ShimDir is where the shim lives under the shell names an agent is pointed
// at. The jail keeps it unwritable, so no command can replace the shell the
// next one runs in.
func ShimDir(home string) string { return filepath.Join(home, ".golem", "bin") }

// HookShimDir is where the shim answers to a plain shell name (bash, zsh) for
// a hook's rewrite. The name matters: the clients approve the rewritten
// command, not the agent's, and Gemini CLI and Codex look inside "<path>/bash
// -c '…'" for the command their allow and deny rules match, while an env or
// exec prefix would hide it.
func HookShimDir(home string) string { return filepath.Join(ShimDir(home), "hook") }

var safePathRE = regexp.MustCompile(`^/[A-Za-z0-9/._+-]+$`)

// ErrNotWrappable is a command Wrap refuses. The hook then refuses the
// command rather than letting it run outside the jail.
var ErrNotWrappable = errors.New("command can't be run through the shield")

// Wrap returns command rewritten to run through shim, for the client's own
// shell to run with -c:
//
//	/home/x/.golem/bin/hook/bash -c '<command>'
//
// The command is not parsed: it is quoted whole and handed to the real shell
// unchanged. The client's shell runs the shim as a child rather than exec'ing
// it, so whatever the client appends to a command (Cursor saves the shell's
// state, Gemini CLI lists background jobs) still runs, and the shim's exit
// status is the command's. The shim's path is left unquoted, which is what
// the clients' wrapper matching expects, so it has to be a plain path. A
// command already wrapped for this shim comes back as it is.
func Wrap(shim, command string) (string, error) {
	if strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) || !safePathRE.MatchString(shim) {
		return "", ErrNotWrappable
	}
	if Wrapped(shim, command) {
		return command, nil
	}
	return shim + " -c " + Quote(command), nil
}

// Wrapped reports whether command is already a Wrap of shim, so a hook that
// runs twice (the Golem agent's and a leftover golem-exec one) wraps once.
func Wrapped(shim, command string) bool {
	return strings.HasPrefix(command, shim+" -c '") && strings.HasSuffix(command, "'")
}

// Quote is s as one shell word that sh, bash, zsh and fish all read back as
// s. Each single quote and backslash is written outside the quotes, escaped,
// because fish, unlike POSIX shells, takes both as escapes inside them; what
// is left inside the quotes then means the same to every one of them.
func Quote(s string) string {
	return "'" + quoteRepl.Replace(s) + "'"
}

var quoteRepl = strings.NewReplacer(`'`, `'\''`, `\`, `'\\'`)

// HookShells are the names the shim answers to in HookShimDir.
var HookShells = []string{"bash", "zsh"}

// LinkShim points link at target (a name beside it), replacing whatever was
// there unless it already does.
func LinkShim(link, target string) error {
	if dest, err := os.Readlink(link); err == nil && dest == target {
		return nil
	}
	_ = os.Remove(link)
	return os.Symlink(target, link)
}

// LinkHookShims puts HookShells in HookShimDir, each a link to binary in
// binDir (the shim dir) whose basename is a shell's, for the clients that
// recognise a shell by its name.
func LinkHookShims(binDir, binary string) error {
	dir := filepath.Join(binDir, "hook")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, name := range HookShells {
		if err := LinkShim(filepath.Join(dir, name), filepath.Join("..", binary)); err != nil {
			return err
		}
	}
	return nil
}
