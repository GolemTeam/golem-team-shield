package shield

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// Coverage says, per agent installed here, whether its shell commands run in
// the jail. `golem check`, `golem doctor` and `golem-exec status` all read it
// (CoverageOf), so they never disagree about an agent.
type Coverage string

const (
	// Jailed: every command the agent's shell tool runs goes through the shim.
	Jailed Coverage = "jailed"
	// Partial: some go through it, or all of them with a weaker jail (one per
	// terminal, not per command).
	Partial Coverage = "partial"
	// NotJailed: the agent's commands run without the shim.
	NotJailed Coverage = "not_jailed"
)

// AgentCoverage is one agent's line.
type AgentCoverage struct {
	Client   string   `json:"client"`
	Label    string   `json:"label"`
	Coverage Coverage `json:"coverage"`
	// Via is how the shim is attached: "shell setting", "pre-tool hook",
	// "plugin", "terminal profile", or "" when it isn't.
	Via string `json:"via,omitempty"`
	// Location is the file that attaches it, or would.
	Location string `json:"location,omitempty"`
	Detail   string `json:"detail"`
}

// CoverageEnv is what Coverage reads, so tests can point it elsewhere.
type CoverageEnv struct {
	Home string
	GOOS string
	// ShimReady reports whether a shim path can run; an attach that points at
	// a shim that can't is not coverage.
	ShimReady func(path string) bool
	// LoginShell picks the hook shim (zsh or bash) a hook rewrites to.
	LoginShell string
	// CodexHomes overrides CodexHomes(Home).
	CodexHomes []string
	// OpenClawDir is OpenClaw's $OPENCLAW_STATE_DIR; "" means ~/.openclaw.
	OpenClawDir string
}

// IsShim reports whether path is one of the shim's names under home.
func IsShim(home, goos, path string) bool {
	dir := ShimDir(home)
	if goos == "windows" {
		slash := func(p string) string { return strings.ReplaceAll(filepath.Clean(p), `\`, "/") }
		return strings.EqualFold(slash(path), slash(filepath.Join(dir, "bash.exe")))
	}
	return strings.HasPrefix(path, dir+string(filepath.Separator)+"golem-")
}

// ReadyShim is the default ShimReady: a regular file, executable off Windows.
// A shim the check may not even look at is taken as there: the jail denies
// ~/.golem, so that is what a check run by a jailed agent sees.
func ReadyShim(goos string) func(string) bool {
	return func(p string) bool {
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrPermission) {
			return true
		}
		return err == nil && fi.Mode().IsRegular() && (goos == "windows" || fi.Mode()&0o111 != 0)
	}
}

// insideJail reports whether this check runs in the jail, which alone keeps
// a process from reading its own ~/.golem.
func insideJail(home string) bool {
	_, err := os.Stat(ShimDir(home))
	return errors.Is(err, fs.ErrPermission)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// tilde shows a path under home as ~/…, as the posture report does.
func tilde(home, p string) string {
	if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.Join("~", rel)
	}
	return p
}

func readJSON(path string) *jsonobject.Object {
	doc, _, err := jsonobject.ReadFile(path)
	if err != nil {
		return nil
	}
	return doc
}

// CoverageOf reads every agent the jail knows how to attach to, and returns a
// line for each one installed here.
func CoverageOf(env CoverageEnv) []AgentCoverage {
	if env.ShimReady == nil {
		env.ShimReady = ReadyShim(env.GOOS)
	}
	var out []AgentCoverage
	reads := []func(CoverageEnv) (AgentCoverage, bool){claudeCoverage, codexCoverage, geminiCoverage, cursorCoverage, copilotCoverage, antigravityCoverage, devinCoverage, vscodeCoverage}
	for _, a := range pluginAgents {
		reads = append(reads, pluginCoverage(a))
	}
	for _, read := range reads {
		if c, ok := read(env); ok {
			out = append(out, c)
		}
	}
	if insideJail(env.Home) {
		for i := range out {
			if out[i].Coverage == Jailed {
				out[i].Detail += "; this check ran inside the jail, which can't read ~/.golem"
			}
		}
	}
	return out
}

func claudeCoverage(env CoverageEnv) (AgentCoverage, bool) {
	dir := filepath.Join(env.Home, ".claude")
	if !exists(dir) && !exists(filepath.Join(env.Home, ".claude.json")) {
		return AgentCoverage{}, false
	}
	settings := filepath.Join(dir, "settings.json")
	c := AgentCoverage{Client: "claude-code", Label: "Claude Code", Coverage: NotJailed, Location: tilde(env.Home, settings)}
	cs := ClaudeShell{Windows: env.GOOS == "windows"}
	var vars *jsonobject.Object
	if doc := readJSON(settings); doc != nil {
		vars, _ = claudeEnv(doc)
	}
	shell := ""
	if vars != nil {
		shell = envString(vars, cs.Var())
	}
	switch {
	case shell == "":
		c.Detail = "Claude Code's shell commands run without the Golem jail: " + cs.Var() + " is not set"
	case !IsShim(env.Home, env.GOOS, shell):
		c.Detail = "Claude Code's shell commands run without the Golem jail: " + cs.Var() + " is " + shell
	case !env.ShimReady(shell):
		c.Detail = "Claude Code's shell is set to the Golem jail, but " + tilde(env.Home, shell) + " is not installed"
	case cs.Windows && envString(vars, claudePowerShellVar) != "0":
		c.Coverage, c.Via = Partial, "shell setting"
		c.Detail = "Claude Code's Bash commands run in the Golem jail, but its PowerShell tool is on and runs outside it"
	default:
		c.Coverage, c.Via = Jailed, "shell setting"
		c.Detail = "Claude Code's shell commands run in the Golem jail (" + cs.Var() + ")"
	}
	return c, true
}
