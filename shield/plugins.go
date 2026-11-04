package shield

import (
	"os"
	"path/filepath"
	"strings"
)

// Hermes and OpenClaw reach the jail through the Golem plugin each loads,
// whose pre-tool hook rewrites a shell call (docs/design-local-shield.md,
// Other clients). The plugin is the Golem agent's to install, so coverage
// reads the installed plugin itself: one from before the rewrite is loaded the
// same way but doesn't jail anything.

type pluginAgent struct {
	client, label string
	installed     func(env CoverageEnv) bool
	plugin        func(env CoverageEnv) string
	rewrites      string
	shim          string
	windows       string
	update        string
}

var pluginAgents = []pluginAgent{
	{
		client: "hermes", label: "Hermes",
		installed: func(env CoverageEnv) bool { return exists(filepath.Join(env.Home, ".hermes")) },
		plugin: func(env CoverageEnv) string {
			return filepath.Join(env.Home, ".hermes", "plugins", "golem", "__init__.py")
		},
		rewrites: "def on_shield_rewrite(",
		shim:     "bash",
		windows:  "Hermes runs Git Bash on Windows, which the Golem jail doesn't cover through its plugin yet",
		update:   "golem update hermes-plugin",
	},
	{
		client: "openclaw", label: "OpenClaw",
		installed: func(env CoverageEnv) bool {
			dir := openclawDir(env)
			return exists(filepath.Join(dir, "credentials")) || exists(filepath.Join(dir, "agents"))
		},
		plugin: func(env CoverageEnv) string {
			return filepath.Join(openclawDir(env), "extensions", "golem", "index.js")
		},
		rewrites: "export function shieldRewrite(",
		windows:  "OpenClaw runs PowerShell on Windows, which the Golem jail doesn't cover yet",
		update:   "golem setup-client",
	},
}

func openclawDir(env CoverageEnv) string {
	if env.OpenClawDir != "" {
		return env.OpenClawDir
	}
	return filepath.Join(env.Home, ".openclaw")
}

func pluginCoverage(a pluginAgent) func(CoverageEnv) (AgentCoverage, bool) {
	return func(env CoverageEnv) (AgentCoverage, bool) {
		if !a.installed(env) {
			return AgentCoverage{}, false
		}
		path := a.plugin(env)
		c := AgentCoverage{Client: a.client, Label: a.label, Coverage: NotJailed, Location: tilde(env.Home, path)}
		if env.GOOS == "windows" {
			c.Detail = a.windows
			return c, true
		}
		shell := a.shim
		if shell == "" {
			shell = "bash"
			if strings.Contains(filepath.Base(env.LoginShell), "zsh") {
				shell = "zsh"
			}
		}
		shim := filepath.Join(HookShimDir(env.Home), shell)
		src, err := os.ReadFile(path)
		switch {
		case err != nil:
			c.Detail = a.label + "'s shell commands run without the Golem jail: the Golem plugin isn't installed"
		case !strings.Contains(string(src), a.rewrites):
			c.Detail = a.label + "'s Golem plugin predates the jail: run `" + a.update + "` to update it"
		case !env.ShimReady(shim):
			c.Detail = a.label + "'s plugin would run its shell commands in the Golem jail, but " + tilde(env.Home, shim) + " is not installed"
		default:
			c.Coverage, c.Via = Jailed, "plugin"
			c.Detail = a.label + "'s shell commands run in the Golem jail through the Golem plugin"
		}
		return c, true
	}
}
