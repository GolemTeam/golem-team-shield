package shield

import (
	"path/filepath"

	"github.com/GolemTeam/golem-team-shield/shield/jailshell"
)

const GrokBotClient = "grok-bot"

type GrokBotDaemon = jailshell.GrokBotDaemon

func GrokBotDaemonFile(home string) string { return jailshell.GrokBotDaemonFile(home) }

func ReadGrokBotDaemon(home string, environ func(pid int) ([]string, bool)) (GrokBotDaemon, bool) {
	return jailshell.ReadGrokBotDaemon(home, environ)
}

func grokBotCoverage(env CoverageEnv) (AgentCoverage, bool) {
	if !exists(filepath.Join(env.Home, ".grokbot")) {
		return AgentCoverage{}, false
	}
	c := AgentCoverage{Client: GrokBotClient, Label: "Grok Bot", Coverage: NotJailed, Location: tilde(env.Home, GrokBotDaemonFile(env.Home))}
	d, up := ReadGrokBotDaemon(env.Home, env.ProcessEnviron)
	shell := d.Shell
	if shell == "" {
		shell = "unset"
	}
	switch {
	case env.ProcessEnviron == nil:
		c.Detail = "this check doesn't read Grok Bot's local-exec daemon, so whether its commands run in the Golem jail is unknown; `golem doctor` reads it"
	case !up:
		c.Detail = "Grok Bot's local-exec daemon isn't running; started from the Dock or Finder it takes the login shell, outside the Golem jail"
	case !IsShim(env.Home, env.GOOS, d.Shell):
		c.Detail = "Grok Bot's commands on this machine run without the Golem jail: its daemon's shell is " + shell
	case !env.ShimReady(d.Shell):
		c.Detail = "Grok Bot's daemon runs on the Golem jail's shell, but " + tilde(env.Home, d.Shell) + " is not installed"
	default:
		c.Coverage, c.Via = Jailed, AttachLaunch
		c.Detail = "Grok Bot's commands on this machine run in the Golem jail (its daemon's shell is " + tilde(env.Home, d.Shell) + ")"
	}
	return c, true
}
