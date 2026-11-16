package agentposture

import (
	"path/filepath"

	"github.com/GolemTeam/golem-team-shield/shield/jailshell"
)

// Grok Bot's desktop app keeps the member's local settings in ~/.grokbot
// (docs/design-grok-bot.md). The files are undocumented, so a key that is
// missing or holds anything unexpected is no finding. The daemon's sealed
// credential, connection and supervisor files sit beside them and are never
// opened.

const grokBotClient = "grok-bot"

type Processes interface {
	Alive(pid int) bool
	Environ(pid int) ([]string, bool)
}

// GrokBotDaemonShell is the SHELL of the Grok Bot local-exec daemon running
// for the user at home. ok is false when none runs or its environment can't be
// read.
func GrokBotDaemonShell(home string, p Processes) (shell string, ok bool) {
	if p == nil {
		return "", false
	}
	d, ok := jailshell.ReadGrokBotDaemon(home, func(pid int) ([]string, bool) {
		if !p.Alive(pid) {
			return nil, false
		}
		return p.Environ(pid)
	})
	return d.Shell, ok
}

var plainShells = map[string]bool{"zsh": true, "bash": true, "sh": true, "dash": true, "ksh": true, "fish": true, "tcsh": true, "csh": true}

func (s *scan) grokBot() {
	dir := filepath.Join(s.env.Home, ".grokbot")
	path := filepath.Join(dir, "settings.json")
	m := s.readSettings(path)
	perm := lookupString(m, "localToolPermission")
	switch perm {
	case "always":
		s.add(grokBotClient, "local_always", Dangerous, "user", path, "localToolPermission", "always",
			"Grok Bot runs commands on this machine without asking")
	case "ask":
		s.add(grokBotClient, "local_ask", Info, "user", path, "localToolPermission", "ask",
			"Grok Bot can run commands on this machine, each one approved first")
	}
	if v, _ := lookupBool(m, "egressTunnelEnabled"); v {
		s.add(grokBotClient, "egress_through_host", Suspicious, "user", path, "egressTunnelEnabled", "true",
			"Grok Bot's cloud computer browses from this machine's network")
	}
	enabled, _ := lookupBool(m, "messagesEnabled")
	send, _ := lookupBool(m, "messagesSendEnabled")
	if enabled && send {
		s.add(grokBotClient, "messages_send", Suspicious, "user", path, "messagesSendEnabled", "true",
			"Grok Bot can send iMessages from this Mac")
	}
	if v, _ := lookupBool(m, "webauthnProxyEnabled"); v {
		s.add(grokBotClient, "security_key_proxy", Info, "user", path, "webauthnProxyEnabled", "true",
			"Grok Bot's browser can use a security key plugged into this machine, approved each time")
	}
	gate := filepath.Join(dir, "local-computer-use-gate.json")
	if on, _ := lookupBool(s.readSettings(gate), "isOn"); on {
		s.add(grokBotClient, "computer_use", Suspicious, "user", gate, "isOn", "true",
			"Grok Bot can control this machine's screen, keyboard and mouse")
	}
	if perm != "ask" && perm != "always" {
		return
	}
	shell, ok := GrokBotDaemonShell(s.env.Home, s.env.Processes)
	if !ok || jailshell.IsShim(s.env.Home, s.env.GOOS, shell) {
		return
	}
	value := filepath.Base(shell)
	switch {
	case shell == "":
		value = "unset"
	case !plainShells[value]:
		value = "other"
	}
	s.add(grokBotClient, "local_unwrapped", Dangerous, "user", filepath.Join(dir, "local-exec-daemon.json"), "SHELL", value,
		"Grok Bot's commands on this machine run outside the Golem jail, unrecorded")
}
