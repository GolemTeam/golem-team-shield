package main

import (
	"os/exec"
	"time"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// sandboxApplyFailed is sandbox-exec's exit when it couldn't jail, before it
// ran anything; nested Seatbelt is the usual cause.
const sandboxApplyFailed = 71

func canJail() bool {
	return exec.Command(shield.SandboxExec, "-p", "(version 1)(allow default)", "/usr/bin/true").Run() == nil
}

func (s *shim) jailed(rec *shield.RunRecord, p shield.Policy, tmp string, argv, env []string) bool {
	start := s.now()
	if s.getenv("SANDBOX_RUNTIME") == "1" && !s.canJail() {
		hostJail(rec, p)
		rec.ExitCode = s.child(argv, env)
		return true
	}
	c := s.context(tmp, rec.RunTag)
	profile, err := shield.CompileSeatbelt(p, c)
	if err != nil {
		profile, err = shield.CompileSeatbelt(p, withoutWorkspace(c))
	}
	if err != nil {
		return false
	}
	rec.Jail = shield.JailSeatbelt
	rec.PolicyHash = shield.ProfileHash(profile)
	if p.ConfinedWrites() {
		rec.Writes = string(shield.WritesWorkspace)
	}
	if p.Proxied() {
		rec.Net = shield.NetSeatbelt
	}
	rec.ExitCode = s.child(shield.SeatbeltArgv(profile, argv), env)
	// sandbox-exec exits 71 before running anything when it can't jail,
	// which is what an agent's own sandbox around this shim looks like.
	if rec.ExitCode == sandboxApplyFailed && s.now().Sub(start) < time.Second && !s.canJail() {
		rec.PolicyHash = ""
		hostJail(rec, p)
		rec.ExitCode = s.child(argv, env)
	}
	return true
}

// hostJail records a run the agent's own sandbox held, where the shield's
// profile can't nest: the proxy variables are set, and nothing of ours
// enforces them or the write roots.
func hostJail(rec *shield.RunRecord, p shield.Policy) {
	rec.Jail, rec.Writes, rec.Net = shield.JailHost, "", ""
	if p.Proxied() {
		rec.Net = shield.NetAdvisory
	}
}

func runJailStage([]string, bool) int { return 126 }
