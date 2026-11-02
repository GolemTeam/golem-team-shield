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
		rec.Jail = shield.JailHost
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
	rec.ExitCode = s.child(shield.SeatbeltArgv(profile, argv), env)
	// sandbox-exec exits 71 before running anything when it can't jail,
	// which is what an agent's own sandbox around this shim looks like.
	if rec.ExitCode == sandboxApplyFailed && s.now().Sub(start) < time.Second && !s.canJail() {
		rec.Jail, rec.PolicyHash = shield.JailHost, ""
		rec.ExitCode = s.child(argv, env)
	}
	return true
}

func runJailStage([]string) int { return 126 }
