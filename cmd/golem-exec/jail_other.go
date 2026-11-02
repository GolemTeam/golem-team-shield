//go:build !darwin && !linux && !windows

package main

import "github.com/GolemTeam/golem-team-shield/shield"

func canJail() bool { return false }

func (s *shim) jailed(rec *shield.RunRecord, _ shield.Policy, _ string, argv, env []string) bool {
	rec.Jail = shield.JailNone
	rec.ExitCode = s.child(argv, env)
	return true
}

func runJailStage([]string) int { return 126 }
