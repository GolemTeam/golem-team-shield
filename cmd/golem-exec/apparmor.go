package main

import "github.com/GolemTeam/golem-team-shield/shield"

const jailLauncher = "golem-shield-userns"

// roleAllowed: the profiled copy may make namespaces, so it runs only as the
// launcher and the jail stage, never as a shell or the CLI, which could hand
// that to a program of the caller's choosing.
func roleAllowed(exe, invoked string) bool {
	return exe != shield.AppArmorStage || invoked == jailLauncher || invoked == jailStage
}
