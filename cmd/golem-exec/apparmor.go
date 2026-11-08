package main

import "github.com/GolemTeam/golem-team-shield/shield"

// roleAllowed: the profiled copy may make namespaces, so it runs only as the
// launcher and the setup in the namespace, never as a shell, the CLI or the
// stage, which could hand what it holds to a program of the caller's choosing.
func roleAllowed(exe, invoked string) bool {
	return exe != shield.AppArmorStage || invoked == shield.AppArmorLauncherRole || invoked == jailSetup
}
