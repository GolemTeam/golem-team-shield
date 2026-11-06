package main

const (
	appArmorStage = "/usr/local/libexec/golem-exec/golem-exec"
	jailLauncher  = "golem-shield-userns"
)

type appArmorState struct {
	Restricted, Installed, Current bool
}

// roleAllowed: the profiled copy may make namespaces, so it runs only as the
// launcher and the jail stage, never as a shell or the CLI, which could hand
// that to a program of the caller's choosing.
func roleAllowed(exe, invoked string) bool {
	return exe != appArmorStage || invoked == jailLauncher || invoked == jailStage
}
