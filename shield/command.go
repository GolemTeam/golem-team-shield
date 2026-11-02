package shield

// SandboxExec is SIP-protected, so a jailed command can't replace it.
const SandboxExec = "/usr/bin/sandbox-exec"

// SeatbeltArgv is argv for running argv under profile. The command's own
// arguments pass through as separate elements, never re-quoted into a string.
func SeatbeltArgv(profile string, argv []string) []string {
	return append([]string{SandboxExec, "-p", profile}, argv...)
}
