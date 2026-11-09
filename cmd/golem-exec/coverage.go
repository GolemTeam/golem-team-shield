package main

import (
	"fmt"
	"os"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// statusAgents says, per agent installed here, whether its shell commands run
// in the jail: the same lines `golem check` and `golem doctor` read.
func (s *setup) statusAgents() {
	cov := shield.CoverageOf(shield.CoverageEnv{Home: s.home, GOOS: s.goos, LoginShell: s.loginShell, CodexHomes: s.codexHomes(), OpenClawDir: os.Getenv("OPENCLAW_STATE_DIR")})
	if len(cov) == 0 {
		fmt.Fprintln(s.stdout, "agents       none here that the jail can attach to")
		return
	}
	required, _ := shield.JailRequired(s.home, s.managedSettings())
	for i, c := range cov {
		label := "agents"
		if i > 0 {
			label = ""
		}
		mark := string(c.Coverage)
		if required && c.Coverage != shield.Jailed {
			mark += ", DANGEROUS: the jail is required here"
		}
		fmt.Fprintf(s.stdout, "%-12s %s [%s]\n", label, c.Detail, mark)
	}
}
