package main

import (
	"fmt"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// statusAgents says, per agent installed here, whether its shell commands run
// in the jail: the same lines `golem check` and `golem doctor` read.
func (s *setup) statusAgents() {
	cov := shield.CoverageOf(shield.CoverageEnv{Home: s.home, GOOS: s.goos})
	if len(cov) == 0 {
		fmt.Fprintln(s.stdout, "agents       none here that the jail can attach to")
		return
	}
	for i, c := range cov {
		label := "agents"
		if i > 0 {
			label = ""
		}
		fmt.Fprintf(s.stdout, "%-12s %s [%s]\n", label, c.Detail, c.Coverage)
	}
}
