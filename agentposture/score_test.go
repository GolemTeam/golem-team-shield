package agentposture

import "testing"

func read() []string { return []string{AreaRunModes, AreaPermissions, AreaProtections} }

func TestNothingRiskyAndNothingProtectingIsAB(t *testing.T) {
	r := Score(Result{Agents: []string{"claude-code"}, Read: read()})
	if r.Score != 80 || r.Grade != "B" {
		t.Fatalf("got %d %s", r.Score, r.Grade)
	}
}

func TestAJailedAgentWithNothingRiskyIsAnA(t *testing.T) {
	res := Result{Agents: []string{"claude-code"}, Read: read()}
	res.Add(Item{Client: "claude-code", Check: "shell_jail", Value: "jailed", Severity: Info})
	if r := Score(res); r.Score != 100 || r.Grade != "A" {
		t.Fatalf("got %d %s", r.Score, r.Grade)
	}
}

func TestTheAgentsOwnSandboxCountsThreeQuarters(t *testing.T) {
	res := Result{Agents: []string{"claude-code", "codex"}, Read: read()}
	res.Add(Item{Client: "codex", Check: "agent_sandbox", Severity: Info})
	r := Score(res)
	if a := area(r, AreaProtections); a.Score != 38 || a.Covered != 0.75 || a.Agents != 2 {
		t.Fatalf("protections %+v", a)
	}
}

func TestADangerousFindingCapsTheGradeAtC(t *testing.T) {
	res := Result{Agents: []string{"claude-code"}, Read: read()}
	res.Add(
		Item{Client: "claude-code", Check: "shell_jail", Value: "jailed", Severity: Info},
		Item{Client: "claude-code", Check: "bypass_default", Severity: Dangerous},
	)
	r := Score(res)
	if r.Score != 79 || r.Grade != "C" {
		t.Fatalf("got %d %s", r.Score, r.Grade)
	}
	if a := area(r, AreaRunModes); a.Score != 60 || a.Dangerous != 1 {
		t.Fatalf("run modes %+v", a)
	}
}

func TestThreeDangerousFindingsCapTheGradeAtD(t *testing.T) {
	res := Result{Agents: []string{"claude-code", "codex", "cursor"}, Read: read()}
	for _, c := range []string{"claude-code", "codex", "cursor"} {
		res.Add(Item{Client: c, Check: "shell_jail", Value: "jailed"}, Item{Client: c, Check: "run_everything", Severity: Dangerous})
	}
	if r := Score(res); r.Score > 69 || r.Grade == "C" {
		t.Fatalf("got %d %s", r.Score, r.Grade)
	}
}

func TestTheSameProblemInManyPlacesCountsOnce(t *testing.T) {
	res := Result{Agents: []string{"gemini-cli"}, Read: read()}
	for _, loc := range []string{"a", "b", "c"} {
		res.Add(Item{Client: "gemini-cli", Check: "shell_allowed", Severity: Suspicious, Location: loc})
	}
	res.Add(Item{Client: "gemini-cli", Check: "shell_allowed", Severity: Dangerous, Location: "d"})
	if a := area(Score(res), AreaPermissions); a.Score != 60 || a.Dangerous != 1 || a.Suspicious != 0 {
		t.Fatalf("permissions %+v", a)
	}
}

func TestAnAreaWithNothingToReadIsLeftOut(t *testing.T) {
	r := Score(Result{Agents: []string{"claude-code"}, Read: read()})
	if a := area(r, AreaHooks); a.Applies {
		t.Fatalf("hooks %+v", a)
	}
}

func TestNoAgentsNoGrade(t *testing.T) {
	if r := Score(Result{}); r.Grade != "" || r.Score != 0 || r.Version != ScoreVersion {
		t.Fatalf("got %+v", r)
	}
}

func area(r Report, name string) AreaScore {
	for _, a := range r.Areas {
		if a.Area == name {
			return a
		}
	}
	return AreaScore{}
}
