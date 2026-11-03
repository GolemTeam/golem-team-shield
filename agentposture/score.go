package agentposture

import "math"

// ScoreVersion names the scoring below. A grade is comparable only with one
// made by the same version.
const ScoreVersion = "2026.11.1"

const (
	weightDangerous  = 40
	weightSuspicious = 15
	weightInfo       = 3
)

type AreaScore struct {
	Area  string `json:"area"`
	Title string `json:"title"`
	// Applies is false when the scan read nothing for the area; it then has
	// no score and is left out of the grade.
	Applies    bool    `json:"applies"`
	Score      int     `json:"score"`
	Dangerous  int     `json:"dangerous"`
	Suspicious int     `json:"suspicious"`
	Info       int     `json:"info"`
	Covered    float64 `json:"covered,omitempty"`
	Agents     int     `json:"agents,omitempty"`
}

type Report struct {
	Version string `json:"version"`
	// Grade is A to F, or "" when no agent was found.
	Grade string      `json:"grade"`
	Score int         `json:"score"`
	Areas []AreaScore `json:"areas"`
}

// Score grades a scan (docs/design-golem-check-report.md, Scoring). Each risk
// area starts at 100 and loses 40, 15 or 3 for each distinct dangerous,
// suspicious or informational check per agent; the grade is 0.8 of their mean
// plus 0.2 of the share of agents whose shell is jailed or sandboxed, capped
// at 79 by a dangerous finding and at 69 by three.
func Score(res Result) Report {
	rep := Report{Version: ScoreVersion}
	type key struct{ client, check string }
	worst := map[string]map[key]string{}
	cover := map[string]float64{}
	for _, it := range res.Items {
		area := it.Area
		if area == "" {
			area = areaOf(it.Check)
		}
		if area == AreaProtections {
			if c := protectionCover(it); c > cover[it.Client] {
				cover[it.Client] = c
			}
			continue
		}
		if worst[area] == nil {
			worst[area] = map[key]string{}
		}
		k := key{it.Client, it.Check}
		if cur, ok := worst[area][k]; !ok || Rank(it.Severity) < Rank(cur) {
			worst[area][k] = it.Severity
		}
	}
	dangerous := 0
	sum, n := 0, 0
	var protection *AreaScore
	for _, a := range areas {
		as := AreaScore{Area: a.Area, Title: a.Title, Applies: contains(res.Read, a.Area)}
		if a.Area == AreaProtections {
			as.Applies = as.Applies && len(res.Agents) > 0
			as.Agents = len(res.Agents)
			for _, c := range res.Agents {
				as.Covered += cover[c]
			}
			if as.Agents > 0 {
				as.Score = int(math.Round(100 * as.Covered / float64(as.Agents)))
			}
			rep.Areas = append(rep.Areas, as)
			protection = &rep.Areas[len(rep.Areas)-1]
			continue
		}
		score := 100
		for _, sev := range worst[a.Area] {
			switch sev {
			case Dangerous:
				as.Dangerous++
				score -= weightDangerous
			case Suspicious:
				as.Suspicious++
				score -= weightSuspicious
			default:
				as.Info++
				score -= weightInfo
			}
		}
		as.Applies = as.Applies || len(worst[a.Area]) > 0
		if as.Applies {
			as.Score = max(score, 0)
			sum += as.Score
			n++
		}
		dangerous += as.Dangerous
		rep.Areas = append(rep.Areas, as)
	}
	if len(res.Agents) == 0 && n == 0 {
		return rep
	}
	overall := 100.0
	if n > 0 {
		overall = float64(sum) / float64(n)
	}
	if protection != nil && protection.Applies {
		overall = 0.8*overall + 0.2*float64(protection.Score)
	}
	rep.Score = int(math.Round(overall))
	switch {
	case dangerous >= 3:
		rep.Score = min(rep.Score, 69)
	case dangerous > 0:
		rep.Score = min(rep.Score, 79)
	}
	rep.Grade = grade(rep.Score)
	return rep
}

// protectionCover is how much of an agent's shell an item says is covered: a
// jail fully, the agent's own sandbox three quarters (the agent can be asked to
// step out of it), a partial jail half.
func protectionCover(it Item) float64 {
	switch it.Check {
	case "shell_jail":
		switch it.Value {
		case "jailed":
			return 1
		case "partial":
			return 0.5
		}
	case "agent_sandbox":
		return 0.75
	}
	return 0
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}
