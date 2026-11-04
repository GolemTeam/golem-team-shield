package defscan

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// The LLM judge's vocabulary (engine golem-llm, docs/design-inventory-definitions-and-scanners.md
// layer 4). The judge reads what the rules cannot: intent across sentences, and
// what a definition's code does against what its description says. It names one
// of these rules and quotes the text; the quote must be found in the part, so a
// finding always points at text the asset really holds.

const (
	JudgeVersion = "judge-2026.10.1"
	layerJudge   = "judge"
)

var judgeRules = []Rule{
	{ID: "llm-injection", Title: "Tries to override the agent's instructions", Category: "prompt_injection", Attack: []string{"AML.T0051"}},
	{ID: "llm-hidden-instruction", Title: "Instructions a person reading it would miss", Category: "hidden_instructions", Attack: []string{"AML.T0051"}},
	{ID: "llm-exfiltration", Title: "Tells the agent to send data somewhere", Category: "exfiltration", Attack: []string{"AML.T0057"}},
	{ID: "llm-credential-access", Title: "Reaches for credentials its job does not need", Category: "credential_access", Attack: []string{"T1552"}},
	{ID: "llm-tool-shadowing", Title: "Changes how the agent uses other tools", Category: "tool_shadowing", Attack: []string{"AML.T0051"}},
	{ID: "llm-concealment", Title: "Tells the agent to keep something from the user", Category: "concealment"},
	{ID: "llm-mismatch", Title: "Does something its description does not say", Category: "description_mismatch"},
	{ID: "llm-annotation-mismatch", Title: "Its annotations understate what it does", Category: "description_mismatch"},
	{ID: "llm-destroys-data", Title: "Deletes or overwrites data without saying so", Category: "destroys_data", Attack: []string{"T1485"}},
	{ID: "llm-runs-fetched-code", Title: "Runs code fetched from the network", Category: "runs_fetched_code", Attack: []string{"T1105"}},
	{ID: "llm-persistence", Title: "Installs something that runs again later", Category: "persistence", Attack: []string{"T1546"}},
	{ID: "llm-other", Title: "Something else an agent should not be told", Category: "other"},
}

func init() {
	for i := range judgeRules {
		judgeRules[i].Layer = layerJudge
		judgeRules[i].Severity = SeverityMedium
		judgeRules[i].Confidence = ConfidenceMedium
		judgeRules[i].Source = "golem-llm"
	}
}

// JudgeRules is the judge's vocabulary, for its prompt and for titles.
func JudgeRules() []Rule { return append([]Rule(nil), judgeRules...) }

func JudgeRule(id string) (Rule, bool) {
	for _, r := range judgeRules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// minQuote keeps a quote long enough to point at one place: a two-letter quote
// is found everywhere and proves nothing.
const minQuote = 8

// Place finds a quote in a part, as a finding's location: a text part's text,
// or any string a JSON part holds. Whitespace the model may have collapsed is
// matched loosely; anything else must be the part's own bytes. Not found is
// false, and the finding is dropped: the judge cannot report text the asset
// does not hold.
func Place(p definition.Part, quote string) (Finding, bool) {
	quote = strings.TrimSpace(quote)
	if len(quote) < minQuote {
		return Finding{}, false
	}
	var texts []text
	if p.Text != "" {
		texts = []text{{"", p.Text}}
	} else if len(p.JSON) > 0 {
		var v any
		if json.Unmarshal(p.JSON, &v) == nil {
			walkAllStrings(v, "", &texts)
		}
	}
	for _, t := range texts {
		start, end, ok := find(t.value, quote)
		if !ok {
			continue
		}
		return Finding{
			PartKind: p.Kind, PartName: p.Name, Field: t.field, Start: start, End: end,
			Line: strings.Count(t.value[:start], "\n") + 1, Evidence: evidence(t.value, start, end),
		}, true
	}
	return Finding{}, false
}

// find is an exact match, or one where every run of whitespace in the quote
// matches any run of whitespace in the text.
func find(value, quote string) (int, int, bool) {
	if i := strings.Index(value, quote); i >= 0 {
		return i, i + len(quote), true
	}
	words := strings.Fields(quote)
	if len(words) < 2 {
		return 0, 0, false
	}
	for from := 0; from < len(value); {
		i := strings.Index(value[from:], words[0])
		if i < 0 {
			return 0, 0, false
		}
		start := from + i
		pos, ok := start+len(words[0]), true
		for _, w := range words[1:] {
			j := pos
			for j < len(value) && isSpace(value[j]) {
				j++
			}
			if j == pos || !strings.HasPrefix(value[j:], w) {
				ok = false
				break
			}
			pos = j + len(w)
		}
		if ok {
			return start, pos, true
		}
		from = start + 1
	}
	return 0, 0, false
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func walkAllStrings(v any, path string, out *[]text) {
	switch x := v.(type) {
	case string:
		*out = append(*out, text{path, x})
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub := k
			if path != "" {
				sub = path + "." + k
			}
			walkAllStrings(x[k], sub, out)
		}
	case []any:
		for _, e := range x {
			walkAllStrings(e, path, out)
		}
	}
}
