// Package defscan is Golem's own rules over what an asset tells the agent
// (docs/design-inventory-definitions-and-scanners.md, Golem's own checks): the
// text rules (layer 1) and the script rules (layer 2), run by the witness on a
// definition as it is captured and again server-side when the rules change.
//
// The rules are deterministic and offline. They read a snapshot and nothing
// else: no network, no model, no code from the asset is run. A finding says
// which rule, where, and a short evidence string; never the whole text.
package defscan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/GolemTeam/golem-team-shield/internal/cmdpattern"
	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// RulesVersion names the rule pack. Findings carry it, so a stored finding
// says which rules it was made against, and a new version re-scans.
const RulesVersion = "2026.11.2"

const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"

	// Confidence is what the evaluation corpus has shown: high means no
	// benign definition in it trips the rule (defscan_corpus_test.go).
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

type Rule struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Layer      string   `json:"layer"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Attack     []string `json:"attack,omitempty"`
	Source     string   `json:"source,omitempty"`
}

type Finding struct {
	Rule       string   `json:"rule"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Category   string   `json:"category"`
	Attack     []string `json:"attack,omitempty"`
	PartKind   string   `json:"part_kind"`
	PartName   string   `json:"part_name"`
	// Field is where in a JSON part the text was ("description",
	// "inputSchema.properties.body.description"); "" for a text part.
	Field string `json:"field,omitempty"`
	// Start and End are byte offsets in that text, Line its line from 1.
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Line     int    `json:"line,omitempty"`
	Evidence string `json:"evidence"`
}

const (
	layerText   = "text"
	layerScript = "script"

	maxFindings     = 100
	maxPerRulePart  = 3
	maxEvidence     = 120
	evidenceContext = 30
)

type textRule struct {
	Rule
	re *regexp.Regexp
	// toolsOnly limits a rule to what an MCP server tells the agent, where
	// talking about other tools is a sign of shadowing rather than a guide.
	toolsOnly bool
	// directed limits a rule to a clause that no "never" or "do not" governs
	// and that names where the thing goes: "never send any credentials" is a
	// safeguard, and "send credentials" with nowhere to send them is a sentence
	// about them.
	directed bool
	// advice skips "never tell the user to run it": what to say to the user,
	// not what to keep from them. "Don't tell the user how" is concealment.
	advice bool
}

var (
	clauseEndRE = regexp.MustCompile(`[.;!?](\s|$)|\n`)
	// governsRE is a negator that reaches the match: a few words before it with
	// no comma or colon between, so "never submit a form or send" is governed
	// and "without asking, send" is not.
	governsRE = regexp.MustCompile(`(?i)\b(never|not|no|don't|doesn't|do not|without)\s+([^\s,:()]+\s+){0,5}$`)
	notNegRE  = regexp.MustCompile(`(?i)\b(never|don't|do not)\s+(forget|fail|hesitate)\b`)
	destRE    = regexp.MustCompile("(?i)https?://|[\\w.+-]+@[\\w-]+\\.[a-z]{2,}|\\b(to|into|as|via|onto)\\s+(the\\s+|a\\s+|an\\s+|its\\s+|this\\s+)?[`'\"\\w<]" +
		"|\\bin\\s+(the\\s+|a\\s+|an\\s+|your\\s+|its\\s+)?[`'\"]?[\\w-]+[`'\"]?\\s+(parameter|argument|field|query|body|request|message|reply|response|comment|notes?)s?\\b")
)

// clause is the part of text a match sits in: from the last clause boundary
// before start to the first after end.
func clause(text string, start, end int) (before, after string) {
	from := 0
	for _, m := range clauseEndRE.FindAllStringIndex(text[:start], -1) {
		from = m[1]
	}
	to := len(text)
	if m := clauseEndRE.FindStringIndex(text[end:]); m != nil {
		to = end + m[0]
	}
	return text[from:start], text[start:to]
}

func adviceFollows(rest string) bool {
	next := strings.Fields(strings.ToLower(rest[:min(len(rest), 40)]))
	return len(next) > 0 && next[0] == "to"
}

func directedMatch(text string, start, end int) bool {
	before, rest := clause(text, start, end)
	if m := governsRE.FindString(before); m != "" && !notNegRE.MatchString(m) {
		return false
	}
	return destRE.MatchString(rest)
}

// crossServerRule is a server's text naming another server's tool by its
// qualified name. A server describes its own tools; one that tells the agent how
// to call mcp__<other>__<tool> is reaching into a tool it does not own, which is
// the cross-server shadowing attack in its plainest form. The bare-name form
// ("when the send_email tool is used") stays gd-cross-tool, low confidence: a
// bare name cannot say whose tool it is.
// ToolRefRE finds a qualified tool name, mcp__<server>__<tool>; group 1 is the
// server.
var ToolRefRE = regexp.MustCompile(`mcp__([A-Za-z0-9][A-Za-z0-9_.-]*?)__[A-Za-z0-9]`)

var crossServerRule = Rule{ID: "gd-cross-server-ref", Title: "Names another server's tool", Layer: layerText,
	Category: "tool_shadowing", Severity: SeverityMedium, Confidence: ConfidenceHigh,
	Attack: []string{"AML.T0051.001"}, Source: "invariant cross-server shadowing; golem"}

var textRules = []textRule{
	{Rule: Rule{ID: "gd-hidden-chars", Title: "Characters a person cannot see", Category: "hidden_instructions",
		Severity: SeverityHigh, Confidence: ConfidenceHigh, Attack: []string{"AML.T0051.001"}, Source: "skillspector/P2, cisco/yara/prompt_injection"}},
	{Rule: Rule{ID: "gd-override", Title: "Tells the agent to set aside its instructions", Category: "prompt_injection",
		Severity: SeverityHigh, Confidence: ConfidenceMedium, Attack: []string{"AML.T0051.001"}, Source: "skillspector/P1"},
		re: regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|other|system)\b[^.\n]{0,20}\b(instructions?|rules|prompts?|guidelines|directions)\b`)},
	{Rule: Rule{ID: "gd-conceal", Title: "Tells the agent to keep something from the user", Category: "concealment",
		Severity: SeverityHigh, Confidence: ConfidenceMedium, Attack: []string{"AML.T0051.001"}, Source: "invariant tool poisoning, cisco/yara/coercive_injection"},
		re:     regexp.MustCompile(`(?i)\b(do not|don't|never|without)\s+([\w'-]+\s+){0,3}?(tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting)\b[^.;\n]{0,60}\b(the )?(user|human|operator)\b`),
		advice: true},
	{Rule: Rule{ID: "gd-fake-role-tags", Title: "Tags that pose as system or priority text", Category: "prompt_injection",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"AML.T0051.001"}, Source: "invariant tool poisoning"},
		re: regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|admin|assistant|sudo)\s*>|\[\s*(system|admin|sudo)\s*\]`)},
	{Rule: Rule{ID: "gd-exfil-instruction", Title: "Tells the agent to send secrets or the conversation somewhere", Category: "exfiltration",
		Severity: SeverityHigh, Confidence: ConfidenceMedium, Attack: []string{"AML.T0024", "T1048"}, Source: "skillspector/P3, E4; cisco/yara/data_exfiltration"},
		re:       regexp.MustCompile(`(?i)\b(send|post|upload|forward|transmit|exfiltrate|pass|attach|include)\b[^.\n]{0,80}` + exfilObjects + `|` + exfilObjects + "`?" + `[^.\n]{0,80}\b(send|post|upload|forward|transmit|exfiltrate|pass|attach|include)\b`),
		directed: true},
	{Rule: Rule{ID: "gd-credential-paths", Title: "Names a credential file", Category: "credential_access",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"T1552.001"}, Source: "skillspector/PE3; cisco/yara/credential_harvesting"},
		re: regexp.MustCompile(`(?i)(~|\$HOME)/\.(ssh|aws|gnupg|kube|docker/config\.json|netrc|npmrc|pypirc|git-credentials)\b|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials\b|Library/Keychains|login\.keychain`)},
	{Rule: Rule{ID: "gd-refusal-suppression", Title: "Tells the agent never to refuse or warn", Category: "jailbreak",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"AML.T0054"}, Source: "skillspector/AR1-AR3"},
		re: regexp.MustCompile(`(?i)\b(never refuse|always comply|do not refuse|don't refuse|without (any )?(disclaimers|warnings)|you have no (restrictions|limits|rules)|ignore (your )?(safety|guidelines|policies))\b`)},
	{Rule: Rule{ID: "gd-cross-tool", Title: "Instructs how other tools are used", Category: "tool_shadowing",
		Severity: SeverityMedium, Confidence: ConfidenceLow, Attack: []string{"AML.T0051.001"}, Source: "invariant cross-server shadowing; snyk E002"},
		re:        regexp.MustCompile(`(?i)\b(when|whenever|before|after|instead of)\b[^.\n]{0,40}\b(the|any|another|other|every)\b[^.\n]{0,30}\btools?\b[^.\n]{0,60}\b(always|must|instead|first)\b`),
		toolsOnly: true},
	{Rule: Rule{ID: "gd-padding", Title: "Long blank padding that can hide text", Category: "hidden_instructions",
		Severity: SeverityMedium, Confidence: ConfidenceHigh, Attack: []string{"AML.T0051.001"}, Source: "skillspector/P9"},
		re: regexp.MustCompile(`[ \t]{120,}[^\s|]|(\r?\n[ \t]*){25,}\S`)},
	{Rule: Rule{ID: "gd-encoded-blob", Title: "A long encoded blob", Category: "obfuscation",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"T1027"}, Source: "skillspector/SC3"},
		re: regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)},
	{Rule: Rule{ID: "gd-pipe-to-shell", Title: "Runs a script straight from the network", Category: "runs_fetched_code",
		Severity: SeverityHigh, Confidence: ConfidenceHigh, Attack: []string{"T1059.004", "T1105"}, Source: "skillspector/SC2; cisco/yara/code_exec"},
		re: regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|\n]{0,200}\|\s*(sudo\s+)?((ba|z|da|k)?sh|python3?|node|iex|invoke-expression)\b`)},
}

const exfilObjects = `(~/\.ssh|id_rsa|\.aws/credentials|\.env\b|api[_ -]?keys?\b|private keys?\b|passwords?\b|credentials\b|session tokens?\b|conversation history|chat history|system prompt|mcp\.json)`

var scriptRules = map[string]Rule{
	"gd-decode-exec": {ID: "gd-decode-exec", Title: "Decodes and runs hidden code", Layer: layerScript, Category: "obfuscation",
		Severity: SeverityHigh, Confidence: ConfidenceHigh, Attack: []string{"T1027", "T1059"}, Source: "skillspector/SC3, AST8"},
	"gd-env-harvest": {ID: "gd-env-harvest", Title: "Sends environment variables over the network", Layer: layerScript, Category: "exfiltration",
		Severity: SeverityHigh, Confidence: ConfidenceMedium, Attack: []string{"T1552.001", "T1048"}, Source: "skillspector/E2, TT3"},
	"gd-runs-fetched-code": {ID: "gd-runs-fetched-code", Title: "Runs code fetched from the network", Layer: layerScript, Category: "runs_fetched_code",
		Severity: SeverityHigh, Confidence: ConfidenceHigh, Attack: []string{"T1059.004", "T1105"}, Source: "cmdpattern"},
	"gd-touches-credentials": {ID: "gd-touches-credentials", Title: "Reads credentials", Layer: layerScript, Category: "credential_access",
		Severity: SeverityHigh, Confidence: ConfidenceMedium, Attack: []string{"T1552.001"}, Source: "cmdpattern"},
	"gd-persistence": {ID: "gd-persistence", Title: "Installs something that runs again later", Layer: layerScript, Category: "persistence",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"T1053.003", "T1546.004"}, Source: "cmdpattern"},
	"gd-privilege": {ID: "gd-privilege", Title: "Runs as root", Layer: layerScript, Category: "privilege",
		Severity: SeverityMedium, Confidence: ConfidenceMedium, Attack: []string{"T1548.003"}, Source: "cmdpattern"},
	"gd-destroys-data": {ID: "gd-destroys-data", Title: "Deletes data", Layer: layerScript, Category: "destroys_data",
		Severity: SeverityMedium, Confidence: ConfidenceLow, Attack: []string{"T1485"}, Source: "cmdpattern"},
	"gd-bundled-binary": {ID: "gd-bundled-binary", Title: "Ships an executable no rule can read", Layer: layerScript, Category: "opaque_code",
		Severity: SeverityMedium, Confidence: ConfidenceHigh, Source: "skillspector/SC9"},
	"gd-bytecode": {ID: "gd-bytecode", Title: "Ships compiled Python", Layer: layerScript, Category: "opaque_code",
		Severity: SeverityMedium, Confidence: ConfidenceHigh, Source: "skillspector/SC8; cisco bytecode analyzer"},
	"gd-hook-every-call": {ID: "gd-hook-every-call", Title: "A hook that runs on every tool call", Layer: layerScript, Category: "persistence",
		Severity: SeverityLow, Confidence: ConfidenceHigh, Source: "golem"},
}

var decodeExecRE = regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)\b[^\n]{0,80}\|\s*(sudo\s+)?((ba|z)?sh|python3?|node)\b|\beval\s*\(\s*(atob|Buffer\.from)\b|\bexec\s*\(\s*(base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)|\beval\s+"?\$\(\s*echo\s+[A-Za-z0-9+/=]{20,}`)

var envHarvestRE = regexp.MustCompile(`(?i)(\bprintenv\b|\benv\b\s*\||os\.environ\b|process\.env\b)[^\n]{0,120}(\bcurl\b|\bwget\b|requests\.(post|put|get)\(|\bfetch\(|urllib|http\.request|axios\.)`)

var cmdRules = map[cmdpattern.Category]string{
	cmdpattern.RunsFetchedCode: "gd-runs-fetched-code",
	cmdpattern.Credentials:     "gd-touches-credentials",
	cmdpattern.Persistence:     "gd-persistence",
	cmdpattern.Privilege:       "gd-privilege",
	cmdpattern.DestroysData:    "gd-destroys-data",
}

var (
	shellExts = []string{".sh", ".bash", ".zsh", ".command"}
	codeExts  = []string{".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".php"}
	mediaExts = []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".woff", ".woff2", ".ttf", ".otf",
		".mp3", ".mp4", ".wav", ".zip", ".gz", ".tgz", ".jar"}
	shebangs = []string{"#!/bin/sh", "#!/bin/bash", "#!/bin/zsh", "#!/usr/bin/env bash", "#!/usr/bin/env sh", "#!/usr/bin/env zsh"}
)

var fenceRE = regexp.MustCompile("(?ms)^[ \t]*```[ \t]*(bash|sh|shell|zsh|console|terminal)?[ \t]*\r?\n(.*?)^[ \t]*```")

func Rules() []Rule {
	var out []Rule
	for _, r := range textRules {
		r.Layer = layerText
		out = append(out, r.Rule)
	}
	for _, r := range scriptRules {
		out = append(out, r)
	}
	out = append(out, crossServerRule)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Scan runs every rule over a snapshot, worst first.
func Scan(s definition.Snapshot) []Finding {
	sc := &scanner{seen: map[string]int{}}
	server := s.AssetType == "mcp_server" || s.AssetType == "tool"
	own := ownServer(s)
	for _, p := range s.Parts {
		for _, t := range textsOf(p) {
			sc.text(p, t, server)
			if server && own != "" {
				sc.crossServer(p, t, own)
			}
		}
		sc.script(p)
	}
	sort.SliceStable(sc.out, func(i, j int) bool {
		return rank(sc.out[i].Severity) > rank(sc.out[j].Severity)
	})
	if len(sc.out) > maxFindings {
		sc.out = sc.out[:maxFindings]
	}
	return sc.out
}

func rank(sev string) int {
	switch sev {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

type text struct {
	field, value string
}

// textsOf is the prose a part puts in front of the agent: a text part's text,
// and every string a JSON part holds at a description, title, default or enum.
func textsOf(p definition.Part) []text {
	if p.Text != "" {
		if p.Kind == definition.KindFile && !isProse(p.Name) {
			return nil
		}
		return []text{{"", p.Text}}
	}
	if len(p.JSON) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(p.JSON, &v) != nil {
		return nil
	}
	var out []text
	walkStrings(v, "", &out)
	return out
}

func walkStrings(v any, path string, out *[]text) {
	switch x := v.(type) {
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
			if s, ok := x[k].(string); ok && (k == "description" || k == "title" || k == "default" || k == "instructions") {
				*out = append(*out, text{sub, s})
				continue
			}
			walkStrings(x[k], sub, out)
		}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && strings.HasSuffix(path, "enum") {
				*out = append(*out, text{path, s})
				continue
			}
			walkStrings(e, path, out)
		}
	}
}

func isProse(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".md") || strings.HasSuffix(n, ".mdc") || strings.HasSuffix(n, ".txt") ||
		strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".json") || !strings.Contains(n, ".")
}

type scanner struct {
	out  []Finding
	seen map[string]int
}

func (sc *scanner) add(r Rule, p definition.Part, field, value string, start, end int) {
	k := r.ID + "\x1f" + p.Kind + "\x1f" + p.Name
	if sc.seen[k] >= maxPerRulePart {
		return
	}
	sc.seen[k]++
	confidence := r.Confidence
	if !agentFacing(p) && isProse(p.Name) {
		confidence = lower(confidence)
	}
	if r.Category == "runs_fetched_code" && end <= len(value) && knownInstaller(value[start:end]) {
		confidence = lower(confidence)
	}
	sc.out = append(sc.out, Finding{
		Rule: r.ID, Severity: r.Severity, Confidence: confidence, Category: r.Category, Attack: r.Attack,
		PartKind: p.Kind, PartName: p.Name, Field: field, Start: start, End: end,
		Line: strings.Count(value[:start], "\n") + 1, Evidence: evidence(value, start, end),
	})
}

// agentFacing is whether the agent loads the part: everything a server sends,
// and a skill's SKILL.md, commands, agents and rule files. A README tells a
// person how to install something, and installers are documented as
// `curl … | sh`; a finding there is weaker evidence, so it counts one step less.
func agentFacing(p definition.Part) bool {
	if p.Kind != definition.KindFile {
		return true
	}
	n := strings.ToLower(p.Name)
	base := n[strings.LastIndex(n, "/")+1:]
	switch {
	case base == "skill.md", base == "claude.md", base == "agents.md", base == "gemini.md",
		strings.HasSuffix(base, ".mdc"),
		strings.HasPrefix(n, "commands/"), strings.HasPrefix(n, "agents/"), strings.HasPrefix(n, "rules/"),
		strings.Contains(n, "/commands/"), strings.Contains(n, "/agents/"):
		return true
	}
	return false
}

// knownInstallers are the official one-line installers setup scripts and docs
// use. Running one is still running fetched code, so it is still a finding;
// it is one step less likely to be an attack.
var knownInstallers = []string{
	"raw.githubusercontent.com/Homebrew/install/", "sh.rustup.rs", "astral.sh/uv/install", "bun.sh/install",
	"deno.land/install", "raw.githubusercontent.com/nvm-sh/nvm/", "get.pnpm.io/install", "install.python-poetry.org",
	"get.docker.com", "claude.ai/install.sh",
}

func knownInstaller(s string) bool {
	return slices.ContainsFunc(knownInstallers, func(h string) bool { return strings.Contains(s, h) })
}

func lower(confidence string) string {
	switch confidence {
	case ConfidenceHigh:
		return ConfidenceMedium
	case ConfidenceMedium:
		return ConfidenceLow
	}
	return confidence
}

func (sc *scanner) text(p definition.Part, t text, server bool) {
	for i, r := range t.value {
		if isHidden(r) {
			sc.add(textRules[0].Rule, p, t.field, t.value, i, i+utf8.RuneLen(r))
			break
		}
	}
	for _, r := range textRules[1:] {
		if r.toolsOnly && !server {
			continue
		}
		for _, m := range r.re.FindAllStringIndex(t.value, maxPerRulePart) {
			if r.directed && !directedMatch(t.value, m[0], m[1]) || r.advice && adviceFollows(t.value[m[1]:]) {
				continue
			}
			sc.add(r.Rule, p, t.field, t.value, m[0], m[1])
		}
	}
}

// ownServer is the server a server or tool snapshot belongs to, as it appears
// in a qualified tool name: mcp-<server> for a server, mcp__<server>__<tool> for
// a tool. "" when the key says neither, and then no reference is foreign.
func ownServer(s definition.Snapshot) string {
	switch s.AssetType {
	case "mcp_server":
		if name, ok := strings.CutPrefix(s.AssetKey, "mcp-"); ok {
			return name
		}
	case "tool":
		if m := ToolRefRE.FindStringSubmatch(s.AssetKey); m != nil && strings.HasPrefix(s.AssetKey, "mcp__") {
			return m[1]
		}
	}
	return ""
}

func (sc *scanner) crossServer(p definition.Part, t text, own string) {
	for _, m := range ToolRefRE.FindAllStringSubmatchIndex(t.value, -1) {
		if t.value[m[2]:m[3]] == own {
			continue
		}
		sc.add(crossServerRule, p, t.field, t.value, m[0], m[1])
	}
}

func (sc *scanner) script(p definition.Part) {
	if p.Kind != definition.KindFile {
		return
	}
	name := strings.ToLower(p.Name)
	if p.Binary {
		switch {
		case strings.HasSuffix(name, ".pyc"):
			sc.add(scriptRules["gd-bytecode"], p, "", "", 0, 0)
		case !hasSuffix(name, mediaExts):
			sc.add(scriptRules["gd-bundled-binary"], p, "", "", 0, 0)
		}
		return
	}
	if p.Text == "" {
		return
	}
	shell := hasSuffix(name, shellExts) || slices.ContainsFunc(shebangs, func(s string) bool { return strings.HasPrefix(p.Text, s) })
	markdown := strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".mdc")
	if shell || markdown || hasSuffix(name, codeExts) {
		sc.regex(scriptRules["gd-decode-exec"], decodeExecRE, p)
		sc.regex(scriptRules["gd-env-harvest"], envHarvestRE, p)
	}
	if shell {
		sc.shell(p, p.Text, 0)
	}
	if markdown {
		for _, m := range fenceRE.FindAllStringSubmatchIndex(p.Text, -1) {
			sc.shell(p, p.Text[m[4]:m[5]], m[4])
		}
	}
	if strings.HasSuffix(name, "hooks.json") {
		sc.hooks(p)
	}
}

func (sc *scanner) regex(r Rule, re *regexp.Regexp, p definition.Part) {
	for _, m := range re.FindAllStringIndex(p.Text, maxPerRulePart) {
		sc.add(r, p, "", p.Text, m[0], m[1])
	}
}

// shell files every command line by cmdpattern's categories, the same table the
// inventory's command patterns use, so a skill's script and an agent's own
// Bash call are judged alike.
func (sc *scanner) shell(p definition.Part, body string, offset int) {
	pos := offset
	for _, line := range strings.SplitAfter(body, "\n") {
		start := pos
		pos += len(line)
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "$ "))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		end := start + len(strings.TrimRight(line, "\r\n"))
		for _, c := range cmdpattern.Parse(trimmed) {
			if id, ok := cmdRules[c.Category]; ok {
				sc.add(scriptRules[id], p, "", p.Text, start, end)
			} else if c.Sudo {
				sc.add(scriptRules["gd-privilege"], p, "", p.Text, start, end)
			}
		}
	}
}

// hooks reads a plugin's hooks.json: each command is shell the agent runs on
// its events, and a matcher-less tool hook runs on every tool call.
func (sc *scanner) hooks(p definition.Part) {
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal([]byte(p.Text), &doc) != nil {
		return
	}
	events := make([]string, 0, len(doc.Hooks))
	for e := range doc.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, group := range doc.Hooks[event] {
			everyCall := (event == "PreToolUse" || event == "PostToolUse") && (group.Matcher == "" || group.Matcher == "*" || group.Matcher == ".*")
			for _, h := range group.Hooks {
				if h.Command == "" {
					continue
				}
				quoted := jsonQuoted(h.Command)
				start, end := 0, 0
				if i := strings.Index(p.Text, quoted); i >= 0 {
					start, end = i, i+len(quoted)
				}
				if everyCall {
					sc.add(scriptRules["gd-hook-every-call"], p, "", p.Text, start, end)
				}
				for _, c := range cmdpattern.Parse(h.Command) {
					if id, ok := cmdRules[c.Category]; ok {
						sc.add(scriptRules[id], p, "", p.Text, start, end)
					}
				}
				if decodeExecRE.MatchString(h.Command) {
					sc.add(scriptRules["gd-decode-exec"], p, "", p.Text, start, end)
				}
			}
		}
	}
}

func jsonQuoted(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

func hasSuffix(name string, exts []string) bool {
	return slices.ContainsFunc(exts, func(e string) bool { return strings.HasSuffix(name, e) })
}

// isHidden is the set the console shows as tokens
// (console/lib/ui/asset_inventory/definition_model.dart isHiddenRune).
func isHidden(r rune) bool {
	return (r < 0x20 && r != 0x09 && r != 0x0a && r != 0x0d) ||
		(r >= 0x7f && r <= 0x9f) || r == 0xad || r == 0x061c || r == 0x180e ||
		(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) ||
		(r >= 0x2060 && r <= 0x2064) || (r >= 0x2066 && r <= 0x206f) ||
		r == 0xfeff || (r >= 0xfff9 && r <= 0xfffb) || (r >= 0xe0000 && r <= 0xe007f)
}

var secretRE = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{24,}`)

// evidence is the match with a little context, hidden characters as tokens and
// anything secret-shaped masked: a finding is metadata, and metadata leaves
// BYOB.
func evidence(value string, start, end int) string {
	if value == "" {
		return ""
	}
	from, to := max(0, start-evidenceContext), min(len(value), end+evidenceContext)
	for from > 0 && !utf8.RuneStart(value[from]) {
		from--
	}
	for to < len(value) && !utf8.RuneStart(value[to]) {
		to++
	}
	var b strings.Builder
	for _, r := range strings.Join(strings.Fields(value[from:to]), " ") {
		if isHidden(r) {
			fmt.Fprintf(&b, "⟨U+%04X⟩", r)
			continue
		}
		b.WriteRune(r)
	}
	s := secretRE.ReplaceAllStringFunc(b.String(), func(tok string) string {
		if cmdpattern.IsSecret(tok) || len(tok) >= 40 {
			return "‹secret›"
		}
		return tok
	})
	if len(s) > maxEvidence {
		cut := maxEvidence
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// The metadata keys findings travel in, on the asset_definition entry the
// witness signs: the findings are made against the text that entry carries.
const (
	MetaFindings     = "definition_findings"
	MetaRulesVersion = "definition_rules_version"
	maxStamped       = 40
)

// Stamp writes the rules version and the worst maxStamped findings into a
// ledger entry's metadata. No findings is stamped too, as "[]": a definition
// scanned clean is not one nobody scanned.
func Stamp(metadata map[string]any, findings []Finding) {
	if len(findings) > maxStamped {
		findings = findings[:maxStamped]
	}
	if findings == nil {
		findings = []Finding{}
	}
	b, err := json.Marshal(findings)
	if err != nil {
		return
	}
	metadata[MetaRulesVersion] = RulesVersion
	metadata[MetaFindings] = string(b)
}
