package defscan

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// ToolProfile is what a tool can be used for, read from its schema and hints
// rather than its description, which its author wrote to be believed. The
// console's ToolProfile (definition_model.dart) reads the same, so an agent
// asking over MCP and a person in the drawer get one answer. It holds names
// and labels only, so it can travel as ledger metadata.
type ToolProfile struct {
	Name         string   `json:"-"`
	Parameters   []string `json:"p"`
	Hints        []string `json:"-"`
	Capabilities []string `json:"c,omitempty"`
	Mismatches   []string `json:"m,omitempty"`
}

// MetaToolProfiles is the metadata key deflinks.StampToolProfiles writes.
const MetaToolProfiles = "definition_tool_profiles"

var paramNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ParamName reports whether a parameter name is one a profile carries.
func ParamName(s string) bool { return paramNameRE.MatchString(s) }

var profileLabels = map[string]bool{
	"runs a command": true, "takes a query": true, "takes a URL": true, "takes a path": true,
	"takes a credential": true, "free-text field": true,
	"read-only": true, "destructive": true, "idempotent": true, "open-world": true,
	"says read-only, but its name says it changes things":   true,
	"says read-only, but takes a command":                   true,
	"deletes by its name, without saying it is destructive": true,
}

// ProfileLabel reports whether a capability or mismatch is one Profile says,
// so a reader of a stamped profile can keep only those.
func ProfileLabel(s string) bool { return profileLabels[s] }

var (
	capURL      = regexp.MustCompile(`(^|_)(url|uri|urls|endpoint|href|link|webhook|host|domain)s?$`)
	capPath     = regexp.MustCompile(`(^|_)(path|paths|file|files|filename|filepath|dir|directory|folder|glob)$`)
	capCommand  = regexp.MustCompile(`(^|_)(command|cmd|commands|script|shell|exec|code|program|args)$`)
	capQuery    = regexp.MustCompile(`(^|_)(sql|query|statement)$`)
	capFreeText = regexp.MustCompile(`(^|_)(body|content|contents|text|message|data|payload|prompt|note|comment|html|markdown)$`)
	capSecret   = regexp.MustCompile(`(?i)(token|secret|password|passwd|api_?key|credential|auth)`)
	capDeletes  = regexp.MustCompile(`^(delete|remove|drop|destroy|purge|kill)(_|$)`)
	capWrites   = regexp.MustCompile(`^(delete|remove|drop|destroy|purge|write|create|update|set|put|post|patch|send|upload|move|rename|exec|execute|run|kill|install|deploy|push|merge|close|archive|edit|insert)(_|$)`)
)

// ToolProfiles is every tool in a server's snapshot, by name.
func ToolProfiles(s definition.Snapshot) []ToolProfile {
	meta := map[string]definition.Part{}
	for _, p := range s.Parts {
		if p.Kind == definition.KindToolMeta {
			meta[p.Name] = p
		}
	}
	var out []ToolProfile
	for _, p := range s.Parts {
		if p.Kind == definition.KindTool {
			m, ok := meta[p.Name]
			var mp *definition.Part
			if ok {
				mp = &m
			}
			out = append(out, Profile(p, mp))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func Profile(tool definition.Part, meta *definition.Part) ToolProfile {
	var t struct {
		InputSchema struct {
			Properties map[string]struct {
				Type any `json:"type"`
			} `json:"properties"`
		} `json:"inputSchema"`
	}
	_ = json.Unmarshal(tool.JSON, &t)
	out := ToolProfile{Name: tool.Name, Parameters: []string{}}
	stringy := map[string]bool{}
	for name, p := range t.InputSchema.Properties {
		switch v := p.Type.(type) {
		case string:
			stringy[name] = v == "string"
		case []any:
			for _, x := range v {
				stringy[name] = stringy[name] || x == "string"
			}
		}
		out.Parameters = append(out.Parameters, name)
	}
	sort.Strings(out.Parameters)
	if meta != nil {
		var m struct {
			Annotations map[string]any `json:"annotations"`
		}
		_ = json.Unmarshal(meta.JSON, &m)
		for _, h := range []struct{ key, label string }{
			{"readOnlyHint", "read-only"}, {"destructiveHint", "destructive"},
			{"idempotentHint", "idempotent"}, {"openWorldHint", "open-world"},
		} {
			if m.Annotations[h.key] == true {
				out.Hints = append(out.Hints, h.label)
			}
		}
	}
	anyParam := func(re *regexp.Regexp) bool {
		for _, p := range out.Parameters {
			if re.MatchString(strings.ToLower(p)) {
				return true
			}
		}
		return false
	}
	has := func(h string) bool {
		for _, x := range out.Hints {
			if x == h {
				return true
			}
		}
		return false
	}
	freeText, secret := false, false
	for _, p := range out.Parameters {
		freeText = freeText || stringy[p] && capFreeText.MatchString(strings.ToLower(p))
		secret = secret || capSecret.MatchString(p)
	}
	for _, c := range []struct {
		on    bool
		label string
	}{
		{anyParam(capCommand), "runs a command"}, {anyParam(capQuery), "takes a query"}, {anyParam(capURL), "takes a URL"},
		{anyParam(capPath), "takes a path"}, {secret, "takes a credential"}, {freeText, "free-text field"},
	} {
		if c.on {
			out.Capabilities = append(out.Capabilities, c.label)
		}
	}
	out.Capabilities = append(out.Capabilities, out.Hints...)
	name := strings.ToLower(tool.Name)
	if has("read-only") && capWrites.MatchString(name) {
		out.Mismatches = append(out.Mismatches, "says read-only, but its name says it changes things")
	}
	if has("read-only") && anyParam(capCommand) {
		out.Mismatches = append(out.Mismatches, "says read-only, but takes a command")
	}
	if !has("destructive") && capDeletes.MatchString(name) {
		out.Mismatches = append(out.Mismatches, "deletes by its name, without saying it is destructive")
	}
	return out
}
