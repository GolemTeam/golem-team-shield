package agentposture

import (
	"regexp"
	"runtime"
	"strings"
)

// Areas group the checks for the report (docs/design-golem-check-report.md).
// An Item a caller adds with none is in AreaRunModes.
const (
	AreaRunModes     = "run_modes"
	AreaPermissions  = "permissions"
	AreaMCPServers   = "mcp_servers"
	AreaInstructions = "instructions"
	AreaHooks        = "hooks"
	AreaSecrets      = "secrets"
	AreaSources      = "sources"
	// AreaProtections is scored by what its items say is in place, not by
	// their severity.
	AreaProtections = "protections"
)

type AreaInfo struct {
	Area  string `json:"area"`
	Title string `json:"title"`
}

var areas = []AreaInfo{
	{AreaRunModes, "Run modes"},
	{AreaPermissions, "Permissions"},
	{AreaMCPServers, "MCP servers"},
	{AreaInstructions, "Instructions and skills"},
	{AreaHooks, "Hooks"},
	{AreaSecrets, "Secrets"},
	{AreaSources, "Plugin sources"},
	{AreaProtections, "Protections"},
}

// Areas is every area, in report order.
func Areas() []AreaInfo { return append([]AreaInfo(nil), areas...) }

func areaTitle(area string) string {
	for _, a := range areas {
		if a.Area == area {
			return a.Title
		}
	}
	return area
}

var checkAreas = map[string]string{
	"shell_allowed": AreaPermissions,
	"agent_sandbox": AreaProtections,
	"no_sandbox":    AreaProtections,
	"shell_jail":    AreaProtections,
}

func areaOf(check string) string {
	if a, ok := checkAreas[check]; ok {
		return a
	}
	return AreaRunModes
}

// Result is a scan with the agents it found installed and the areas it read
// something for, so an area with nothing to read is not scored as clean.
type Result struct {
	Items  []Item
	Agents []string
	Read   []string
	// Repo names the repository a ScanRepo read; "" for a machine.
	Repo string
}

// MaxReportItems caps ScanAll, which reports more than the settings Scan does.
const MaxReportItems = 1000

// ScanAll is Scan with the agents and areas it covered, and the config scan.
// Scan stays the settings alone: it is what the Golem agent's posture reporter
// sends, and the agent alerts on the config scan's findings separately.
func ScanAll(env Env) Result {
	s := scanEnv(env)
	if s == nil {
		return Result{}
	}
	res := Result{Items: s.items, Agents: sortedSet(s.agents)}
	if len(res.Agents) > 0 {
		s.read[AreaRunModes], s.read[AreaPermissions], s.read[AreaProtections] = true, true, true
	}
	skip := ManagedAssetPaths(env.Home)
	cs := ScanConfig(env, skip)
	for a := range cs.Read {
		if a != AreaInstructions && a != AreaHooks {
			s.read[a] = true
		}
	}
	// The config scan's own instruction and hook checks stay for the Golem
	// agent's alerts; the report reads the same files with defscan's rules.
	for _, it := range cs.Items() {
		if it.Area == AreaInstructions || it.Area == AreaHooks {
			continue
		}
		if it.Check == "mcp_plaintext_secret" && it.Scope == "project" && it.Severity == Info {
			it.Severity, it.Detail = Suspicious, it.Detail+", in a repository file, so probably committed"
		}
		res.Items = append(res.Items, it)
	}
	res.Items = append(res.Items, s.instructionItems(skip)...)
	res.Items = append(res.Items, s.hookItems()...)
	res.Items = append(res.Items, s.permissionItems()...)
	res.Items = append(res.Items, s.secretItems()...)
	res.Items = append(res.Items, s.sourceItems()...)
	if len(res.Agents) > 0 {
		s.read[AreaSecrets] = true
	}
	res.Items = collapseCopies(res.Items)
	Sort(res.Items)
	if len(res.Items) > MaxReportItems {
		res.Items = res.Items[:MaxReportItems]
	}
	res.Read = sortedSet(s.read)
	return res
}

// Add appends items a caller found, such as the shell jail's coverage. An
// agent a protection item names counts as found, since only installed agents
// get one.
func (r *Result) Add(items ...Item) {
	for _, it := range items {
		if it.Area == "" {
			it.Area = areaOf(it.Check)
		}
		r.Items = append(r.Items, it)
		if it.Area == AreaProtections && it.Client != "" && !contains(r.Agents, it.Client) {
			r.Agents = append(r.Agents, it.Client)
		}
		if !contains(r.Read, it.Area) {
			r.Read = append(r.Read, it.Area)
		}
	}
	Sort(r.Items)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var worktreeRE = regexp.MustCompile(`[/\\]\.claude[/\\]worktrees[/\\][^/\\]+`)

// collapseCopies reports a finding once per repository: a git worktree is a
// copy of its repository's files, and on a case-insensitive disk one
// repository can be listed under two spellings of its path.
func collapseCopies(items []Item) []Item {
	seen := map[string]bool{}
	out := items[:0]
	for _, it := range items {
		loc := worktreeRE.ReplaceAllString(it.Location, "")
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			loc = strings.ToLower(loc)
		}
		k := strings.Join([]string{it.Client, it.Check, it.Severity, it.Subject, it.Setting, loc}, "\x00")
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, it)
	}
	return out
}
