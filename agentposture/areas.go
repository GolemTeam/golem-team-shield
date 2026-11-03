package agentposture

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
}

// ScanAll is Scan with the agents and areas it covered.
func ScanAll(env Env) Result {
	s := scanEnv(env)
	if s == nil {
		return Result{}
	}
	res := Result{Items: s.items, Agents: sortedSet(s.agents)}
	if len(res.Agents) > 0 {
		s.read[AreaRunModes], s.read[AreaPermissions], s.read[AreaProtections] = true, true, true
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
