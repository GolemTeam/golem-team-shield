package agentposture

import "sort"

// Rule names a check for a report that lists checks apart from findings, such
// as SARIF. A defscan rule (gd-*) keeps defscan's title.
type Rule struct {
	ID    string `json:"id"`
	Area  string `json:"area"`
	Title string `json:"title"`
}

var checkTitles = map[string]Rule{
	"bypass_default":           {Area: AreaRunModes, Title: "Permission prompts are off by default"},
	"bypass_accepted":          {Area: AreaRunModes, Title: "The bypass-mode warning was accepted"},
	"run_everything":           {Area: AreaRunModes, Title: "Every command runs without asking"},
	"auto_review":              {Area: AreaRunModes, Title: "A model approves commands instead of a person"},
	"auto_execution":           {Area: AreaRunModes, Title: "Terminal commands run without asking"},
	"full_access":              {Area: AreaRunModes, Title: "Commands run with no sandbox"},
	"never_ask":                {Area: AreaRunModes, Title: "The agent never asks"},
	"network_open":             {Area: AreaRunModes, Title: "Sandboxed commands can reach the network"},
	"yolo_allowed":             {Area: AreaRunModes, Title: "YOLO mode is not disabled"},
	"folder_trust_off":         {Area: AreaRunModes, Title: "A cloned repo's settings apply without asking"},
	"auto_edit_default":        {Area: AreaRunModes, Title: "File edits run without asking"},
	"tools_auto_approve":       {Area: AreaRunModes, Title: "The editor's agent runs every tool without asking"},
	"workspace_trust_off":      {Area: AreaRunModes, Title: "Every folder opens trusted"},
	"shell_allowed":            {Area: AreaPermissions, Title: "Any shell command runs without asking"},
	"write_allowed":            {Area: AreaPermissions, Title: "Any file is edited without asking"},
	"fetch_allowed":            {Area: AreaPermissions, Title: "Any web page is fetched without asking"},
	"mcp_all_allowed":          {Area: AreaPermissions, Title: "Every MCP tool runs without asking"},
	"mcp_server_allowed":       {Area: AreaPermissions, Title: "Every tool of one MCP server runs without asking"},
	"project_mcp_auto":         {Area: AreaPermissions, Title: "Every repository's MCP servers start without asking"},
	"broad_directories":        {Area: AreaPermissions, Title: "The agent may work in the whole disk or home directory"},
	"mcp_pipe_to_shell":        {Area: AreaMCPServers, Title: "An MCP server starts by piping a download into a shell"},
	"mcp_insecure_remote":      {Area: AreaMCPServers, Title: "An MCP server is reached over plain http"},
	"mcp_unpinned_package":     {Area: AreaMCPServers, Title: "An MCP server's package version is not pinned"},
	"mcp_unpinned_image":       {Area: AreaMCPServers, Title: "An MCP server's container image is not pinned"},
	"mcp_container_escape":     {Area: AreaMCPServers, Title: "An MCP server's container can reach the whole machine"},
	"mcp_broad_root":           {Area: AreaMCPServers, Title: "A filesystem MCP server is given the disk or home directory"},
	"mcp_plaintext_secret":     {Area: AreaSecrets, Title: "A credential in plain text in an MCP server's definition"},
	"config_plaintext_secret":  {Area: AreaSecrets, Title: "A credential in plain text in an agent's settings"},
	"credential_file_readable": {Area: AreaSecrets, Title: "An agent's sign-in file is readable by other users"},
	"hook_script_writable":     {Area: AreaHooks, Title: "A hook runs a script other users can change"},
	"hook_script_missing":      {Area: AreaHooks, Title: "A hook runs a script that does not exist"},
	"hook_errors_hidden":       {Area: AreaHooks, Title: "A hook hides its own failures"},
	"marketplace_third_party":  {Area: AreaSources, Title: "Plugins can come from a third-party marketplace"},
	"marketplace_insecure":     {Area: AreaSources, Title: "A plugin marketplace is fetched over plain http"},
	"marketplace_from_project": {Area: AreaSources, Title: "A repository adds a plugin marketplace"},
	"plugin_from_project":      {Area: AreaSources, Title: "A repository turns a plugin on"},
	"extension_installed":      {Area: AreaSources, Title: "An agent extension is installed"},
	"agent_sandbox":            {Area: AreaProtections, Title: "Shell commands run in the agent's sandbox"},
	"no_sandbox":               {Area: AreaProtections, Title: "Shell commands run without the agent's sandbox"},
	"shell_jail":               {Area: AreaProtections, Title: "Shell commands run in the Golem jail"},
}

// RuleFor is a check's rule, or the check itself as its title when it is a
// caller's own.
func RuleFor(check string) Rule {
	if r, ok := checkTitles[check]; ok {
		r.ID = check
		return r
	}
	if t, ok := ruleTitles[check]; ok {
		return Rule{ID: check, Area: AreaInstructions, Title: t}
	}
	return Rule{ID: check, Area: areaOf(check), Title: check}
}

func Rules() []Rule {
	var out []Rule
	for id := range checkTitles {
		out = append(out, RuleFor(id))
	}
	for id := range ruleTitles {
		out = append(out, RuleFor(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
