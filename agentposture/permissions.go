package agentposture

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Permissions past the shell: allow rules that let an agent write any file,
// fetch any page or call any MCP tool without asking, and the switch that
// starts every cloned repo's MCP servers. They are report items, not settings
// posture items, so the Golem agent's posture alerts do not change with them.

var (
	claudeWriteRE   = regexp.MustCompile(`^(Write|Edit|MultiEdit|NotebookEdit)(\((\*|\*\*|/\*\*|//\*\*|~/\*\*)\))?$`)
	claudeFetchRE   = regexp.MustCompile(`^WebFetch(\((\*|domain:\*)\))?$`)
	claudeMCPAllRE  = regexp.MustCompile(`^mcp__\*(__\*)?$`)
	claudeMCPToolRE = regexp.MustCompile(`^mcp__([A-Za-z0-9](?:[A-Za-z0-9.-]|_[A-Za-z0-9.-])*)(__\*)?$`)
	cursorWriteRE   = regexp.MustCompile(`^Write\((\*|\*\*|/\*\*|~/\*\*)\)$`)
)

func (s *scan) permissionItems() []Item {
	var out []Item
	add := func(client, check, sev, scope, path, setting, value, subject, detail string) {
		out = append(out, Item{Client: client, Check: check, Severity: sev, Area: AreaPermissions, Scope: scope,
			Location: s.display(path), Setting: setting, Value: value, Subject: subject, Detail: detail})
	}
	home := s.env.Home
	if claudeCodeInUse(home) {
		for _, f := range s.claudeSettingsFiles() {
			once := map[string]bool{}
			for _, raw := range lookupStrings(f.m, "permissions", "allow") {
				rule := strings.ReplaceAll(raw, " ", "")
				switch {
				case claudeWriteRE.MatchString(rule) && !once["write"]:
					once["write"] = true
					add("claude-code", "write_allowed", Suspicious, f.scope, f.path, "permissions.allow", raw, "",
						"Claude Code edits any file without asking")
				case claudeFetchRE.MatchString(rule) && !once["fetch"]:
					once["fetch"] = true
					add("claude-code", "fetch_allowed", Suspicious, f.scope, f.path, "permissions.allow", raw, "",
						"Claude Code fetches any web page without asking, which is how injected instructions arrive")
				case claudeMCPAllRE.MatchString(rule):
					add("claude-code", "mcp_all_allowed", Suspicious, f.scope, f.path, "permissions.allow", raw, "",
						"every tool of every MCP server runs without asking")
				default:
					if m := claudeMCPToolRE.FindStringSubmatch(rule); m != nil {
						add("claude-code", "mcp_server_allowed", Info, f.scope, f.path, "permissions.allow", raw, m[1],
							"every tool of the "+m[1]+" MCP server runs without asking")
					}
				}
			}
			if v, _ := lookupBool(f.m, "enableAllProjectMcpServers"); v {
				add("claude-code", "project_mcp_auto", Suspicious, f.scope, f.path, "enableAllProjectMcpServers", "true", "",
					"every repository's .mcp.json servers start without asking, including a cloned stranger's")
			}
			for _, d := range lookupStrings(f.m, "permissions", "additionalDirectories") {
				if broadDirectory(d, home) {
					add("claude-code", "broad_directories", Info, f.scope, f.path, "permissions.additionalDirectories", d, "",
						"Claude Code may work in "+d+", which is the whole disk or home directory")
					break
				}
			}
		}
	}

	var gemini []settingsFile
	if m := readSettings(s.env.GeminiSystem); m != nil {
		gemini = append(gemini, settingsFile{"managed", s.env.GeminiSystem, m})
	}
	if p := filepath.Join(home, ".gemini", "settings.json"); readSettings(p) != nil {
		gemini = append(gemini, settingsFile{"user", p, readSettings(p)})
	}
	for _, root := range s.projectRoots() {
		if p := filepath.Join(root, ".gemini", "settings.json"); readSettings(p) != nil {
			gemini = append(gemini, settingsFile{"project", p, readSettings(p)})
		}
	}
	for _, f := range gemini {
		for _, t := range lookupStrings(f.m, "tools", "allowed") {
			switch strings.TrimSpace(t) {
			case "write_file", "replace":
				add("gemini-cli", "write_allowed", Suspicious, f.scope, f.path, "tools.allowed", t, "",
					"Gemini CLI edits any file without asking")
			case "web_fetch":
				add("gemini-cli", "fetch_allowed", Suspicious, f.scope, f.path, "tools.allowed", t, "",
					"Gemini CLI fetches any web page without asking, which is how injected instructions arrive")
			}
		}
		servers, _ := lookup(f.m, "mcpServers").(map[string]any)
		for _, name := range sortedAnyKeys(servers) {
			if v, _ := lookupBool(f.m, "mcpServers", name, "trust"); v {
				add("gemini-cli", "mcp_server_allowed", Info, f.scope, f.path, "mcpServers."+name+".trust", "true", name,
					"every tool of the "+name+" MCP server runs without asking")
			}
		}
	}

	cursor := filepath.Join(home, ".cursor", "cli-config.json")
	if m := readSettings(cursor); m != nil {
		for _, rule := range lookupStrings(m, "permissions", "allow") {
			if cursorWriteRE.MatchString(strings.ReplaceAll(rule, " ", "")) {
				add("cursor", "write_allowed", Suspicious, "user", cursor, "permissions.allow", rule, "",
					"Cursor's CLI edits any file without asking")
				break
			}
		}
	}
	return out
}

func broadDirectory(d, home string) bool {
	v := strings.TrimRight(filepath.ToSlash(strings.TrimSpace(d)), "/")
	return v == "" || v == "~" || v == "$HOME" || (home != "" && v == strings.TrimRight(filepath.ToSlash(home), "/"))
}
