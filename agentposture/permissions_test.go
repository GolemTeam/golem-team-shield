package agentposture

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestPermissionsPastTheShell(t *testing.T) {
	env := postureTestEnv(t)
	project := filepath.Join(t.TempDir(), "repo")
	projects, _ := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{}}})
	writePostureFile(t, filepath.Join(env.Home, ".claude.json"), string(projects))
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"), `{"permissions":{
		"allow":["Edit","Write(*)","WebFetch(domain:*)","mcp__github","mcp__linear__list_issues","mcp__claude_ai_Slack__*"],
		"additionalDirectories":["~/"]}}`)
	writePostureFile(t, filepath.Join(project, ".claude", "settings.json"), `{"enableAllProjectMcpServers":true,"permissions":{"allow":["mcp__*"]}}`)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "settings.json"),
		`{"tools":{"allowed":["write_file","web_fetch"]},"mcpServers":{"db":{"command":"x","trust":true},"ok":{"command":"y"}}}`)
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"), `{"permissions":{"allow":["Read(**)","Write(**)"]}}`)

	got := map[string]int{}
	subjects := map[string]bool{}
	for _, it := range ScanAll(env).Items {
		if it.Area != AreaPermissions || it.Check == "shell_allowed" {
			continue
		}
		got[it.Client+"/"+it.Check+"/"+it.Scope+"/"+it.Severity]++
		if it.Subject != "" {
			subjects[it.Subject] = true
		}
	}
	for k, n := range map[string]int{
		"claude-code/write_allowed/user/suspicious":       1,
		"claude-code/fetch_allowed/user/suspicious":       1,
		"claude-code/mcp_server_allowed/user/info":        2,
		"claude-code/broad_directories/user/info":         1,
		"claude-code/project_mcp_auto/project/suspicious": 1,
		"claude-code/mcp_all_allowed/project/suspicious":  1,
		"gemini-cli/write_allowed/user/suspicious":        1,
		"gemini-cli/fetch_allowed/user/suspicious":        1,
		"gemini-cli/mcp_server_allowed/user/info":         1,
		"cursor/write_allowed/user/suspicious":            1,
	} {
		if got[k] != n {
			t.Errorf("%s: %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	for _, s := range []string{"github", "claude_ai_Slack", "db"} {
		if !subjects[s] {
			t.Errorf("no item for server %s: %v", s, subjects)
		}
	}
	if subjects["linear"] || subjects["linear__list_issues"] {
		t.Error("allowing one tool is reported as allowing the whole server")
	}
	for _, it := range Scan(env) {
		if it.Check == "write_allowed" {
			t.Error("a report-only check reached the posture items")
		}
	}
}
