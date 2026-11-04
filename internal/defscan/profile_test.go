package defscan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

func toolPart(t *testing.T, name string, props map[string]any, hints map[string]any) (definition.Part, *definition.Part) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"name": name, "description": "d", "inputSchema": map[string]any{"type": "object", "properties": props}})
	p, err := definition.JSON(definition.KindTool, name, b)
	if err != nil {
		t.Fatal(err)
	}
	if hints == nil {
		return p, nil
	}
	mb, _ := json.Marshal(map[string]any{"annotations": hints})
	m, err := definition.JSON(definition.KindToolMeta, name, mb)
	if err != nil {
		t.Fatal(err)
	}
	return p, &m
}

// The same cases as the console's tools_view_test.dart, so the two agree.
func TestAToolsProfileMatchesTheConsoles(t *testing.T) {
	p, m := toolPart(t, "fetch_page", map[string]any{"url": map[string]any{"type": "string"}, "body": map[string]any{"type": "string"},
		"api_key": map[string]any{"type": "string"}}, map[string]any{"openWorldHint": true})
	got := Profile(p, m)
	if strings.Join(got.Capabilities, ",") != "takes a URL,takes a credential,free-text field,open-world" || len(got.Mismatches) != 0 {
		t.Fatalf("profile %+v", got)
	}
	p, m = toolPart(t, "delete_repo", map[string]any{"command": map[string]any{"type": "string"}}, map[string]any{"readOnlyHint": true})
	got = Profile(p, m)
	if got.Capabilities[0] != "runs a command" || len(got.Mismatches) != 3 {
		t.Fatalf("profile %+v", got)
	}
}

func TestEveryLabelAProfileSaysIsKnown(t *testing.T) {
	var parts []definition.Part
	for _, c := range []struct {
		name  string
		props map[string]any
		hints map[string]any
	}{
		{"delete_all", map[string]any{"cmd": map[string]any{"type": "string"}, "sql": map[string]any{}, "url": map[string]any{}, "path": map[string]any{},
			"api_key": map[string]any{}, "body": map[string]any{"type": "string"}}, map[string]any{"readOnlyHint": true, "idempotentHint": true, "openWorldHint": true}},
		{"remove_x", nil, map[string]any{"destructiveHint": true}},
	} {
		p, m := toolPart(t, c.name, c.props, c.hints)
		parts = append(parts, p, *m)
	}
	seen := 0
	for _, p := range ToolProfiles(definition.Snapshot{AssetType: "mcp_server", Parts: parts}) {
		for _, l := range append(p.Capabilities, p.Mismatches...) {
			seen++
			if !ProfileLabel(l) {
				t.Errorf("%q is not a known label", l)
			}
		}
	}
	if seen != len(profileLabels) {
		t.Errorf("said %d labels, know %d", seen, len(profileLabels))
	}
}
