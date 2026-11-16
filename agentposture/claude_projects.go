package agentposture

import (
	"encoding/json"
	"path/filepath"
	"sort"
)

// ClaudeProjects are the repositories Claude Code has opened, as
// ~/.claude.json lists them, sorted and at most MaxProjects. The file keeps
// every directory ever opened, so the ones that are gone are dropped before
// the cap, or they would push live projects out of it.
func ClaudeProjects(home string) []string {
	b, _, ok := readCapped(filepath.Join(home, ".claude.json"))
	if !ok {
		return nil
	}
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var projects []string
	for p := range doc.Projects {
		if filepath.IsAbs(p) && isDir(p) {
			projects = append(projects, p)
		}
	}
	sort.Strings(projects)
	if len(projects) > MaxProjects {
		projects = projects[:MaxProjects]
	}
	return projects
}
