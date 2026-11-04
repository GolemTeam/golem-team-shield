package shield

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestTheAgentJailsEveryClientTheFreeToolDoes(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Attachments {
		if seen[a.Client] {
			t.Errorf("%s has two rows", a.Client)
		}
		seen[a.Client] = true
		if a.FreeTool != "" && a.Agent == "" {
			t.Errorf("golem-exec jails %s and the Golem agent doesn't", a.Client)
		}
		if a.FreeTool != a.Agent && a.Why == "" {
			t.Errorf("%s: golem-exec by %q, the agent by %q, and no reason why", a.Client, a.FreeTool, a.Agent)
		}
	}
}

func TestEveryClientTheCoverageReportShowsHasARow(t *testing.T) {
	home := t.TempDir()
	for _, f := range []string{
		".claude/settings.json", ".codex/config.toml", ".gemini/installation_id", ".cursor/hooks.json",
		".copilot/config.json", ".gemini/antigravity/x", ".hermes/config.yaml", ".openclaw/agents/x",
		".codeium/windsurf/x", ".config/Code/User/x",
	} {
		p := filepath.Join(home, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var covered, rows []string
	for _, c := range CoverageOf(CoverageEnv{Home: home, GOOS: "linux", LoginShell: "/bin/bash", ShimReady: func(string) bool { return false }}) {
		covered = append(covered, c.Client)
	}
	for _, a := range Attachments {
		rows = append(rows, a.Client)
	}
	sort.Strings(covered)
	sort.Strings(rows)
	if len(covered) != len(rows) {
		t.Fatalf("the coverage report shows %v; Attachments has rows for %v", covered, rows)
	}
	for i := range rows {
		if covered[i] != rows[i] {
			t.Fatalf("the coverage report shows %v; Attachments has rows for %v", covered, rows)
		}
	}
}
