package agentposture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
	"github.com/GolemTeam/golem-team-shield/internal/defscan"
)

// The instructions area runs defscan, the rules the Golem agent's inventory
// runs, over what the agents load into their context: instruction files,
// skills with the files they bundle, commands, subagents and plugins. A
// finding names the rule, the file and the line, and never the text: it is the
// file's own content, possibly written by an attacker, and the report is made
// to be handed on.

type definitionSource struct {
	client, scope, assetType, key string
	dir                           string
	parts                         []definition.Part
}

var ruleTitles = func() map[string]string {
	m := map[string]string{}
	for _, r := range defscan.Rules() {
		m[r.ID] = r.Title
	}
	return m
}()

// ruleSeverity is a defscan finding as an Item severity: only a rule the
// corpus holds to high confidence makes a severe one dangerous, since honest
// project docs say much of what the rest look for.
func ruleSeverity(severity, confidence string) string {
	switch {
	case severity == defscan.SeverityHigh && confidence == defscan.ConfidenceHigh:
		return Dangerous
	case severity == defscan.SeverityHigh && confidence == defscan.ConfidenceMedium,
		severity == defscan.SeverityMedium && confidence == defscan.ConfidenceHigh:
		return Suspicious
	}
	return Info
}

func (s *scan) instructionItems(skip map[string]bool) []Item {
	var out []Item
	for _, src := range s.definitionSources(skip) {
		s.read[AreaInstructions] = true
		seen := map[string]bool{}
		for _, f := range defscan.Scan(definition.Build(src.assetType, src.key, definition.SourceConfigScan, src.parts)) {
			area := AreaInstructions
			if strings.HasSuffix(f.PartName, "hooks.json") {
				area = AreaHooks
				s.read[AreaHooks] = true
			}
			loc := DisplayHome(s.env.Home, filepath.Join(src.dir, filepath.FromSlash(f.PartName)))
			if seen[f.Rule+"\x00"+loc] {
				continue
			}
			seen[f.Rule+"\x00"+loc] = true
			title := ruleTitles[f.Rule]
			if title == "" {
				title = f.Rule
			}
			out = append(out, Item{
				Client: src.client, Check: f.Rule, Severity: ruleSeverity(f.Severity, f.Confidence), Area: area,
				Scope: src.scope, Location: loc, Subject: src.key, Line: f.Line,
				Detail: src.key + ": " + strings.ToLower(title[:1]) + title[1:],
			})
		}
	}
	return out
}

func (s *scan) definitionSources(skip map[string]bool) []definitionSource {
	home := s.env.Home
	var out []definitionSource
	file := func(client, scope, path, partName string) {
		if skip[path] {
			return
		}
		b, _, ok := readCapped(path)
		if !ok || len(b) == 0 {
			return
		}
		dir := strings.TrimSuffix(path, filepath.FromSlash(partName))
		out = append(out, definitionSource{client, scope, "instructions", filepath.Base(path), dir,
			[]definition.Part{definition.Text(definition.KindFile, partName, b)}})
	}
	glob := func(client, scope, dir, sub, pattern string) {
		matches, _ := filepath.Glob(filepath.Join(dir, sub, pattern))
		sort.Strings(matches)
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.Mode().IsRegular() {
				file(client, scope, m, sub+"/"+filepath.Base(m))
			}
		}
	}
	skills := func(client, scope, root string, depth int) {
		for _, dir := range NestedSkillDirs(root, depth) {
			if skip[filepath.Join(dir, "SKILL.md")] {
				continue
			}
			name := filepath.Base(dir)
			if b, _, ok := readCapped(filepath.Join(dir, "SKILL.md")); ok {
				if n := FrontmatterName(b); n != "" {
					name = n
				}
			}
			out = append(out, definitionSource{client, scope, "skill", name, dir, DefinitionFiles(home, dir, nil)})
		}
	}

	claude := filepath.Join(home, ".claude")
	file("claude-code", "user", filepath.Join(claude, "CLAUDE.md"), "CLAUDE.md")
	glob("claude-code", "user", claude, "commands", "*.md")
	glob("claude-code", "user", claude, "agents", "*.md")
	skills("claude-code", "user", filepath.Join(claude, "skills"), 1)
	glob("cursor", "user", filepath.Join(home, ".cursor"), "rules", "*")
	file("gemini-cli", "user", filepath.Join(home, ".gemini", "GEMINI.md"), "GEMINI.md")
	file("windsurf", "user", filepath.Join(home, ".codeium", "windsurf", "memories", "global_rules.md"), "global_rules.md")
	codexHome := filepath.Join(home, ".codex")
	for i, dir := range s.env.CodexHomes {
		if i == 0 {
			codexHome = dir
		}
		file("codex", "user", filepath.Join(dir, "AGENTS.md"), "AGENTS.md")
	}
	for _, r := range ClientSkillRoots(home, codexHome, filepath.Join(home, ".openclaw")) {
		skills(r.Client, "user", r.Dir, r.Depth)
	}

	for _, p := range s.projectRoots() {
		for _, f := range []struct{ client, name string }{
			{"claude-code", "CLAUDE.md"}, {"claude-code", "CLAUDE.local.md"}, {"codex", "AGENTS.md"},
			{"gemini-cli", "GEMINI.md"}, {"cursor", ".cursorrules"}, {"windsurf", ".windsurfrules"},
			{"copilot", ".github/copilot-instructions.md"},
		} {
			file(f.client, "project", filepath.Join(p, filepath.FromSlash(f.name)), f.name)
		}
		glob("claude-code", "project", filepath.Join(p, ".claude"), "commands", "*.md")
		glob("claude-code", "project", filepath.Join(p, ".claude"), "agents", "*.md")
		glob("cursor", "project", filepath.Join(p, ".cursor"), "rules", "*")
		skills("claude-code", "project", filepath.Join(p, ".claude", "skills"), 1)
	}

	for _, root := range InstalledClaudePlugins(home) {
		name := filepath.Base(root)
		if b, _, ok := readCapped(filepath.Join(root, ".claude-plugin", "plugin.json")); ok {
			var m struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(b, &m) == nil && m.Name != "" {
				name = m.Name
			}
		}
		if name == "golem" {
			continue
		}
		out = append(out, definitionSource{"claude-code", "user", "plugin", name, root, DefinitionFiles(home, root, nil)})
	}
	for _, r := range ClientPluginRoots(home, filepath.Join(home, ".openclaw")) {
		entries, err := os.ReadDir(r.Dir)
		if err != nil {
			continue
		}
		client := r.Client
		if client == "gemini" {
			client = "gemini-cli"
		}
		for _, e := range entries {
			dir := filepath.Join(r.Dir, e.Name())
			if !e.IsDir() || e.Name() == "golem" {
				continue
			}
			if _, err := os.Stat(filepath.Join(dir, r.Manifest)); err != nil {
				continue
			}
			out = append(out, definitionSource{client, "user", "plugin", e.Name(), dir, DefinitionFiles(home, dir, nil)})
		}
	}
	return out
}
