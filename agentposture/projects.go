package agentposture

import (
	"path/filepath"
	"sort"
	"strings"
)

// Cursor's CLI, Gemini CLI and Codex each read a settings file inside the
// repository too (.cursor/cli.json, .gemini/settings.json, .codex/config.toml),
// so a cloned repo can switch an agent's prompts off for everyone who opens it.
// Only Claude Code lists the repos it has opened; Env.Projects adds the ones a
// caller learned some other way.

func (s *scan) projectRoots() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range append(ClaudeProjects(s.env.Home), s.env.Projects...) {
		if p != "" && filepath.IsAbs(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	if len(out) > MaxProjects {
		out = out[:MaxProjects]
	}
	return out
}

func (s *scan) projectSettings() {
	for _, root := range s.projectRoots() {
		repo := filepath.Base(root)
		cursor := filepath.Join(root, ".cursor", "cli.json")
		if m := readSettings(cursor); m != nil {
			switch lookupString(m, "approvalMode") {
			case "unrestricted":
				s.add("cursor", "run_everything", Dangerous, "project", cursor, "approvalMode", "unrestricted",
					"the "+repo+" repo makes Cursor's CLI run every command without asking")
			case "auto-review":
				s.add("cursor", "auto_review", Info, "project", cursor, "approvalMode", "auto-review",
					"the "+repo+" repo lets a model approve Cursor's commands")
			}
		}
		gemini := filepath.Join(root, ".gemini", "settings.json")
		if m := readSettings(gemini); m != nil {
			for _, t := range lookupStrings(m, "tools", "allowed") {
				if strings.TrimSpace(t) == "run_shell_command" {
					s.add("gemini-cli", "shell_allowed", Suspicious, "project", gemini, "tools.allowed", t,
						"the "+repo+" repo lets Gemini CLI run any shell command without asking")
					break
				}
			}
			if lookupString(m, "general", "defaultApprovalMode") == "auto_edit" {
				s.add("gemini-cli", "auto_edit_default", Info, "project", gemini, "general.defaultApprovalMode", "auto_edit",
					"the "+repo+" repo lets Gemini CLI edit files without asking")
			}
		}
		codex := filepath.Join(root, ".codex", "config.toml")
		if doc := readCodexTOML(codex); doc != nil {
			s.codexTable("codex", "project", codex, "", doc[""])
		}
	}
}
