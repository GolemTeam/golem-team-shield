package agentposture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
	"github.com/GolemTeam/golem-team-shield/internal/defscan"
)

// The hooks area reads every hook command an agent runs: Claude Code's (user,
// managed and each project's settings), Gemini CLI's, Cursor's, Codex's,
// Devin's (Devin Desktop is what Windsurf became, and its Cascade hooks are
// Devin's) and Antigravity's.
// Each file's commands go through defscan's hook rules as one hooks.json, the
// shape a plugin ships, so a settings hook and a plugin hook are judged alike;
// then the file a command runs is checked on disk.

type hookFile struct {
	client, scope, path, format string
	project                     string
}

type hookCommand struct{ event, matcher, command string }

func (s *scan) hookFiles() []hookFile {
	home := s.env.Home
	out := []hookFile{
		{"claude-code", "user", filepath.Join(home, ".claude", "settings.json"), "claude", ""},
		{"claude-code", "managed", filepath.Join(s.env.ManagedDir, "managed-settings.json"), "claude", ""},
		{"gemini-cli", "user", filepath.Join(home, ".gemini", "settings.json"), "claude", ""},
		{"cursor", "user", filepath.Join(home, ".cursor", "hooks.json"), "cursor", ""},
		{"antigravity", "user", filepath.Join(home, ".gemini", "config", "hooks.json"), "sets", ""},
	}
	for _, dir := range s.env.CodexHomes {
		out = append(out, hookFile{"codex", "user", filepath.Join(dir, "hooks.json"), "claude", ""})
	}
	if dir := s.devinConfigDir(); dir != "" {
		out = append(out, hookFile{"devin", "user", filepath.Join(dir, "config.json"), "claude", ""})
	}
	for _, p := range s.projectRoots() {
		out = append(out,
			hookFile{"claude-code", "project", filepath.Join(p, ".claude", "settings.json"), "claude", p},
			hookFile{"claude-code", "local", filepath.Join(p, ".claude", "settings.local.json"), "claude", p},
			hookFile{"gemini-cli", "project", filepath.Join(p, ".gemini", "settings.json"), "claude", p},
			hookFile{"cursor", "project", filepath.Join(p, ".cursor", "hooks.json"), "cursor", p},
			hookFile{"devin", "project", filepath.Join(p, ".devin", "config.json"), "claude", p},
			hookFile{"devin", "local", filepath.Join(p, ".devin", "config.local.json"), "claude", p},
			hookFile{"devin", "project", filepath.Join(p, ".devin", "hooks.v1.json"), "bare", p})
	}
	return out
}

// readHookCommands reads a hooks file in the shape its agent writes: Claude
// Code's "hooks" object of events (Gemini CLI, Codex and Devin share it), a
// file that is that object itself (Devin's hooks.v1.json), Cursor's flat
// entries, or Antigravity's named sets of events.
func (s *scan) readHookCommands(path, format string) []hookCommand {
	m := s.readSettings(path)
	switch format {
	case "bare":
		return hookCommandsOf(m, "claude")
	case "sets":
		var out []hookCommand
		for _, set := range sortedAnyKeys(m) {
			if events, ok := m[set].(map[string]any); ok {
				out = append(out, hookCommandsOf(events, "claude")...)
			}
		}
		return out
	}
	hooks, _ := m["hooks"].(map[string]any)
	return hookCommandsOf(hooks, format)
}

func hookCommandsOf(hooks map[string]any, format string) []hookCommand {
	var out []hookCommand
	for _, event := range sortedAnyKeys(hooks) {
		entries, _ := hooks[event].([]any)
		for _, e := range entries {
			entry, _ := e.(map[string]any)
			if format == "cursor" {
				if c, _ := entry["command"].(string); c != "" {
					out = append(out, hookCommand{event, "", c})
				}
				continue
			}
			matcher, _ := entry["matcher"].(string)
			inner, _ := entry["hooks"].([]any)
			for _, h := range inner {
				hm, _ := h.(map[string]any)
				if t, _ := hm["type"].(string); t != "command" {
					continue
				}
				if c, _ := hm["command"].(string); c != "" {
					out = append(out, hookCommand{event, matcher, c})
				}
			}
		}
	}
	return out
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	hiddenErrorsRE = regexp.MustCompile(`\|\|\s*(true|:)\s*$|;\s*exit\s+0\s*$|2>\s*/dev/null`)
	hookRunners    = map[string]bool{"sh": true, "bash": true, "zsh": true, "python": true, "python3": true, "node": true,
		"bun": true, "deno": true, "ruby": true, "perl": true, "pwsh": true, "powershell": true, "uv": true}
)

// golemHook is a hook Golem installed, which is reported as a protection
// rather than reviewed.
func golemHook(command string) bool {
	f := strings.Fields(command)
	return len(f) > 0 && (strings.HasPrefix(exeName(f[0]), "golem") || strings.Contains(command, "/.golem/"))
}

// hookScript is the file a hook command runs, when it names one by path: the
// command itself, or the script an interpreter is given. A bare program name is
// found on PATH by the shell and is not looked up here.
func hookScript(command, home, project string) string {
	f := strings.Fields(command)
	for len(f) > 0 && strings.Contains(f[0], "=") && !strings.ContainsAny(f[0], "/\\") {
		f = f[1:]
	}
	if len(f) > 1 && hookRunners[exeName(f[0])] && !strings.HasPrefix(f[1], "-") {
		f = f[1:]
	}
	if len(f) == 0 {
		return ""
	}
	p := strings.Trim(f[0], `"'`)
	switch {
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(home, p[2:])
	case strings.HasPrefix(p, "$HOME/"), strings.HasPrefix(p, "${HOME}/"):
		p = filepath.Join(home, p[strings.Index(p, "/")+1:])
	case strings.HasPrefix(p, "$CLAUDE_PROJECT_DIR/"), strings.HasPrefix(p, "${CLAUDE_PROJECT_DIR}/"):
		if project == "" {
			return ""
		}
		p = filepath.Join(project, p[strings.Index(p, "/")+1:])
	case strings.Contains(p, "$"):
		return ""
	case filepath.IsAbs(p), strings.HasPrefix(p, "/"), strings.HasPrefix(p, `\`):
	case strings.Contains(p, "/") && project != "":
		p = filepath.Join(project, p)
	default:
		return ""
	}
	return filepath.Clean(p)
}

func (s *scan) hookItems() []Item {
	var out []Item
	for _, hf := range s.hookFiles() {
		cmds := s.readHookCommands(hf.path, hf.format)
		var theirs []hookCommand
		for _, c := range cmds {
			if !golemHook(c.command) {
				theirs = append(theirs, c)
			}
		}
		if len(cmds) > 0 {
			s.read[AreaHooks] = true
		}
		if len(theirs) == 0 {
			continue
		}
		loc := s.display(hf.path)
		add := func(check, sev, subject, detail string) {
			out = append(out, Item{Client: hf.client, Check: check, Severity: sev, Area: AreaHooks, Scope: hf.scope,
				Location: loc, Subject: subject, Detail: detail})
		}
		// hooks.json carries the events, for the every-call rule; the same
		// commands as a script get the script rules, such as env harvesting.
		var body strings.Builder
		for _, c := range theirs {
			body.WriteString(c.command + "\n")
		}
		parts := []definition.Part{
			definition.Text(definition.KindFile, "hooks.json", claudeShapedHooks(theirs)),
			definition.Text(definition.KindFile, "hooks.sh", []byte(body.String())),
		}
		seen := map[string]bool{}
		for _, f := range defscan.Scan(definition.Build("plugin", hf.client, definition.SourceConfigScan, parts)) {
			if seen[f.Rule] {
				continue
			}
			seen[f.Rule] = true
			title := ruleTitles[f.Rule]
			if title == "" {
				title = f.Rule
			}
			add(f.Rule, ruleSeverity(f.Severity, f.Confidence), "", "a hook: "+strings.ToLower(title[:1])+title[1:])
		}
		for _, c := range theirs {
			if hiddenErrorsRE.MatchString(strings.TrimSpace(c.command)) {
				add("hook_errors_hidden", Info, c.event, "a "+c.event+" hook hides its own failures, so a broken check looks like a passing one")
			}
			script := hookScript(c.command, s.env.Home, hf.project)
			if script == "" {
				continue
			}
			shown := s.display(script)
			info, err := os.Stat(script)
			switch {
			case os.IsNotExist(err):
				add("hook_script_missing", Suspicious, c.event,
					fmt.Sprintf("a %s hook runs %s, which does not exist, so whatever is put there next will run", c.event, shown))
			case err == nil && unixModes && othersCanWrite(script, info):
				add("hook_script_writable", Dangerous, c.event,
					fmt.Sprintf("a %s hook runs %s, which other users on this machine can change", c.event, shown))
			}
		}
	}
	return out
}

// othersCanWrite is a file, or the directory holding it, that group or other
// can write to. A sticky directory such as /tmp lets others add files but not
// replace this one, so it does not count.
func othersCanWrite(path string, info os.FileInfo) bool {
	if info.Mode().Perm()&0o022 != 0 {
		return true
	}
	dir, err := os.Stat(filepath.Dir(path))
	return err == nil && dir.Mode().Perm()&0o022 != 0 && dir.Mode()&os.ModeSticky == 0
}

func claudeShapedHooks(cmds []hookCommand) []byte {
	type cmd struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	}
	type group struct {
		Matcher string `json:"matcher,omitempty"`
		Hooks   []cmd  `json:"hooks"`
	}
	doc := struct {
		Hooks map[string][]group `json:"hooks"`
	}{map[string][]group{}}
	for _, c := range cmds {
		doc.Hooks[c.event] = append(doc.Hooks[c.event], group{c.matcher, []cmd{{"command", c.command}}})
	}
	b, _ := json.Marshal(doc)
	return b
}
