package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
	"github.com/GolemTeam/golem-team-shield/shield"
)

// The agents other than Claude Code reach the jail through their pre-tool
// hook (docs/design-local-shield.md, Other clients). With no Golem agent,
// golem-exec registers itself as that hook, and the hook does only the
// rewrite: `golem-exec hook <client>`.

func (s *setup) codexHomes() []string { return shield.CodexHomes(s.home, s.codexHome) }

func (s *setup) hookCommand(client string) string {
	return filepath.Join(s.binDir(), "golem-exec") + " hook " + client
}

// agentHook is one agent golem-exec registers its hook with: the files to
// edit, each only where the agent is installed.
type agentHook struct {
	label string
	files []string
	wire  func(*jsonobject.Object) ([]string, error)
	undo  func(*jsonobject.Object) ([]string, error)
}

func (s *setup) agentHooks() []agentHook {
	codex := shield.CodexHook{Command: s.hookCommand("codex")}
	var codexFiles []string
	for _, dir := range s.codexHomes() {
		if shield.CodexInstalled(dir) {
			codexFiles = append(codexFiles, filepath.Join(dir, "hooks.json"))
		}
	}
	gemini := shield.GeminiHook{Command: s.hookCommand("gemini-cli")}
	var geminiFiles []string
	if shield.GeminiInstalled(s.home) {
		geminiFiles = []string{filepath.Join(s.home, ".gemini", "settings.json")}
	}
	cursor := shield.CursorHook{Command: s.hookCommand("cursor")}
	var cursorFiles []string
	if shield.CursorInstalled(s.home) {
		cursorFiles = []string{filepath.Join(s.home, ".cursor", "hooks.json")}
	}
	return []agentHook{
		{"Codex", codexFiles, codex.Wire, codex.Unwire},
		{"Gemini CLI", geminiFiles, gemini.Wire, gemini.Unwire},
		{"Cursor", cursorFiles, cursor.Wire, cursor.Unwire},
	}
}

// wireAgents adds or removes golem-exec's hook in each agent installed here,
// and says what it changed. Those agents run PowerShell on Windows, which the
// jail doesn't cover, so they are left alone there.
func (s *setup) wireAgents(remove bool) int {
	if s.goos == "windows" {
		return 0
	}
	code := 0
	for _, a := range s.agentHooks() {
		edit := a.wire
		if remove {
			edit = a.undo
		}
		for _, p := range a.files {
			changes, err := s.editJSON(p, edit)
			if err != nil {
				fmt.Fprintf(s.stderr, "golem-exec: could not edit %s: %v\n", p, err)
				code = 1
				continue
			}
			for _, c := range changes {
				fmt.Fprintf(s.stdout, "%s: %s\n", a.label, c)
			}
		}
	}
	return code
}

func (s *setup) editJSON(path string, edit func(*jsonobject.Object) ([]string, error)) ([]string, error) {
	doc, _, err := jsonobject.ReadFile(path)
	if err != nil {
		return nil, err
	}
	changes, err := edit(doc)
	if err != nil || len(changes) == 0 {
		return nil, err
	}
	return changes, jsonobject.WriteFile(path, doc)
}

// hook answers a client's pre-tool hook with its command rewritten into the
// jail. It exits 0 with nothing to say for anything it can't read, as the
// client then runs the call unchanged; a command it reads but can't wrap is
// refused by the answer itself.
func (s *setup) hook(args []string) int {
	if len(args) != 1 || (args[0] != "codex" && args[0] != "gemini-cli" && args[0] != "cursor") {
		fmt.Fprintln(s.stderr, "usage: golem-exec hook codex|gemini-cli|cursor")
		return 2
	}
	var in map[string]any
	if err := json.NewDecoder(io.LimitReader(s.stdin, 5<<20)).Decode(&in); err != nil {
		return 0
	}
	var out map[string]any
	switch args[0] {
	case "codex":
		if shim := shield.HookShim(s.home, s.loginShell); s.shimRuns(shim) {
			out = shield.CodexRewrite(shim, in)
		}
	case "cursor":
		if shim := shield.HookShim(s.home, s.loginShell); s.shimRuns(shim) {
			out = shield.CursorRewrite(shim, in)
		}
	case "gemini-cli":
		if shim := filepath.Join(shield.HookShimDir(s.home), "bash"); s.shimRuns(shim) {
			if out = shield.GeminiRewrite(shim, in); out != nil {
				shield.NoteGeminiSession(s.home, in)
			}
		}
	}
	if out != nil {
		b, _ := json.Marshal(out)
		fmt.Fprintln(s.stdout, string(b))
	}
	return 0
}

func (s *setup) shimRuns(shim string) bool {
	return s.goos != "windows" && shield.ReadyShim(s.goos)(shim)
}
