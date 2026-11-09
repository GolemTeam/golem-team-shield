package agentposture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

// PlanFixes only reads: writing the plan, backing it up and putting it back
// are checkcmd's, so this package keeps its read-only promise.
//
// A run mode or allow rule that stops an agent asking goes back to the agent's
// default, which asks, so nothing the agent could do is lost. A credential file
// or hook script other users can read or change loses those permission bits and
// keeps its contents. A plaintext secret stays where it is: moving it means
// choosing where it lives instead, and that is the person's choice.

type FileFix struct {
	Path     string
	Location string
	// Format is "" when only the permissions change, and Old and New are nil.
	Format           string
	Old, New         []byte
	OldMode, NewMode os.FileMode
	Changes          []string
	Items            []Item
}

type SkippedFix struct {
	Item   Item
	Reason string
}

type FixPlan struct {
	Files   []FileFix
	Skipped []SkippedFix
}

type fixEdit struct {
	path   string
	change string
	json   func(*jsonobject.Object) bool
	codex  bool
	clear  os.FileMode
}

type fixer func(s *scan, it Item, path string) ([]fixEdit, string)

const (
	tightenSecret = "lets only you read it, since it holds a credential"
	tightenHook   = "stops other users changing it, since an agent runs it"
	codexChange   = `stops Codex running commands with no sandbox (sandbox_mode "danger-full-access")`
)

var fixers = map[string]fixer{
	"claude-code/bypass_default": jsonFix(`stops sessions starting with permission prompts off (permissions.defaultMode "bypassPermissions")`,
		removeIfString("bypassPermissions", "permissions", "defaultMode")),
	"claude-code/bypass_accepted": jsonFix("brings back the warning before a bypass session (skipDangerousModePermissionPrompt)",
		removeIfTrue("skipDangerousModePermissionPrompt")),
	"claude-code/shell_allowed": jsonFix("takes out the allow rule that runs any shell command",
		dropStrings(func(r string) bool { return claudeShellRules[strings.ReplaceAll(r, " ", "")] }, "permissions", "allow")),
	"claude-code/write_allowed": jsonFix("takes out the allow rule that edits any file",
		dropStrings(func(r string) bool { return claudeWriteRE.MatchString(strings.ReplaceAll(r, " ", "")) }, "permissions", "allow")),
	"claude-code/fetch_allowed": jsonFix("takes out the allow rule that fetches any web page",
		dropStrings(func(r string) bool { return claudeFetchRE.MatchString(strings.ReplaceAll(r, " ", "")) }, "permissions", "allow")),
	"claude-code/mcp_all_allowed": jsonFix("takes out the allow rule that calls every MCP tool",
		dropStrings(func(r string) bool { return claudeMCPAllRE.MatchString(strings.ReplaceAll(r, " ", "")) }, "permissions", "allow")),
	"claude-code/project_mcp_auto": jsonFix("stops every repository's MCP servers starting without asking (enableAllProjectMcpServers)",
		removeIfTrue("enableAllProjectMcpServers")),

	"gemini-cli/shell_allowed": jsonFix("takes run_shell_command out of tools.allowed",
		dropStrings(func(t string) bool { return strings.TrimSpace(t) == "run_shell_command" }, "tools", "allowed")),
	"gemini-cli/write_allowed": jsonFix("takes write_file and replace out of tools.allowed",
		dropStrings(func(t string) bool { t = strings.TrimSpace(t); return t == "write_file" || t == "replace" }, "tools", "allowed")),
	"gemini-cli/fetch_allowed": jsonFix("takes web_fetch out of tools.allowed",
		dropStrings(func(t string) bool { return strings.TrimSpace(t) == "web_fetch" }, "tools", "allowed")),
	"gemini-cli/folder_trust_off": jsonFix("turns folder trust on, so a cloned repo's settings ask first (security.folderTrust.enabled)",
		setIfFalse("security", "folderTrust", "enabled")),

	"cursor/run_everything": jsonFix(`stops Cursor's CLI running every command without asking (approvalMode "unrestricted")`,
		removeIfString("unrestricted", "approvalMode")),
	"cursor/write_allowed": jsonFix("takes out the allow rule that edits any file",
		dropStrings(func(r string) bool { return cursorWriteRE.MatchString(strings.ReplaceAll(r, " ", "")) }, "permissions", "allow")),

	"devin/shell_allowed": jsonFix("takes out the allow rule that runs any shell command (exec)",
		dropStrings(func(r string) bool { return strings.EqualFold(strings.TrimSpace(r), "exec") }, "permissions", "allow")),

	"codex/full_access": func(_ *scan, _ Item, path string) ([]fixEdit, string) {
		return []fixEdit{{path: path, codex: true, change: codexChange}}, ""
	},

	"*/credential_file_readable": tightenFix(0o077, tightenSecret),
	"*/config_plaintext_secret":  tightenFix(0o077, tightenSecret),
	"*/mcp_plaintext_secret":     tightenFix(0o077, tightenSecret),
	"*/hook_script_writable":     hookScriptFix,
}

func init() {
	for _, editor := range editorApps {
		fixers[editor.client+"/tools_auto_approve"] = jsonFix("stops the editor's agent running every tool without asking (chat.tools.global.autoApprove)",
			func(o *jsonobject.Object) bool {
				a := removeIfTrue("chat.tools.global.autoApprove")(o)
				return removeIfTrue("chat.tools.autoApprove")(o) || a
			})
		fixers[editor.client+"/workspace_trust_off"] = jsonFix("turns workspace trust back on (security.workspace.trust.enabled)",
			removeIfFalse("security.workspace.trust.enabled"))
	}
}

func fixerFor(it Item) fixer {
	if f := fixers[it.Client+"/"+it.Check]; f != nil {
		return f
	}
	return fixers["*/"+it.Check]
}

func jsonFix(change string, edit func(*jsonobject.Object) bool) fixer {
	return func(_ *scan, _ Item, path string) ([]fixEdit, string) {
		return []fixEdit{{path: path, change: change, json: edit}}, ""
	}
}

func tightenFix(clear os.FileMode, change string) fixer {
	return func(_ *scan, _ Item, path string) ([]fixEdit, string) {
		if !unixModes {
			return nil, ""
		}
		return []fixEdit{{path: path, change: change, clear: clear}}, ""
	}
}

// hookScriptFix reads the hook file again because the item names that file,
// not the script its command runs.
func hookScriptFix(s *scan, it Item, path string) ([]fixEdit, string) {
	if !unixModes {
		return nil, ""
	}
	var edits []fixEdit
	why := ""
	for _, hf := range s.hookFiles() {
		if hf.path != path {
			continue
		}
		for _, c := range s.readHookCommands(hf.path, hf.format) {
			if c.event != it.Subject || golemHook(c.command) {
				continue
			}
			script := hookScript(c.command, s.env.Home, hf.project)
			if script == "" {
				continue
			}
			info, err := os.Stat(script)
			if err != nil || !othersCanWrite(script, info) {
				continue
			}
			if info.Mode().Perm()&0o022 == 0 {
				why = "other users can write to the folder holding " + s.display(script) + ", and -fix changes no folder"
				continue
			}
			edits = append(edits, fixEdit{path: script, change: tightenHook, clear: 0o022})
		}
	}
	return edits, why
}

func refused(home string, it Item) string {
	switch {
	case strings.HasPrefix(it.Location, `HKCU\`) || strings.HasPrefix(it.Location, `HKLM\`):
		return "policy in the registry, which -fix never changes"
	case it.Scope == "managed":
		return "managed policy, which -fix never changes: ask whoever manages this machine"
	case it.Scope == "project", it.Scope == "local" && realPath(home, it.Location) != filepath.Join(home, ".claude.json"):
		return "in a repository's files, which -fix leaves alone: change it in the repository"
	}
	return ""
}

// noFixer says where to change a finding -fix has no change for, so a plan
// with nothing to do never reads as a clean bill of health.
func noFixer(it Item) string {
	name := it.Client
	if n := clientNames[it.Client]; n != "" {
		name = n
	}
	if strings.HasSuffix(it.Location, ".vscdb") {
		return "kept in the app's own database, which -fix never edits: change it in " + name + "'s settings"
	}
	return "-fix has no safe change for this: change it in " + name + "'s settings"
}

var clientNames = map[string]string{
	"claude-code": "Claude Code", "claude-desktop": "Claude Desktop", "cursor": "Cursor", "codex": "Codex",
	"gemini-cli": "Gemini CLI", "copilot": "Copilot CLI", "devin": "Devin", "vscode": "VS Code",
	"vscode-insiders": "VS Code Insiders", "vscodium": "VSCodium", "windsurf": "Windsurf",
	"antigravity": "Antigravity", "openclaw": "OpenClaw", "hermes": "Hermes", "ollama": "Ollama",
}

func realPath(home, location string) string {
	if location == "~" || strings.HasPrefix(location, "~/") || strings.HasPrefix(location, `~\`) {
		return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(location, "~")))
	}
	return filepath.FromSlash(location)
}

type pendingFile struct {
	path  string
	edits []fixEdit
	items []Item
}

// PlanFixes plans the changes that answer the dangerous and suspicious
// findings in the person's own settings on this machine.
func PlanFixes(env Env) FixPlan {
	var plan FixPlan
	if env.Home == "" || env.Repo != "" {
		return plan
	}
	s := &scan{env: env, agents: map[string]bool{}, read: map[string]bool{}}
	files := map[string]*pendingFile{}
	var order []string
	for _, it := range ScanAll(env).Items {
		if Rank(it.Severity) > Rank(Suspicious) {
			continue
		}
		if it.Area == AreaProtections {
			if it.Severity == Dangerous {
				plan.Skipped = append(plan.Skipped, SkippedFix{it, "the jail is required here: run golem-exec install, or golem setup-client where the Golem agent runs"})
			}
			continue
		}
		if why := refused(env.Home, it); why != "" {
			plan.Skipped = append(plan.Skipped, SkippedFix{it, why})
			continue
		}
		f := fixerFor(it)
		if f == nil {
			plan.Skipped = append(plan.Skipped, SkippedFix{it, noFixer(it)})
			continue
		}
		edits, why := f(s, it, realPath(env.Home, it.Location))
		if len(edits) == 0 {
			if why != "" {
				plan.Skipped = append(plan.Skipped, SkippedFix{it, why})
			}
			continue
		}
		for _, e := range edits {
			p := files[e.path]
			if p == nil {
				p = &pendingFile{path: e.path}
				files[e.path] = p
				order = append(order, e.path)
			}
			p.edits = append(p.edits, e)
			p.items = append(p.items, it)
		}
	}
	sort.Strings(order)
	for _, path := range order {
		ff, why := s.planFile(files[path])
		if why != "" {
			for _, it := range uniqueItems(files[path].items) {
				plan.Skipped = append(plan.Skipped, SkippedFix{it, why})
			}
			continue
		}
		if ff != nil {
			plan.Files = append(plan.Files, *ff)
		}
	}
	return plan
}

func uniqueItems(items []Item) []Item {
	var out []Item
	seen := map[string]bool{}
	for _, it := range items {
		k := strings.Join([]string{it.Client, it.Check, it.Location, it.Subject, it.Setting}, "\x00")
		if !seen[k] {
			seen[k] = true
			out = append(out, it)
		}
	}
	return out
}

func (s *scan) planFile(p *pendingFile) (*FileFix, string) {
	info, err := os.Lstat(p.path)
	switch {
	case err != nil:
		return nil, ""
	case info.Mode()&os.ModeSymlink != 0:
		return nil, "a symbolic link, which -fix leaves alone: change the file it points to"
	case !info.Mode().IsRegular():
		return nil, ""
	case info.Size() > MaxFileBytes:
		return nil, "too large to read"
	}
	ff := &FileFix{Path: p.path, Location: s.display(p.path), OldMode: info.Mode().Perm(), NewMode: info.Mode().Perm()}
	var jsonEdits []fixEdit
	var modeChanges []string
	codex := false
	seen := map[string]bool{}
	note := func(change string) {
		if !seen[change] {
			seen[change] = true
			ff.Changes = append(ff.Changes, change)
		}
	}
	for _, e := range p.edits {
		switch {
		case e.json != nil:
			jsonEdits = append(jsonEdits, e)
		case e.codex:
			codex = true
		case ff.NewMode&e.clear != 0:
			ff.NewMode &^= e.clear
			modeChanges = append(modeChanges, e.change)
		}
	}
	if len(jsonEdits) > 0 || codex {
		old, err := os.ReadFile(p.path)
		if err != nil {
			return nil, "could not be read"
		}
		var out []byte
		if codex {
			var n int
			if out, n = codexWithoutFullAccess(old); out == nil {
				return nil, "uses TOML this check does not edit (a multi-line string), so it is left alone: change it by hand"
			}
			if n > 0 {
				note(codexChange)
			}
			ff.Format = "toml"
		} else {
			doc, err := jsonobject.Parse(old)
			if err != nil {
				return nil, "not plain JSON (comments, trailing commas or an error), so it is left alone: change it by hand"
			}
			for _, e := range jsonEdits {
				if e.json(doc) {
					note(e.change)
				}
			}
			if out, err = formatLike(old, doc); err != nil {
				return nil, "could not be written back as JSON"
			}
			ff.Format = "json"
		}
		if bytes.Equal(old, out) {
			ff.Format = ""
		} else {
			ff.Old, ff.New = old, out
		}
	}
	for _, c := range modeChanges {
		note(c)
	}
	if ff.Old == nil && ff.NewMode == ff.OldMode {
		return nil, ""
	}
	ff.Items = uniqueItems(p.items)
	return ff, ""
}

// formatLike lays doc out the way the original was, so the diff shows only
// what changed: one line or indented, its indent, line endings and last
// newline. MarshalJSON is called directly because json.Marshal would escape
// the & in a hook command as &.
func formatLike(orig []byte, doc *jsonobject.Object) ([]byte, error) {
	compact, err := doc.MarshalJSON()
	if err != nil {
		return nil, err
	}
	body := bytes.TrimRight(orig, "\r\n")
	var out bytes.Buffer
	if bytes.ContainsAny(body, "\n") {
		if err := json.Indent(&out, compact, "", indentOf(body)); err != nil {
			return nil, err
		}
	} else {
		out.Write(compact)
	}
	b := out.Bytes()
	if len(body) < len(orig) {
		b = append(b, '\n')
	}
	if bytes.Contains(orig, []byte("\r\n")) {
		b = bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
	}
	return b, nil
}

func indentOf(b []byte) string {
	for _, line := range bytes.Split(b, []byte("\n"))[1:] {
		line = bytes.TrimRight(line, "\r")
		rest := bytes.TrimLeft(line, " \t")
		if len(rest) > 0 && len(rest) < len(line) {
			return string(line[:len(line)-len(rest)])
		}
	}
	return "  "
}

// codexWithoutFullAccess drops each sandbox_mode = "danger-full-access" line
// at the top level or in a profile, read the way readCodexTOML reads keys. A
// file with a multi-line string returns nil: there a line is not always a key.
func codexWithoutFullAccess(b []byte) ([]byte, int) {
	if bytes.Contains(b, []byte(`"""`)) || bytes.Contains(b, []byte(`'''`)) {
		return nil, 0
	}
	var out bytes.Buffer
	table, n := "", 0
	for _, raw := range strings.SplitAfter(string(b), "\n") {
		line := strings.TrimSpace(stripTOMLComment(raw))
		if strings.HasPrefix(line, "[") {
			table = strings.TrimSpace(strings.Trim(line, "[]"))
		} else if k, v, ok := strings.Cut(line, "="); ok {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			t := table
			if t == "" {
				if i := strings.LastIndex(k, "."); i > 0 {
					t, k = k[:i], k[i+1:]
				}
			}
			if s, ok := tomlString(v); ok {
				v = s
			}
			if k == "sandbox_mode" && v == "danger-full-access" && (t == "" || strings.HasPrefix(t, "profiles.")) {
				n++
				continue
			}
		}
		out.WriteString(raw)
	}
	return out.Bytes(), n
}

func editAt(o *jsonobject.Object, path []string, edit func(*jsonobject.Object) bool) bool {
	if len(path) == 0 {
		return edit(o)
	}
	raw, ok := o.Get(path[0])
	if !ok {
		return false
	}
	child, err := jsonobject.Parse(raw)
	if err != nil || !editAt(child, path[1:], edit) {
		return false
	}
	b, err := child.MarshalJSON()
	if err != nil {
		return false
	}
	o.Set(path[0], b)
	return true
}

func atKey(path []string, edit func(obj *jsonobject.Object, key string) bool) func(*jsonobject.Object) bool {
	parents, key := path[:len(path)-1], path[len(path)-1]
	return func(o *jsonobject.Object) bool {
		return editAt(o, parents, func(obj *jsonobject.Object) bool { return edit(obj, key) })
	}
}

func isValue(raw json.RawMessage, want any) bool {
	var v any
	return json.Unmarshal(raw, &v) == nil && v == want
}

func removeIf(want any, path ...string) func(*jsonobject.Object) bool {
	return atKey(path, func(obj *jsonobject.Object, key string) bool {
		raw, ok := obj.Get(key)
		if !ok || !isValue(raw, want) {
			return false
		}
		obj.Remove(key)
		return true
	})
}

func removeIfString(value string, path ...string) func(*jsonobject.Object) bool {
	return removeIf(value, path...)
}

func removeIfTrue(path ...string) func(*jsonobject.Object) bool  { return removeIf(true, path...) }
func removeIfFalse(path ...string) func(*jsonobject.Object) bool { return removeIf(false, path...) }

func setIfFalse(path ...string) func(*jsonobject.Object) bool {
	return atKey(path, func(obj *jsonobject.Object, key string) bool {
		raw, ok := obj.Get(key)
		if !ok || !isValue(raw, false) {
			return false
		}
		obj.Set(key, json.RawMessage("true"))
		return true
	})
}

// dropStrings keeps every other element of the array as its original bytes.
func dropStrings(drop func(string) bool, path ...string) func(*jsonobject.Object) bool {
	return atKey(path, func(obj *jsonobject.Object, key string) bool {
		raw, ok := obj.Get(key)
		if !ok {
			return false
		}
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return false
		}
		var b bytes.Buffer
		b.WriteByte('[')
		kept := 0
		for _, el := range arr {
			var s string
			if json.Unmarshal(el, &s) == nil && drop(s) {
				continue
			}
			if kept > 0 {
				b.WriteByte(',')
			}
			b.Write(el)
			kept++
		}
		if kept == len(arr) {
			return false
		}
		b.WriteByte(']')
		obj.Set(key, b.Bytes())
		return true
	})
}
