// Package agentposture reads how the AI coding agents on a machine are set up to
// run, from their own settings files, and reports the settings that let them
// act without asking: permission prompts off, every command allowed, no
// sandbox. It covers Claude Code (including its managed and MDM policy),
// Cursor, Codex, Gemini CLI, Devin, and the VS Code family of editors.
//
// It reads files and nothing else: no network, no processes, and it never
// reports a file's contents, only a setting's name and a value from a fixed
// vocabulary.
package agentposture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Severity of an Item. Dangerous means an agent runs commands or tools without
// asking; suspicious means a setting that weakens a safeguard; info is worth
// knowing and not a risk on its own.
const (
	Info       = "info"
	Suspicious = "suspicious"
	Dangerous  = "dangerous"
)

const (
	// MaxItems caps one scan's report.
	MaxItems = 200
	// MaxFileBytes is the largest settings file read; a bigger one is skipped
	// rather than read in part.
	MaxFileBytes = 1 << 20
	// MaxProjects caps the repositories whose own settings are read.
	MaxProjects = 200
)

// Item is one finding: a setting an agent is configured with, where it is set,
// and what it means. It names a setting and its value, never a file's
// contents, and every Value comes from a fixed vocabulary.
type Item struct {
	// Client is the agent: claude-code, cursor, codex, gemini-cli, devin,
	// vscode, vscode-insiders, vscodium, windsurf or antigravity.
	Client string `json:"client,omitempty"`
	// Check names the finding, e.g. bypass_default, run_everything or
	// full_access.
	Check    string `json:"check,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Area is the report section (areas.go).
	Area string `json:"area,omitempty"`
	// Subject is the MCP server, hook event, skill or plugin a finding is
	// about, where it is about one.
	Subject string `json:"subject,omitempty"`
	// Scope is where the setting applies: managed, user, project or local.
	Scope string `json:"scope,omitempty"`
	// Location is the file, with the home directory shown as ~, or a registry
	// key on Windows.
	Location string `json:"location,omitempty"`
	Setting  string `json:"setting,omitempty"`
	Value    string `json:"value,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// Env is what a scan reads from. DefaultEnv fills it for the current machine;
// tests and callers that know more (repositories an agent was seen working in,
// a CODEX_HOME recorded elsewhere) set the fields directly.
type Env struct {
	Home    string
	GOOS    string
	AppData string // %APPDATA% on Windows
	XDG     string // $XDG_CONFIG_HOME
	// ManagedDir holds Claude Code's managed-settings.json.
	ManagedDir string
	// GeminiSystem is Gemini CLI's system-wide settings file.
	GeminiSystem string
	// CodexHomes are the directories a Codex here may read config.toml from.
	CodexHomes []string
	// ManagedPrefs are the macOS managed-preferences plists for Claude Code.
	ManagedPrefs []string
	// Registry reads Claude Code's policy from the Windows registry hive "HKLM"
	// or "HKCU"; nil elsewhere.
	Registry func(hive string) map[string]any
	// Projects are repositories agents were seen working in, beyond the ones
	// ~/.claude.json lists.
	Projects []string
}

// DefaultEnv is the current machine's Env.
func DefaultEnv() Env {
	home := userHome()
	env := Env{Home: home, GOOS: runtime.GOOS, AppData: os.Getenv("APPDATA"), XDG: os.Getenv("XDG_CONFIG_HOME")}
	switch env.GOOS {
	case "darwin":
		env.ManagedDir = "/Library/Application Support/ClaudeCode"
		env.ManagedPrefs = managedPrefsPaths()
		env.GeminiSystem = "/Library/Application Support/GeminiCli/settings.json"
	case "windows":
		env.ManagedDir = `C:\Program Files\ClaudeCode`
		env.Registry = claudeRegistryPolicy
		env.GeminiSystem = `C:\ProgramData\gemini-cli\settings.json`
	default:
		env.ManagedDir = "/etc/claude-code"
		env.GeminiSystem = "/etc/gemini-cli/settings.json"
	}
	if home != "" {
		env.CodexHomes = defaultCodexHomes(home)
	}
	return env
}

func userHome() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// defaultCodexHomes is $CODEX_HOME, then ~/.codex.
func defaultCodexHomes(home string) []string {
	dirs := []string{filepath.Join(home, ".codex")}
	if d := os.Getenv("CODEX_HOME"); d != "" && filepath.Clean(d) != dirs[0] {
		dirs = append([]string{filepath.Clean(d)}, dirs...)
	}
	return dirs
}

type scan struct {
	env    Env
	items  []Item
	agents map[string]bool
	read   map[string]bool
}

// Scan reads every supported agent's settings and returns what it finds,
// worst first, at most MaxItems. It only reads files.
func Scan(env Env) []Item {
	if s := scanEnv(env); s != nil {
		return s.items
	}
	return nil
}

func scanEnv(env Env) *scan {
	if env.Home == "" {
		return nil
	}
	s := &scan{env: env, agents: map[string]bool{}, read: map[string]bool{}}
	s.claudeCode()
	s.cursorCLI()
	s.codex()
	s.gemini()
	s.editors()
	s.editorState()
	s.devin()
	s.projectSettings()
	Sort(s.items)
	if len(s.items) > MaxItems {
		s.items = s.items[:MaxItems]
	}
	return s
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Rank orders severities: dangerous first.
func Rank(severity string) int {
	switch severity {
	case Dangerous:
		return 0
	case Suspicious:
		return 1
	}
	return 2
}

// Sort orders items worst first, then by agent, check and location, so the
// same machine always reports in the same order.
func Sort(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if ra, rb := Rank(a.Severity), Rank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Location < b.Location
	})
}

func (s *scan) add(client, check, sev, scope, path, setting, value, detail string) {
	s.items = append(s.items, Item{
		Client: client, Check: check, Severity: sev, Area: areaOf(check), Scope: scope, Location: s.display(path),
		Setting: setting, Value: value, Detail: detail,
	})
}

// readCapped reads a regular file of at most MaxFileBytes.
func readCapped(path string) ([]byte, os.FileInfo, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
		return nil, nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false
	}
	return b, info, true
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func (s *scan) display(path string) string {
	sep := string(filepath.Separator)
	if s.env.Home != "" && strings.HasPrefix(path, s.env.Home+sep) {
		return "~" + sep + strings.TrimPrefix(path, s.env.Home+sep)
	}
	return path
}

func readSettings(path string) map[string]any {
	b, _, ok := readCapped(path)
	if !ok {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(StripJSONC(b), &m) != nil {
		return nil
	}
	return m
}

// StripJSONC removes // and /* */ comments and trailing commas outside
// strings: VS Code's and Gemini's settings files allow both.
func StripJSONC(b []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(b) {
				i++
				out.WriteByte(b[i])
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

func lookup(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[k]
	}
	return cur
}

func lookupString(m map[string]any, keys ...string) string {
	s, _ := lookup(m, keys...).(string)
	return s
}

func lookupBool(m map[string]any, keys ...string) (value, set bool) {
	b, ok := lookup(m, keys...).(bool)
	return b, ok
}

func lookupStrings(m map[string]any, keys ...string) []string {
	arr, _ := lookup(m, keys...).([]any)
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

type settingsFile struct {
	scope, path string
	m           map[string]any
}

// claudeSettingsFiles lists Claude Code's settings that apply, highest
// precedence first, because the sandbox default is the first one that sets it.
func (s *scan) claudeSettingsFiles() []settingsFile {
	var out []settingsFile
	add := func(scope, path string) {
		if m := readSettings(path); m != nil {
			out = append(out, settingsFile{scope, path, m})
		}
	}
	out = append(out, s.claudeManagedFiles()...)
	add("user", filepath.Join(s.env.Home, ".claude", "settings.json"))
	for _, p := range s.projectRoots() {
		add("local", filepath.Join(p, ".claude", "settings.local.json"))
		add("project", filepath.Join(p, ".claude", "settings.json"))
	}
	return out
}

func claudeCodeInUse(home string) bool {
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
		return true
	}
	return isDir(filepath.Join(home, ".claude"))
}

var claudeShellRules = map[string]bool{"Bash": true, "Bash(*)": true, "Bash(:*)": true, "Bash(*:*)": true}

func (s *scan) claudeCode() {
	const client = "claude-code"
	if !claudeCodeInUse(s.env.Home) {
		return
	}
	s.agents[client] = true
	files := s.claudeSettingsFiles()
	bypassRefused := false
	for _, f := range files {
		applied := f.scope == "managed" || strings.HasPrefix(f.path, `HKCU\`)
		if applied && lookupString(f.m, "permissions", "disableBypassPermissionsMode") == "disable" {
			bypassRefused = true
		}
	}
	const refused = ", but managed settings refuse bypass mode, so it has no effect"
	sandbox, sandboxSet := false, false
	sandboxScope, sandboxPath := "user", filepath.Join(s.env.Home, ".claude", "settings.json")
	for _, f := range files {
		if lookupString(f.m, "permissions", "defaultMode") == "bypassPermissions" {
			sev, detail := Dangerous, "every Claude Code session starts with permission prompts off"
			if f.scope == "project" || f.scope == "local" {
				sev, detail = Suspicious, "a project setting turns permission prompts off; Claude Code before 2.1.257 obeys it"
			}
			if bypassRefused {
				sev, detail = Info, detail+refused
			}
			s.add(client, "bypass_default", sev, f.scope, f.path, "permissions.defaultMode", "bypassPermissions", detail)
		}
		// Claude Code reads this key from user, local and managed settings
		// only, so a repo cannot set it.
		if v, _ := lookupBool(f.m, "skipDangerousModePermissionPrompt"); v && f.scope != "project" {
			sev, detail := Suspicious, "someone accepted the bypass-mode warning here, so bypass sessions start without it"
			if bypassRefused {
				sev, detail = Info, detail+refused
			}
			s.add(client, "bypass_accepted", sev, f.scope, f.path, "skipDangerousModePermissionPrompt", "true", detail)
		}
		for _, rule := range lookupStrings(f.m, "permissions", "allow") {
			if claudeShellRules[strings.ReplaceAll(rule, " ", "")] {
				s.add(client, "shell_allowed", Suspicious, f.scope, f.path, "permissions.allow", rule,
					"any shell command runs without asking")
				break
			}
		}
		// A project's sandbox setting is that project's, not the machine's
		// default.
		if !sandboxSet && (f.scope == "managed" || f.scope == "user") {
			if v, ok := lookupBool(f.m, "sandbox", "enabled"); ok {
				sandbox, sandboxSet, sandboxScope, sandboxPath = v, true, f.scope, f.path
			}
		}
	}
	if sandbox {
		s.add(client, "agent_sandbox", Info, sandboxScope, sandboxPath, "sandbox.enabled", "true",
			"shell commands run in Claude Code's sandbox")
	} else {
		s.add(client, "no_sandbox", Info, sandboxScope, sandboxPath, "sandbox.enabled", "false",
			"shell commands run without Claude Code's sandbox")
	}
}

func (s *scan) cursorCLI() {
	const client = "cursor"
	path := filepath.Join(s.env.Home, ".cursor", "cli-config.json")
	m := readSettings(path)
	if m == nil {
		return
	}
	s.agents[client] = true
	switch lookupString(m, "approvalMode") {
	case "unrestricted":
		s.add(client, "run_everything", Dangerous, "user", path, "approvalMode", "unrestricted",
			"Cursor's CLI runs every command without asking")
	case "auto-review":
		s.add(client, "auto_review", Info, "user", path, "approvalMode", "auto-review",
			"Cursor's CLI lets a model approve commands instead of asking")
	}
	switch lookupString(m, "sandbox", "mode") {
	case "disabled":
		s.add(client, "no_sandbox", Info, "user", path, "sandbox.mode", "disabled",
			"Cursor's CLI runs commands without its sandbox")
	case "enabled":
		s.add(client, "agent_sandbox", Info, "user", path, "sandbox.mode", "enabled",
			"Cursor's CLI runs commands in its sandbox")
	}
}

// codexTOML holds scalar keys per table: "" is the top level.
type codexTOML map[string]map[string]string

// readCodexTOML reads `key = value` lines per table. Like
// parseCodexMCPServers it is not a TOML parser: it reads the few scalar keys
// these checks need, and files a dotted top-level key under its table.
func readCodexTOML(path string) codexTOML {
	b, _, ok := readCapped(path)
	if !ok {
		return nil
	}
	out := codexTOML{}
	table := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), MaxFileBytes)
	for sc.Scan() {
		line := strings.TrimSpace(stripTOMLComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			table = strings.TrimSpace(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
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
		if out[t] == nil {
			out[t] = map[string]string{}
		}
		out[t][k] = v
	}
	return out
}

func (s *scan) codex() {
	const client = "codex"
	sandboxed := ""
	for _, dir := range s.env.CodexHomes {
		path := filepath.Join(dir, "config.toml")
		if isDir(dir) {
			s.agents[client] = true
			if sandboxed == "" {
				sandboxed = path
			}
		}
		if doc := readCodexTOML(path); doc != nil {
			if doc[""]["sandbox_mode"] == "danger-full-access" {
				sandboxed = "-"
			}
			tables := make([]string, 0, len(doc))
			for t := range doc {
				tables = append(tables, t)
			}
			sort.Strings(tables)
			for _, t := range tables {
				switch {
				case t == "":
					s.codexTable(client, "user", path, "", doc[t])
				case strings.HasPrefix(t, "profiles."):
					s.codexTable(client, "user", path, strings.TrimPrefix(t, "profiles."), doc[t])
				case t == "sandbox_workspace_write" && doc[t]["network_access"] == "true":
					s.add(client, "network_open", Info, "user", path, "sandbox_workspace_write.network_access", "true",
						"commands in Codex's sandbox can reach the network")
				}
			}
		}
		profiles, _ := filepath.Glob(filepath.Join(dir, "*.config.toml"))
		sort.Strings(profiles)
		for _, p := range profiles {
			if doc := readCodexTOML(p); doc != nil {
				s.codexTable(client, "user", p, strings.TrimSuffix(filepath.Base(p), ".config.toml"), doc[""])
			}
		}
	}
	// Codex sandboxes commands unless its default says otherwise; a profile
	// that turns the sandbox off is reported as its own finding.
	if sandboxed != "" && sandboxed != "-" {
		s.add(client, "agent_sandbox", Info, "user", sandboxed, "sandbox_mode", "default",
			"Codex runs commands in its sandbox by default")
	}
}

func (s *scan) codexTable(client, scope, path, profile string, t map[string]string) {
	if t == nil {
		return
	}
	prefix, where := "", ""
	if profile != "" {
		prefix, where = "profiles."+profile+".", " in profile "+profile
	}
	never := t["approval_policy"] == "never"
	if t["sandbox_mode"] == "danger-full-access" {
		detail := "Codex runs commands with no sandbox" + where
		if never {
			detail += ", and never asks"
		}
		s.add(client, "full_access", Dangerous, scope, path, prefix+"sandbox_mode", "danger-full-access", detail)
	} else if never {
		s.add(client, "never_ask", Info, scope, path, prefix+"approval_policy", "never",
			"Codex never asks"+where+"; its sandbox is the only limit")
	}
}

func (s *scan) gemini() {
	const client = "gemini-cli"
	var files []settingsFile
	if m := readSettings(s.env.GeminiSystem); m != nil {
		files = append(files, settingsFile{"managed", s.env.GeminiSystem, m})
	}
	userPath := filepath.Join(s.env.Home, ".gemini", "settings.json")
	if m := readSettings(userPath); m != nil {
		files = append(files, settingsFile{"user", userPath, m})
	}
	if len(files) == 0 {
		return
	}
	s.agents[client] = true
	yoloRefused := false
	for _, f := range files {
		if v, _ := lookupBool(f.m, "security", "disableYoloMode"); v {
			yoloRefused = true
		}
		for _, t := range lookupStrings(f.m, "tools", "allowed") {
			if strings.TrimSpace(t) == "run_shell_command" {
				s.add(client, "shell_allowed", Suspicious, f.scope, f.path, "tools.allowed", t,
					"any shell command runs without asking")
				break
			}
		}
		if v, ok := lookupBool(f.m, "security", "folderTrust", "enabled"); ok && !v {
			s.add(client, "folder_trust_off", Suspicious, f.scope, f.path, "security.folderTrust.enabled", "false",
				"a cloned repo's Gemini settings apply without asking")
		}
		if lookupString(f.m, "general", "defaultApprovalMode") == "auto_edit" {
			s.add(client, "auto_edit_default", Info, f.scope, f.path, "general.defaultApprovalMode", "auto_edit",
				"file edits run without asking")
		}
	}
	for _, f := range files {
		if geminiSandbox(f.m) {
			s.add(client, "agent_sandbox", Info, f.scope, f.path, "tools.sandbox", "true",
				"Gemini CLI runs tools in its sandbox")
			break
		}
	}
	if !yoloRefused {
		f := files[len(files)-1]
		s.add(client, "yolo_allowed", Info, f.scope, f.path, "security.disableYoloMode", "false",
			"YOLO mode is not disabled, so --yolo runs every tool without asking")
	}
}

// geminiSandbox is tools.sandbox (or the older top-level sandbox) set to true
// or to a sandbox command.
func geminiSandbox(m map[string]any) bool {
	for _, v := range []any{lookup(m, "tools", "sandbox"), lookup(m, "sandbox")} {
		switch v := v.(type) {
		case bool:
			return v
		case string:
			return v != "" && v != "false"
		}
	}
	return false
}

var editorApps = []struct{ client, dir string }{
	{"vscode", "Code"},
	{"vscode-insiders", "Code - Insiders"},
	{"vscodium", "VSCodium"},
	{"cursor", "Cursor"},
	{"windsurf", "Windsurf"},
	{"antigravity", "Antigravity"},
}

// aiEditors are the editors built around an agent. VS Code and its forks are
// not counted as agents on their settings alone.
var aiEditors = map[string]bool{"cursor": true, "windsurf": true, "antigravity": true}

func (s *scan) editorBase() string {
	switch s.env.GOOS {
	case "darwin":
		return filepath.Join(s.env.Home, "Library", "Application Support")
	case "windows":
		return s.env.AppData
	}
	if s.env.XDG != "" {
		return s.env.XDG
	}
	return filepath.Join(s.env.Home, ".config")
}

func (s *scan) editors() {
	base := s.editorBase()
	if base == "" {
		return
	}
	for _, app := range editorApps {
		path := filepath.Join(base, app.dir, "User", "settings.json")
		m := readSettings(path)
		if m == nil {
			continue
		}
		if aiEditors[app.client] {
			s.agents[app.client] = true
		}
		// VS Code keeps settings as flat dotted keys, not nested objects.
		for _, key := range []string{"chat.tools.global.autoApprove", "chat.tools.autoApprove"} {
			if v, _ := m[key].(bool); v {
				s.add(app.client, "tools_auto_approve", Dangerous, "user", path, key, "true",
					"the editor's agent runs every tool without asking")
				break
			}
		}
		if v, ok := m["security.workspace.trust.enabled"].(bool); ok && !v {
			s.add(app.client, "workspace_trust_off", Suspicious, "user", path, "security.workspace.trust.enabled", "false",
				"every folder opens trusted, so its tasks and extensions run without asking")
		}
	}
}

// devinConfigDir is where Devin (the CLI, and Devin Desktop) keeps its user
// config.json.
func (s *scan) devinConfigDir() string {
	if s.env.GOOS == "windows" {
		if s.env.AppData == "" {
			return ""
		}
		return filepath.Join(s.env.AppData, "devin")
	}
	return filepath.Join(s.env.Home, ".config", "devin")
}

// devinShellAllowed reports a Devin config that allows the exec tool outright:
// every shell command then runs without asking. Exec(<prefix>) rules allow only
// that command and are not findings.
func (s *scan) devinShellAllowed(scope, path, repo string) {
	m := readSettings(path)
	if m == nil {
		return
	}
	for _, rule := range lookupStrings(m, "permissions", "allow") {
		if strings.EqualFold(strings.TrimSpace(rule), "exec") {
			detail := "Devin runs any shell command without asking"
			if repo != "" {
				detail = "the " + repo + " repo lets Devin run any shell command without asking"
			}
			s.add("devin", "shell_allowed", Suspicious, scope, path, "permissions.allow", rule, detail)
			return
		}
	}
}

func (s *scan) devin() {
	if dir := s.devinConfigDir(); dir != "" {
		if isDir(dir) {
			s.agents["devin"] = true
		}
		s.devinShellAllowed("user", filepath.Join(dir, "config.json"), "")
	}
	for _, root := range s.projectRoots() {
		repo := filepath.Base(root)
		s.devinShellAllowed("project", filepath.Join(root, ".devin", "config.json"), repo)
		s.devinShellAllowed("local", filepath.Join(root, ".devin", "config.local.json"), repo)
	}
}
