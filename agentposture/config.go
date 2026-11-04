package agentposture

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"
)

// The config scan reads what this machine's AI agents are configured to load
// and run: MCP server definitions, hooks, and the instruction files that go
// straight into an agent's context. It only reads files, and it records where
// a secret is, never the secret. The Golem agent runs it on a timer and alerts
// on what is new (witness/agent_scan.go), so a finding's Check, Location,
// Subject and Detail are its alert fingerprint and must not change.

type ConfigFinding struct {
	Client   string
	Scope    string
	Check    string
	Severity string
	Location string // file, with the home directory shown as ~
	Subject  string // the MCP server, hook event or file the finding is about
	Detail   string // what was found; never a secret's value
}

// ConfigScan is a pass of the config scan. Unreadable holds files that exist
// but could not be read or parsed; Partial says ~/.claude.json could not be
// read, so the project list, and with it every project's files, is unknown.
// A caller that remembers findings keeps the ones in those files rather than
// forgetting them, so a file caught mid-write does not re-alert next pass.
type ConfigScan struct {
	Findings   []ConfigFinding
	Unreadable map[string]bool
	Scanned    map[string]bool
	Partial    bool
	Read       map[string]bool
}

type configFile struct{ client, scope, path string }

// The shapes an MCP config comes in besides an mcpServers object.
const (
	mcpFormatVSCode   = "servers"
	mcpFormatCodex    = "codex"
	mcpFormatOpenClaw = "openclaw"
)

type mcpFile struct {
	configFile
	format string
}

type configScanner struct {
	env        Env
	skip       map[string]bool
	out        ConfigScan
	mcpFiles   []mcpFile
	queued     map[string]bool
	extraFiles []configFile
}

// ScanConfig runs the config scan. skip lists files to leave out by path, such
// as the skills Golem installs itself.
func ScanConfig(env Env, skip map[string]bool) ConfigScan {
	s := &configScanner{env: env, skip: skip, out: ConfigScan{
		Unreadable: map[string]bool{}, Scanned: map[string]bool{}, Read: map[string]bool{},
	}}
	if env.Home == "" {
		return s.out
	}
	s.scanClaudeCode()
	for _, p := range env.Projects {
		if filepath.IsAbs(p) && !s.queued[p] {
			s.queueProject(p)
		}
	}
	for _, f := range s.mcpConfigPaths() {
		s.scanMCPFile(f)
	}
	for _, f := range s.instructionFiles() {
		s.scanInstructions(f)
	}
	s.scanClaudeHooks(filepath.Join(env.Home, ".claude", "settings.json"))
	sort.Slice(s.out.Findings, func(i, j int) bool {
		a, b := s.out.Findings[i], s.out.Findings[j]
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Check < b.Check
	})
	return s.out
}

func (s *configScanner) add(f configFile, check, sev, subject, detail string) {
	s.out.Findings = append(s.out.Findings, ConfigFinding{
		Client: f.client, Scope: f.scope, Check: check, Severity: sev,
		Location: s.display(f.path), Subject: subject, Detail: detail,
	})
}

func (s *configScanner) display(path string) string {
	sep := string(filepath.Separator)
	if s.env.Home != "" && strings.HasPrefix(path, s.env.Home+sep) {
		return "~" + sep + strings.TrimPrefix(path, s.env.Home+sep)
	}
	return path
}

// read is readCapped that remembers a file which exists but could not be read.
func (s *configScanner) read(path, area string) ([]byte, os.FileInfo, bool) {
	if s.env.Repo != "" && !within(s.env.Repo, path) {
		return nil, nil, false
	}
	b, info, ok := readCapped(path)
	if ok {
		s.out.Scanned[s.display(path)] = true
		s.out.Read[area] = true
		if area == AreaMCPServers {
			s.out.Read[AreaSecrets] = true
		}
	} else if _, err := os.Stat(path); err == nil {
		s.out.Unreadable[s.display(path)] = true
	}
	return b, info, ok
}

// MCPServer is one configured MCP server, as the clients' configs write it.
type MCPServer struct {
	Type    string // "http", "sse" or "stdio" where the config says
	Command string
	Args    []string
	Env     map[string]string
	URL     string
	Headers map[string]string
}

// UnmarshalJSON keeps the string fields and skips the rest, so one server with
// `"env": {"DEBUG": true}` does not fail the parse of the whole file around it.
func (d *MCPServer) UnmarshalJSON(b []byte) error {
	var raw struct {
		Type      any            `json:"type"`
		Transport any            `json:"transport"`
		Command   any            `json:"command"`
		Args      []any          `json:"args"`
		Env       map[string]any `json:"env"`
		URL       any            `json:"url"`
		Headers   map[string]any `json:"headers"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	d.Type, _ = raw.Type.(string)
	if d.Type == "" {
		d.Type, _ = raw.Transport.(string)
	}
	d.Command, _ = raw.Command.(string)
	d.URL, _ = raw.URL.(string)
	for _, a := range raw.Args {
		if s, ok := a.(string); ok {
			d.Args = append(d.Args, s)
		}
	}
	d.Env, d.Headers = stringValues(raw.Env), stringValues(raw.Headers)
	return nil
}

func stringValues(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// ParseMCPServers reads an mcpServers object entry by entry.
func ParseMCPServers(raw json.RawMessage) map[string]MCPServer {
	var entries map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	out := make(map[string]MCPServer, len(entries))
	for name, e := range entries {
		var d MCPServer
		_ = json.Unmarshal(e, &d)
		out[name] = d
	}
	return out
}

// scanClaudeCode reads ~/.claude.json, and queues the .mcp.json and CLAUDE.md of
// every project Claude Code has opened: those came with a repository, and a
// cloned repo is exactly where a stranger's MCP server or instructions arrive.
func (s *configScanner) scanClaudeCode() {
	f := configFile{"claude-code", "user", filepath.Join(s.env.Home, ".claude.json")}
	b, info, ok := s.read(f.path, AreaMCPServers)
	if !ok {
		s.out.Partial = s.out.Unreadable[s.display(f.path)]
		return
	}
	var doc struct {
		MCPServers json.RawMessage            `json:"mcpServers"`
		Projects   map[string]json.RawMessage `json:"projects"`
	}
	if json.Unmarshal(b, &doc) != nil {
		s.out.Unreadable[s.display(f.path)] = true
		s.out.Partial = true
		return
	}
	s.scanServers(f, info, ParseMCPServers(doc.MCPServers))
	projects := make([]string, 0, len(doc.Projects))
	for p := range doc.Projects {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	for i, p := range projects {
		var proj struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		_ = json.Unmarshal(doc.Projects[p], &proj)
		s.scanServers(configFile{"claude-code", "local", f.path}, info, ParseMCPServers(proj.MCPServers))
		if i >= MaxProjects || !filepath.IsAbs(p) {
			continue
		}
		s.queueProject(p)
	}
}

func (s *configScanner) queueProject(p string) {
	if s.queued == nil {
		s.queued = map[string]bool{}
	}
	s.queued[p] = true
	s.mcpFiles = append(s.mcpFiles,
		mcpFile{configFile{"claude-code", "project", filepath.Join(p, ".mcp.json")}, ""},
		mcpFile{configFile{"cursor", "project", filepath.Join(p, ".cursor", "mcp.json")}, ""},
		mcpFile{configFile{"vscode", "project", filepath.Join(p, ".vscode", "mcp.json")}, mcpFormatVSCode},
		mcpFile{configFile{"codex", "project", filepath.Join(p, ".codex", "config.toml")}, mcpFormatCodex})
	s.extraFiles = append(s.extraFiles, configFile{"claude-code", "project", filepath.Join(p, "CLAUDE.md")})
}

func (s *configScanner) mcpConfigPaths() []mcpFile {
	home := s.env.Home
	user := func(client, path, format string) mcpFile { return mcpFile{configFile{client, "user", path}, format} }
	paths := []mcpFile{
		user("cursor", filepath.Join(home, ".cursor", "mcp.json"), ""),
		user("windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), ""),
		user("gemini-cli", filepath.Join(home, ".gemini", "settings.json"), ""),
	}
	paths = append(paths, s.mcpFiles...)
	switch s.env.GOOS {
	case "darwin":
		paths = append(paths, user("claude-desktop", filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), ""))
	case "windows":
		if s.env.AppData != "" {
			paths = append(paths, user("claude-desktop", filepath.Join(s.env.AppData, "Claude", "claude_desktop_config.json"), ""))
		}
	default:
		paths = append(paths, user("claude-desktop", filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), ""))
	}
	paths = append(paths, user("antigravity", filepath.Join(home, ".gemini", "antigravity", "mcp_config.json"), ""))
	if base := editorBaseOf(s.env); base != "" {
		for _, app := range editorApps {
			if app.client == "cursor" || app.client == "windsurf" || app.client == "antigravity" {
				continue
			}
			paths = append(paths, user(app.client, filepath.Join(base, app.dir, "User", "mcp.json"), mcpFormatVSCode))
		}
	}
	for _, dir := range s.env.CodexHomes {
		paths = append(paths, user("codex", filepath.Join(dir, "config.toml"), mcpFormatCodex))
	}
	return append(paths, user("openclaw", filepath.Join(home, ".openclaw", "openclaw.json"), mcpFormatOpenClaw))
}

func (s *configScanner) scanMCPFile(f mcpFile) {
	b, info, ok := s.read(f.path, AreaMCPServers)
	if !ok {
		return
	}
	if f.format == mcpFormatCodex {
		s.scanServers(f.configFile, info, ParseCodexMCPServers(string(b)))
		return
	}
	var doc struct {
		MCPServers json.RawMessage `json:"mcpServers"`
		Servers    json.RawMessage `json:"servers"`
		MCP        struct {
			Servers json.RawMessage `json:"servers"`
		} `json:"mcp"`
	}
	if json.Unmarshal(StripJSONC(b), &doc) != nil {
		s.out.Unreadable[s.display(f.path)] = true
		return
	}
	raw := doc.MCPServers
	switch f.format {
	case mcpFormatVSCode:
		raw = doc.Servers
	case mcpFormatOpenClaw:
		raw = doc.MCP.Servers
	}
	s.scanServers(f.configFile, info, ParseMCPServers(raw))
}

var (
	pipeToShellRe = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b` +
		`|\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b`)
	secretValueRe = regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{32,}` +
		`|\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{40,}` +
		`|\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b|\bglpat-[A-Za-z0-9_-]{20,}` +
		`|\bnpm_[A-Za-z0-9]{36}\b`)
	secretNameRe  = regexp.MustCompile(`(?i)token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential`)
	placeholderRe = regexp.MustCompile(`(?i)^\$\{[^}]*\}$|^\$[A-Z_][A-Z0-9_]*$|^%[A-Z_][A-Z0-9_]*%$|^<.*>$|your[_-]|x{6,}|changeme|placeholder|example`)
	pkgRunners    = map[string]bool{"npx": true, "uvx": true, "bunx": true, "pnpx": true}
	movingTags    = map[string]bool{"latest": true, "next": true, "beta": true, "alpha": true, "canary": true, "nightly": true}
)

// unixModes is whether this filesystem's permission bits mean anything: Go
// reports 0666 for every file on Windows. It is the running OS, not Env.GOOS,
// since a test can describe another OS's layout on any machine.
var unixModes = runtime.GOOS != "windows"

func (s *configScanner) scanServers(f configFile, info os.FileInfo, servers map[string]MCPServer) {
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	loose := info != nil && unixModes && info.Mode().Perm()&0o044 != 0
	for _, name := range names {
		d := servers[name]
		line := strings.TrimSpace(d.Command + " " + strings.Join(d.Args, " "))
		if pipeToShellRe.MatchString(line) {
			s.add(f, "mcp_pipe_to_shell", Dangerous, name, "starts by piping a download into a shell")
		}
		if pkg, ok := unpinnedPackage(d.Command, d.Args); ok {
			s.add(f, "mcp_unpinned_package", Info, name,
				fmt.Sprintf("runs %s without a pinned version, so each start may fetch different code", pkg))
		}
		if c, ok := parseContainerRun(d.Command, d.Args); ok {
			if c.unpinned() {
				s.add(f, "mcp_unpinned_image", Info, name,
					"runs the image "+c.image+" without a pinned tag or digest, so each start may run a different image")
			}
			if why := c.escape(); why != "" {
				s.add(f, "mcp_container_escape", Suspicious, name, "runs its container with "+why+", so it can reach the whole machine")
			}
		}
		if root := broadRoot(d, s.env.Home); root != "" {
			s.add(f, "mcp_broad_root", Suspicious, name, "is given "+root+" as a filesystem root")
		}
		if d.URL != "" {
			if u, err := url.Parse(d.URL); err == nil && strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname()) {
				s.add(f, "mcp_insecure_remote", Suspicious, name, "talks to "+u.Hostname()+" over plain http")
			}
		}
		sev := Info
		if loose {
			sev = Suspicious
		}
		for _, where := range plaintextSecrets(d) {
			detail := "has a credential in plain text in " + where
			if loose {
				detail += ", in a file other users on this machine can read"
			}
			s.add(f, "mcp_plaintext_secret", sev, name, detail)
		}
	}
}

func exeName(arg string) string {
	arg = strings.ReplaceAll(arg, `\`, "/")
	name := strings.ToLower(filepath.Base(arg))
	return strings.TrimSuffix(name, ".exe")
}

// unpinnedPackage reports the package an npx-style runner fetches when no
// version, or "latest", is pinned.
func unpinnedPackage(command string, args []string) (string, bool) {
	cmd := exeName(command)
	rest := args
	if cmd == "pnpm" || cmd == "yarn" {
		if len(rest) == 0 || rest[0] != "dlx" {
			return "", false
		}
		rest = rest[1:]
	} else if !pkgRunners[cmd] {
		return "", false
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--package" || a == "-p" || a == "--from" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		name, version := splitPackageVersion(a)
		if name == "" || strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
			return "", false
		}
		if version == "" || movingTags[version] {
			return a, true
		}
		return "", false
	}
	return "", false
}

type containerRun struct {
	image string
	flags map[string][]string
}

var containerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true, "--name": true,
	"-p": true, "--publish": true, "--network": true, "--net": true, "-w": true, "--workdir": true, "--entrypoint": true,
	"-u": true, "--user": true, "--platform": true, "--pull": true, "-l": true, "--label": true, "--add-host": true,
	"--pid": true, "--cap-add": true, "--security-opt": true, "-m": true, "--memory": true, "--device": true,
}

// parseContainerRun reads `docker run` or `podman run`: its flags and the
// image, the first argument that is neither.
func parseContainerRun(command string, args []string) (containerRun, bool) {
	if cmd := exeName(command); cmd != "docker" && cmd != "podman" {
		return containerRun{}, false
	}
	i := 0
	for i < len(args) && args[i] != "run" {
		i++
	}
	c := containerRun{flags: map[string][]string{}}
	for i++; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			c.image = a
			return c, true
		}
		if k, v, ok := strings.Cut(a, "="); ok {
			c.flags[k] = append(c.flags[k], v)
		} else if containerValueFlags[a] && i+1 < len(args) {
			i++
			c.flags[a] = append(c.flags[a], args[i])
		} else {
			c.flags[a] = append(c.flags[a], "")
		}
	}
	return containerRun{}, false
}

func (c containerRun) unpinned() bool {
	if strings.Contains(c.image, "@sha256:") {
		return false
	}
	name := c.image[strings.LastIndex(c.image, "/")+1:]
	_, tag, ok := strings.Cut(name, ":")
	return !ok || movingTags[tag]
}

// escape names what lets the container reach past itself, or "".
func (c containerRun) escape() string {
	if _, ok := c.flags["--privileged"]; ok {
		return "--privileged"
	}
	for _, v := range c.flags["--pid"] {
		if v == "host" {
			return "the host's processes (--pid host)"
		}
	}
	for _, v := range c.flags["--cap-add"] {
		if strings.EqualFold(v, "ALL") || strings.EqualFold(v, "SYS_ADMIN") {
			return "--cap-add " + strings.ToUpper(v)
		}
	}
	mounts := append(append([]string{}, c.flags["-v"]...), c.flags["--volume"]...)
	for _, m := range c.flags["--mount"] {
		for _, part := range strings.Split(m, ",") {
			if k, v, ok := strings.Cut(part, "="); ok && (k == "source" || k == "src") {
				mounts = append(mounts, v+":")
			}
		}
	}
	for _, m := range mounts {
		src, _, _ := strings.Cut(m, ":")
		switch {
		case strings.Contains(src, "docker.sock"):
			return "the Docker socket mounted"
		case src == "/":
			return "the root filesystem mounted"
		}
	}
	return ""
}

// broadRoot is the root a filesystem server is given when it is the whole
// machine or the whole home directory, or "".
func broadRoot(d MCPServer, home string) string {
	if !strings.Contains(strings.ToLower(d.Command+" "+strings.Join(d.Args, " ")), "filesystem") {
		return ""
	}
	for _, a := range d.Args {
		v := strings.TrimRight(strings.ReplaceAll(a, `\`, "/"), "/")
		switch {
		case v == "" && a != "", v == "C:", strings.EqualFold(v, "c:"):
			return "the whole disk"
		case v == "~", v == "$HOME", v == "${HOME}", home != "" && v == strings.TrimRight(strings.ReplaceAll(home, `\`, "/"), "/"):
			return "the whole home directory"
		}
	}
	return ""
}

func splitPackageVersion(spec string) (name, version string) {
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			return spec[:i+1], spec[i+2:]
		}
		return spec, ""
	}
	if i := strings.IndexAny(spec, "@="); i >= 0 {
		return spec[:i], strings.TrimLeft(spec[i:], "@=")
	}
	return spec, ""
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}

// plaintextSecrets names where a server definition holds a literal credential.
// It returns names only: the value must never reach the ledger or an alert.
func plaintextSecrets(d MCPServer) []string {
	var where []string
	check := func(kind, key, value string) {
		v := strings.TrimSpace(value)
		if v == "" || placeholderRe.MatchString(v) {
			return
		}
		if secretValueRe.MatchString(v) || (secretNameRe.MatchString(key) && len(v) >= 16 && !strings.ContainsAny(v, " /")) {
			where = append(where, kind+" "+key)
		}
	}
	for _, k := range sortedKeys(d.Env) {
		check("env", k, d.Env[k])
	}
	for _, k := range sortedKeys(d.Headers) {
		if strings.EqualFold(k, "authorization") {
			v := strings.TrimSpace(d.Headers[k])
			if i := strings.IndexByte(v, ' '); i > 0 {
				v = strings.TrimSpace(v[i+1:])
			}
			if v != "" && !placeholderRe.MatchString(v) {
				where = append(where, "header "+k)
			}
			continue
		}
		check("header", k, d.Headers[k])
	}
	for i, a := range d.Args {
		if secretValueRe.MatchString(a) {
			where = append(where, fmt.Sprintf("argument %d", i+1))
		}
	}
	return where
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *configScanner) scanClaudeHooks(path string) {
	f := configFile{"claude-code", "user", path}
	b, _, ok := s.read(path, AreaHooks)
	if !ok {
		return
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(b, &doc) != nil {
		s.out.Unreadable[s.display(path)] = true
		return
	}
	events := make([]string, 0, len(doc.Hooks))
	for e := range doc.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, e := range events {
		for _, m := range doc.Hooks[e] {
			for _, h := range m.Hooks {
				if h.Type == "command" && pipeToShellRe.MatchString(h.Command) {
					s.add(f, "hook_pipe_to_shell", Dangerous, e, "a "+e+" hook pipes a download into a shell")
				}
			}
		}
	}
}

func (s *configScanner) instructionFiles() []configFile {
	var out []configFile
	add := func(client, path string) {
		if !s.skip[path] {
			out = append(out, configFile{client, "user", path})
		}
	}
	home := s.env.Home
	claude := filepath.Join(home, ".claude")
	add("claude-code", filepath.Join(claude, "CLAUDE.md"))
	for _, g := range []struct{ client, pattern string }{
		{"claude-code", filepath.Join(claude, "skills", "*", "*.md")},
		{"claude-code", filepath.Join(claude, "commands", "*.md")},
		{"claude-code", filepath.Join(claude, "agents", "*.md")},
		{"cursor", filepath.Join(home, ".cursor", "rules", "*")},
	} {
		matches, _ := filepath.Glob(g.pattern)
		sort.Strings(matches)
		for _, m := range matches {
			add(g.client, m)
		}
	}
	add("gemini-cli", filepath.Join(home, ".gemini", "GEMINI.md"))
	add("codex", filepath.Join(home, ".codex", "AGENTS.md"))
	add("windsurf", filepath.Join(home, ".codeium", "windsurf", "memories", "global_rules.md"))
	for _, f := range s.extraFiles {
		if !s.skip[f.path] {
			out = append(out, f)
		}
	}
	return out
}

var (
	concealRe  = regexp.MustCompile(`(?i)\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+(?:this|it)\s+to)\s+the\s+user\b|\bwithout\s+(?:telling|informing)\s+the\s+user\b|\bhide\s+(?:this|it)\s+from\s+the\s+user\b`)
	overrideRe = regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|other)\s+instructions\b`)
	credFileRe = regexp.MustCompile(`(?i)\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)|\.aws/credentials|\.config/gcloud/|\.netrc\b|\.docker/config\.json`)
)

// invisibleRune reports characters that render as nothing or reorder text (bidi
// controls, zero-width characters, Unicode tags): the usual carriers of
// instructions that a person reviewing the file cannot see.
func invisibleRune(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200B, r == 0x200C, r == 0x200D, r == 0x2060, r == 0xFEFF:
		return true
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	}
	return false
}

func (s *configScanner) scanInstructions(f configFile) {
	b, _, ok := s.read(f.path, AreaInstructions)
	if !ok || !utf8.Valid(b) {
		return
	}
	subject := filepath.Base(f.path)
	if subject == "SKILL.md" {
		subject = filepath.Base(filepath.Dir(f.path))
	}
	text := strings.TrimPrefix(string(b), "\uFEFF")
	// Distinct code points and no line numbers: the detail is part of the
	// finding's fingerprint, and an edit elsewhere in the file must not make an
	// already-reported finding new again.
	seenRune := map[rune]bool{}
	var hidden []string
	for _, r := range text {
		if invisibleRune(r) && !seenRune[r] && len(hidden) < 5 {
			seenRune[r] = true
			hidden = append(hidden, fmt.Sprintf("U+%04X", r))
		}
	}
	if len(hidden) > 0 {
		sort.Strings(hidden)
		s.add(f, "instructions_hidden_unicode", Dangerous, subject,
			"contains characters a reader cannot see: "+strings.Join(hidden, ", "))
	}
	for _, c := range []struct {
		check, severity string
		re              *regexp.Regexp
		detail          string
	}{
		// Info, not alerts: ordinary project docs say these things for honest
		// reasons (install steps, where credentials come from, how to resist a
		// prompt injection). Recorded so a reviewer can look; only concealment,
		// narrowed to telling, and hidden characters raise a flag.
		{"instructions_conceal", Suspicious, concealRe, "tells the agent to keep something from the user"},
		{"instructions_override", Info, overrideRe, "tells the agent to ignore its other instructions"},
		{"instructions_pipe_to_shell", Info, pipeToShellRe, "mentions piping a download into a shell"},
		{"instructions_credential_files", Info, credFileRe, "mentions credential files"},
	} {
		// The matched text is not quoted: it is the file's own content, and a
		// finding's detail reaches metadata and webhook notes unredacted.
		if matchesInstruction(c.check, c.re, text) {
			s.add(f, c.check, c.severity, subject, c.detail)
		}
	}
}

// matchesInstruction is re.MatchString, except that "never tell the user to
// run it" and "don't tell the user how to fix it" are about what to say, not
// what to keep back, and do not count as concealment.
func matchesInstruction(check string, re *regexp.Regexp, text string) bool {
	if check != "instructions_conceal" {
		return re.MatchString(text)
	}
	for _, loc := range re.FindAllStringIndex(text, -1) {
		next := strings.Fields(strings.ToLower(text[loc[1]:min(loc[1]+40, len(text))]))
		if len(next) > 0 && (next[0] == "to" || next[0] == "how") {
			continue
		}
		return true
	}
	return false
}

// Items is the scan as report items. A hook's detail already names its event;
// the others read as "<server or file> <what was found>".
func (c ConfigScan) Items() []Item {
	out := make([]Item, 0, len(c.Findings))
	for _, f := range c.Findings {
		area, detail := AreaRunModes, f.Subject+" "+f.Detail
		switch {
		case f.Check == "mcp_plaintext_secret":
			area = AreaSecrets
		case strings.HasPrefix(f.Check, "mcp_"):
			area = AreaMCPServers
		case strings.HasPrefix(f.Check, "hook_"):
			area, detail = AreaHooks, f.Detail
		case strings.HasPrefix(f.Check, "instructions_"):
			area = AreaInstructions
		}
		out = append(out, Item{
			Client: f.Client, Check: f.Check, Severity: f.Severity, Area: area, Scope: f.Scope,
			Location: f.Location, Subject: f.Subject, Detail: detail,
		})
	}
	return out
}
