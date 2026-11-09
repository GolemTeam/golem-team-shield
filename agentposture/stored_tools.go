package agentposture

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// What an MCP server told an agent is read only from the copy the agent wrote
// down the last time it started the server; nothing here starts one. Cursor
// keeps each server's INSTRUCTIONS.md and tools/<tool>.json under
// ~/.cursor/projects/<project>/mcps/<server>/, with SERVER_METADATA.json
// naming the server as its config does. Antigravity keeps <tool>.json under
// ~/.gemini/antigravity/mcp/<server>/ (antigravity-ide/ for the newer app),
// the VS Code family every server's instructions and tools in its state
// database under mcpToolCache, and Codex the tools of its built-in apps server
// in cache/codex_apps_tools. Claude Code, Claude Desktop, Gemini CLI, Windsurf,
// Copilot CLI and the rest keep no copy. The layouts are undocumented and were
// read off the apps; anything that does not decode as expected is skipped.

const (
	maxStoredProjects   = 500
	maxStoredWorkspaces = 100
	vscodeToolCacheKey  = "mcpToolCache"
)

// StoredServer is one MCP server's tools as an agent wrote them down.
type StoredServer struct {
	Client  string
	Name    string
	Scope   string
	Path    string
	Written time.Time
	Parts   []definition.Part
}

// StoredServers is every copy the agents on this machine keep, newest per
// agent and server, in a fixed order (Cursor, Antigravity, the VS Code family,
// Codex) so a caller that keeps the first copy of a name keeps the same one
// every pass. A repository scan has none.
func StoredServers(env Env) []StoredServer {
	if env.Home == "" || env.Repo != "" {
		return nil
	}
	var out []StoredServer
	out = append(out, cursorStored(env.Home)...)
	out = append(out, antigravityStored(env.Home)...)
	out = append(out, vscodeStored(env)...)
	out = append(out, codexAppsStored(env)...)
	return out
}

type newestStored map[string]StoredServer

func (n newestStored) offer(s StoredServer) {
	if cur, ok := n[s.Name]; !ok || s.Written.After(cur.Written) {
		n[s.Name] = s
	}
}

func (n newestStored) sorted() []StoredServer {
	names := make([]string, 0, len(n))
	for k := range n {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]StoredServer, 0, len(names))
	for _, k := range names {
		out = append(out, n[k])
	}
	return out
}

func cursorStored(home string) []StoredServer {
	root := filepath.Join(home, ".cursor", "projects")
	projects, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	if len(projects) > maxStoredProjects {
		projects = projects[:maxStoredProjects]
	}
	newest := newestStored{}
	for _, p := range projects {
		servers, err := os.ReadDir(filepath.Join(root, p.Name(), "mcps"))
		if err != nil {
			continue
		}
		for _, s := range servers {
			dir := filepath.Join(root, p.Name(), "mcps", s.Name())
			b, _, ok := readCapped(filepath.Join(dir, "SERVER_METADATA.json"))
			if !ok {
				continue
			}
			var meta struct {
				ServerName string `json:"serverName"`
			}
			if json.Unmarshal(b, &meta) != nil || meta.ServerName == "" {
				continue
			}
			newest.offer(StoredServer{Client: "cursor", Name: meta.ServerName, Scope: "user", Path: dir, Written: newestFile(dir)})
		}
	}
	var out []StoredServer
	for _, s := range newest.sorted() {
		if b, _, ok := readCapped(filepath.Join(s.Path, "INSTRUCTIONS.md")); ok && len(b) > 0 {
			s.Parts = append(s.Parts, definition.Text(definition.KindInstructions, "", b))
		}
		s.Parts = append(s.Parts, storedTools(filepath.Join(s.Path, "tools"), "arguments")...)
		if len(s.Parts) > 0 {
			out = append(out, s)
		}
	}
	return out
}

func antigravityStored(home string) []StoredServer {
	newest := newestStored{}
	for _, app := range []string{"antigravity", "antigravity-ide"} {
		root := filepath.Join(home, ".gemini", app, "mcp")
		servers, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, s := range servers {
			if !s.IsDir() {
				continue
			}
			dir := filepath.Join(root, s.Name())
			newest.offer(StoredServer{Client: "antigravity", Name: s.Name(), Scope: "user", Path: dir, Written: newestFile(dir)})
		}
	}
	var out []StoredServer
	for _, s := range newest.sorted() {
		if s.Parts = storedTools(s.Path, "parameters"); len(s.Parts) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// vscodeStored reads each profile's database, for the servers in user
// settings, and the most recently used workspaces', for a workspace's own.
// Cursor, Windsurf and Antigravity keep their own copies or none, and theirs
// are not opened: a key a database lacks costs a walk of all of it.
func vscodeStored(env Env) []StoredServer {
	base := editorBaseOf(env)
	if base == "" {
		return nil
	}
	var out []StoredServer
	for _, app := range editorApps {
		if app.client == "cursor" || app.client == "windsurf" || app.client == "antigravity" {
			continue
		}
		user := filepath.Join(base, app.dir, "User")
		newest := newestStored{}
		profiles, _ := filepath.Glob(filepath.Join(user, "profiles", "*", "globalStorage", "state.vscdb"))
		for _, db := range append([]string{filepath.Join(user, "globalStorage", "state.vscdb")}, profiles...) {
			for _, s := range vscodeToolCache(app.client, "user", db) {
				newest.offer(s)
			}
		}
		for _, db := range recentWorkspaceDBs(filepath.Join(user, "workspaceStorage")) {
			for _, s := range vscodeToolCache(app.client, "project", db) {
				newest.offer(s)
			}
		}
		out = append(out, newest.sorted()...)
	}
	return out
}

func recentWorkspaceDBs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type db struct {
		path string
		mod  time.Time
	}
	var dbs []db
	for _, e := range entries {
		p := filepath.Join(dir, e.Name(), "state.vscdb")
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			dbs = append(dbs, db{p, info.ModTime()})
		}
	}
	sort.SliceStable(dbs, func(i, j int) bool { return dbs[i].mod.After(dbs[j].mod) })
	if len(dbs) > maxStoredWorkspaces {
		dbs = dbs[:maxStoredWorkspaces]
	}
	out := make([]string, len(dbs))
	for i, d := range dbs {
		out[i] = d.path
	}
	return out
}

// vscodeToolCache decodes {"serverTools": [[id, {serverName,
// serverInstructions, tools}], ...]}. VS Code rewrites a tool's name to suit
// itself and keeps the server's as serverToolName, and files a tool sent with
// no description as "<empty>"; both are undone so the tool reads as sent.
func vscodeToolCache(client, scope, path string) []StoredServer {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	v, err := readItemTable(path, map[string]bool{vscodeToolCacheKey: true})
	if err != nil || v[vscodeToolCacheKey] == nil {
		return nil
	}
	var doc struct {
		ServerTools [][]json.RawMessage `json:"serverTools"`
	}
	if json.Unmarshal(v[vscodeToolCacheKey], &doc) != nil {
		return nil
	}
	var out []StoredServer
	for _, entry := range doc.ServerTools {
		if len(entry) != 2 {
			continue
		}
		var id string
		var e struct {
			ServerName         string                       `json:"serverName"`
			ServerInstructions string                       `json:"serverInstructions"`
			Tools              []map[string]json.RawMessage `json:"tools"`
		}
		if json.Unmarshal(entry[0], &id) != nil || json.Unmarshal(entry[1], &e) != nil {
			continue
		}
		name := vscodeServerName(id, e.ServerName)
		if name == "" {
			continue
		}
		s := StoredServer{Client: client, Name: name, Scope: scope, Path: path, Written: info.ModTime()}
		if e.ServerInstructions != "" {
			s.Parts = append(s.Parts, definition.Text(definition.KindInstructions, "", []byte(e.ServerInstructions)))
		}
		for _, t := range e.Tools {
			if len(s.Parts) >= definition.MaxParts {
				break
			}
			if orig, ok := t["serverToolName"]; ok {
				t["name"] = orig
			}
			if string(t["description"]) == `"<empty>"` {
				delete(t, "description")
			}
			if p, ok := visibleTool(t, "inputSchema"); ok {
				s.Parts = append(s.Parts, p)
			}
		}
		if len(s.Parts) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// vscodeServerName takes the config's name out of the id VS Code files a
// server under: mcp.config.<config>.<name> for a settings file and
// workspace-dot-mcp.<folder>.<name> for a workspace's .mcp.json. Any other id,
// such as an extension's, carries no config name.
func vscodeServerName(id, serverName string) string {
	for _, prefix := range []string{"mcp.config.", "workspace-dot-mcp."} {
		if rest, ok := strings.CutPrefix(id, prefix); ok {
			if _, name, ok := strings.Cut(rest, "."); ok && name != "" {
				return name
			}
		}
	}
	return serverName
}

func codexAppsStored(env Env) []StoredServer {
	newest := newestStored{}
	for _, home := range env.CodexHomes {
		files, _ := filepath.Glob(filepath.Join(home, "cache", "codex_apps_tools", "*.json"))
		sort.Strings(files)
		for _, f := range files {
			b, info, ok := readCapped(f)
			if !ok {
				continue
			}
			var doc struct {
				Tools []struct {
					ServerName string                     `json:"server_name"`
					Tool       map[string]json.RawMessage `json:"tool"`
				} `json:"tools"`
			}
			if json.Unmarshal(b, &doc) != nil {
				continue
			}
			byServer := map[string]*StoredServer{}
			var order []string
			for _, t := range doc.Tools {
				if t.ServerName == "" || t.Tool == nil {
					continue
				}
				s := byServer[t.ServerName]
				if s == nil {
					s = &StoredServer{Client: "codex", Name: t.ServerName, Scope: "user", Path: f, Written: info.ModTime()}
					byServer[t.ServerName] = s
					order = append(order, t.ServerName)
				}
				if len(s.Parts) >= definition.MaxParts {
					continue
				}
				if p, ok := visibleTool(t.Tool, "inputSchema"); ok {
					s.Parts = append(s.Parts, p)
				}
			}
			for _, name := range order {
				if s := byServer[name]; len(s.Parts) > 0 {
					newest.offer(*s)
				}
			}
		}
	}
	return newest.sorted()
}

func storedTools(dir, schemaField string) []definition.Part {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var parts []definition.Part
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || len(parts) >= definition.MaxParts {
			continue
		}
		b, _, ok := readCapped(filepath.Join(dir, e.Name()))
		if !ok {
			continue
		}
		var t map[string]json.RawMessage
		if json.Unmarshal(b, &t) != nil {
			continue
		}
		if p, ok := visibleTool(t, schemaField); ok {
			parts = append(parts, p)
		}
	}
	return parts
}

// visibleTool puts a stored tool back in the shape the model reads, so it
// hashes the same here as from the gateway.
func visibleTool(t map[string]json.RawMessage, schemaField string) (definition.Part, bool) {
	visible := map[string]json.RawMessage{"name": t["name"], "description": t["description"]}
	if s, ok := t[schemaField]; ok {
		visible["inputSchema"] = s
	}
	if len(visible["description"]) == 0 {
		delete(visible, "description")
	}
	raw, err := json.Marshal(visible)
	if err != nil {
		return definition.Part{}, false
	}
	part, _, err := definition.Tool(raw)
	return part, err == nil
}

func newestFile(dir string) time.Time {
	var newest time.Time
	_ = filepath.WalkDir(dir, func(_ string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return newest
}
