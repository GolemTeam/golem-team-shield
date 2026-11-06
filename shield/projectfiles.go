package shield

import (
	"path/filepath"
	"sort"
	"strings"
)

// projectFiles are the files in a work tree that an agent reads when it
// starts or calls a tool, and that would let a command re-point its shell or
// run something outside the jail: Claude Code's project settings, which
// override the user's env, CLAUDE_CODE_SHELL included, and which Cursor,
// Copilot CLI and Devin read too; and the project hooks and MCP servers of
// the agents the jail attaches to (docs/design-local-shield.md, Project
// files). projectTrees are whole folders of them. The work tree is otherwise
// writable.
var projectFiles = []string{
	".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
	".cursor/hooks.json", ".cursor/mcp.json",
	".gemini/settings.json",
	".devin/hooks.v1.json", ".devin/config.json", ".devin/config.local.json",
	".devin/mcp_config.json", ".devin/mcp_config.local.json",
	".github/copilot/settings.json", ".github/copilot/settings.local.json",
	".codex/hooks.json", ".codex/config.toml",
	".agents/hooks.json", ".agents/mcp_config.json",
	".vscode/settings.json",
}

var projectTrees = []string{".github/hooks"}

// ProjectPaths are the agents' project files a command may not write, as
// absolute paths. Folders are each folder on the way to one, as an entry of
// its own, so a folder of the command's making can't be renamed into place
// with the files already in it; the files beside them stay writable.
type ProjectPaths struct {
	Files, Trees, Folders []string
}

// ProjectFilePaths are those of each work tree in c, at its root and in every
// folder from there down to the command's working directory, where an agent
// started deeper reads its own copies: Gemini CLI where it was started, Codex
// each .codex/config.toml from the root down, Devin each folder from its
// working directory up. The folders on that way are entries too, or one could
// be swapped for a copy holding the files. Folders below the working
// directory are left alone, so cloning a repository that has them still works.
func ProjectFilePaths(c Context) ProjectPaths {
	var out ProjectPaths
	seen := map[string]bool{}
	add := func(list *[]string, p string) {
		if !seen[p] {
			seen[p] = true
			*list = append(*list, p)
		}
	}
	for i, root := range projectRoots(c) {
		if i > 0 && !isWorkspace(c, root) {
			add(&out.Folders, root)
		}
		for _, f := range projectFiles {
			add(&out.Files, filepath.Join(root, f))
		}
		for _, t := range projectTrees {
			add(&out.Trees, filepath.Join(root, t))
		}
		for _, d := range projectFolders() {
			add(&out.Folders, filepath.Join(root, d))
		}
	}
	return out
}

func isWorkspace(c Context, p string) bool {
	for _, ws := range c.Workspace {
		if filepath.Clean(ws) == p {
			return true
		}
	}
	return false
}

// projectRoots are each work tree's root and the folders between it and the
// working directory.
func projectRoots(c Context) []string {
	var roots []string
	for _, ws := range c.Workspace {
		ws = filepath.Clean(ws)
		roots = append(roots, ws)
		if c.WorkingDir == "" || !within(c.WorkingDir, ws) {
			continue
		}
		rel, err := filepath.Rel(ws, filepath.Clean(c.WorkingDir))
		if err != nil || rel == "." {
			continue
		}
		d := ws
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			d = filepath.Join(d, part)
			roots = append(roots, d)
		}
	}
	return roots
}

// projectFolders are the folders on the way to each project file, relative.
func projectFolders() []string {
	dirs := map[string]bool{}
	for _, p := range append(append([]string{}, projectFiles...), projectTrees...) {
		for d := filepath.Dir(p); d != "."; d = filepath.Dir(d) {
			dirs[d] = true
		}
	}
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
