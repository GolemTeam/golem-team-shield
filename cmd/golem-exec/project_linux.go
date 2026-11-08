package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// Landlock can only allow, so it can't keep a command from writing one file
// inside a work tree it may otherwise write. A mount can: in the command's
// own mount namespace, each project file an agent reads (hooks, MCP servers,
// settings; shield.ProjectFilePaths) is bound read-only onto itself, and each folder on the way is
// bound onto itself, which makes it a mount point that can't be renamed or
// removed, so a folder can't be swapped for one with a planted file in it. A
// missing file can't be bound. When its nearest existing folder is itself
// one of the project folders (.claude, .github, …), that folder is bound
// read-only instead, with what is already in it bound back writable. Any
// other folder, the work tree's root above all, is where people work and
// must stay writable, so a file missing there is left to the shim's check
// after the command.

type projectKind byte

const (
	projectFile projectKind = iota
	projectTree
	projectFolder
)

type projectPath struct {
	Path string
	Kind projectKind
}

// makeProjectFolders makes each agent's folder missing at a root (the git
// work tree's, or a folder on the way down to the working directory:
// .claude, .cursor, .github, .vscode, …), as the Windows jail does. A file
// missing at a root can't be held, but a folder that exists can, bound
// read-only while it lacks a file on the list. .mcp.json, the one file at a
// root, isn't held. Git doesn't list an empty folder.
func makeProjectFolders(c shield.Context) {
	var trees []string
	for _, ws := range c.Workspace {
		if _, err := os.Lstat(filepath.Join(ws, ".git")); err == nil {
			trees = append(trees, filepath.Clean(ws))
		}
	}
	working := workingFolders(c)
	for _, f := range shield.ProjectFilePaths(c).Folders {
		parent := filepath.Dir(f)
		if !working[parent] || working[f] || !(isTree(parent, trees)) {
			continue
		}
		_ = os.Mkdir(f, 0o755)
	}
}

func isTree(p string, trees []string) bool {
	for _, t := range trees {
		if p == t || within(p, []string{t}) {
			return true
		}
	}
	return false
}

func projectPaths(c shield.Context) []projectPath {
	pp := shield.ProjectFilePaths(c)
	var out []projectPath
	for _, l := range []struct {
		paths []string
		kind  projectKind
	}{{pp.Files, projectFile}, {pp.Trees, projectTree}, {pp.Folders, projectFolder}} {
		for _, p := range l.paths {
			out = append(out, projectPath{Path: p, Kind: l.kind})
		}
	}
	return out
}

// workingFolders are each work tree's root and the folders down to the
// working directory: where people work, never bound read-only.
func workingFolders(c shield.Context) map[string]bool {
	out := map[string]bool{}
	for _, ws := range c.Workspace {
		ws = filepath.Clean(ws)
		out[ws] = true
		rel, err := filepath.Rel(ws, filepath.Clean(c.WorkingDir))
		if c.WorkingDir == "" || err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		d := ws
		for _, part := range strings.Split(rel, "/") {
			d = filepath.Join(d, part)
			out[d] = true
		}
	}
	return out
}

// planProjectMounts works out the binds that hold paths, deepest first, and
// returns the files it can't hold for the check after the command.
func planProjectMounts(paths []projectPath, roots []string, working map[string]bool) (mountPlan, []projectPath) {
	readOnly := map[string]bool{}
	set := func(p string, ro bool) { readOnly[p] = readOnly[p] || ro }
	protected, folders := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		protected[p.Path] = true
		folders[p.Path] = p.Kind == projectFolder
	}
	var unheld []projectPath
	for _, p := range paths {
		fi, err := os.Lstat(p.Path)
		switch {
		case err == nil && fi.Mode()&os.ModeSymlink != 0:
			if p.Kind != projectFolder {
				unheld = append(unheld, p)
			}
		case err == nil && p.Kind == projectFolder:
			if fi.IsDir() {
				set(p.Path, false)
			}
		case err == nil:
			set(p.Path, true)
		case p.Kind == projectFolder:
		default:
			holder := nearestExisting(p.Path)
			entries, err := os.ReadDir(holder)
			if holder == "" || !folders[holder] || working[holder] || !within(holder, roots) || err != nil {
				unheld = append(unheld, p)
				continue
			}
			set(holder, true)
			for _, e := range entries {
				child := filepath.Join(holder, e.Name())
				if e.Type()&os.ModeSymlink == 0 && !protected[child] {
					set(child, false)
				}
			}
		}
	}
	var plan mountPlan
	for p, ro := range readOnly {
		plan.Binds = append(plan.Binds, planBind{Path: p, ReadOnly: ro})
	}
	sort.Slice(plan.Binds, func(i, j int) bool {
		di, dj := strings.Count(plan.Binds[i].Path, "/"), strings.Count(plan.Binds[j].Path, "/")
		if di != dj {
			return di > dj
		}
		return plan.Binds[i].Path < plan.Binds[j].Path
	})
	return plan, unheld
}

func nearestExisting(p string) string {
	for d := filepath.Dir(p); d != filepath.Dir(d); d = filepath.Dir(d) {
		if fi, err := os.Lstat(d); err == nil {
			if fi.IsDir() {
				return d
			}
			return ""
		}
	}
	return ""
}

// within is strictly inside a root: the root itself is never bound.
func within(p string, roots []string) bool {
	for _, r := range roots {
		if rel, err := filepath.Rel(r, p); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}
