package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

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

// makeClaudeFolders makes each git work tree's .claude when it is missing,
// as the Windows jail does: five agents read it, and its settings.json
// re-points Claude Code's shell, but a file missing at the root can't be
// held, and a folder that exists can (bound read-only while it lacks a file
// on the list). Git doesn't list an empty folder.
func makeClaudeFolders(workspace []string) {
	for _, ws := range workspace {
		if _, err := os.Lstat(filepath.Join(ws, ".git")); err != nil {
			continue
		}
		_ = os.Mkdir(filepath.Join(ws, ".claude"), 0o755)
	}
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

type mountPlan struct {
	Binds []planBind `json:"binds,omitempty"`
}

type planBind struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"ro,omitempty"`
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

// applyMountPlan binds each path onto itself, deepest first so a folder's
// recursive bind carries what was bound inside it, then makes the read-only
// ones read-only. A remount must keep the flags the original mount was
// locked with, or the kernel refuses it in a user namespace.
func applyMountPlan(plan mountPlan) error {
	for _, b := range plan.Binds {
		if err := unix.Mount(b.Path, b.Path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
	}
	for _, b := range plan.Binds {
		if !b.ReadOnly {
			continue
		}
		var st unix.Statfs_t
		if err := unix.Statfs(b.Path, &st); err != nil {
			return err
		}
		flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
		for _, f := range []struct{ st, ms uintptr }{
			{unix.ST_NOSUID, unix.MS_NOSUID}, {unix.ST_NODEV, unix.MS_NODEV}, {unix.ST_NOEXEC, unix.MS_NOEXEC},
			{unix.ST_NOATIME, unix.MS_NOATIME}, {unix.ST_NODIRATIME, unix.MS_NODIRATIME}, {unix.ST_RELATIME, unix.MS_RELATIME},
		} {
			if uintptr(st.Flags)&f.st != 0 {
				flags |= f.ms
			}
		}
		if err := unix.Mount("", b.Path, "", flags, ""); err != nil {
			return err
		}
	}
	return nil
}
