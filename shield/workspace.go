package shield

import (
	"os"
	"path/filepath"
	"strings"
)

// Workspace is what FindWorkspace learned about the repository a command runs
// in. It reads .git itself rather than asking git, because git run inside an
// untrusted repository runs that repository's config.
type Workspace struct {
	// Writable is where a tainted session may still write.
	Writable []string
	// Hooks and config stay unwritable to a tainted session even inside the
	// work tree: a hook written there runs in every later, clean session.
	Protected []string
}

// FindWorkspace walks up from dir to the nearest .git. For a linked worktree
// the common git dir is shared with every other worktree of the repository
// (in a bare-clone layout it holds them all), so only the parts a commit
// writes are opened, never the whole directory.
func FindWorkspace(dir string) Workspace {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		dotgit := filepath.Join(d, ".git")
		fi, err := os.Lstat(dotgit)
		if err == nil && fi.IsDir() {
			return Workspace{
				Writable:  []string{d},
				Protected: []string{filepath.Join(dotgit, "hooks"), filepath.Join(dotgit, "config")},
			}
		}
		if err == nil && fi.Mode().IsRegular() {
			if ws, ok := linkedWorktree(d, dotgit); ok {
				return ws
			}
			return Workspace{Writable: []string{d}}
		}
		if parent := filepath.Dir(d); parent == d {
			return Workspace{}
		}
	}
}

func linkedWorktree(top, dotgit string) (Workspace, bool) {
	gitdir, ok := readPointer(dotgit, "gitdir:", top)
	if !ok {
		return Workspace{}, false
	}
	ws := Workspace{
		Writable:  []string{top, gitdir},
		Protected: []string{filepath.Join(gitdir, "config.worktree")},
	}
	if common, ok := readPointer(filepath.Join(gitdir, "commondir"), "", gitdir); ok {
		for _, part := range []string{"objects", "refs", "logs"} {
			ws.Writable = append(ws.Writable, filepath.Join(common, part))
		}
		ws.Writable = append(ws.Writable,
			filepath.Join(common, "packed-refs"), filepath.Join(common, "packed-refs.lock"))
	}
	return ws, true
}

func readPointer(path, prefix, base string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return "", false
	}
	s := strings.TrimSpace(string(raw))
	if prefix != "" {
		if !strings.HasPrefix(s, prefix) {
			return "", false
		}
		s = strings.TrimSpace(strings.TrimPrefix(s, prefix))
	}
	if s == "" || strings.ContainsAny(s, "\x00\n") {
		return "", false
	}
	if !filepath.IsAbs(s) {
		s = filepath.Join(base, s)
	}
	return filepath.Clean(s), true
}
