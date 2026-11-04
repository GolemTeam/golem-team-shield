package agentposture

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ScanRepo reads what a repository brings with it for the agents that open
// it, and nothing from the home directory: what a clone hands every developer
// who works in it. Locations are relative to dir, and nothing is graded as a
// protection, since a repository's files cannot jail a shell.
func ScanRepo(dir string) Result {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Result{}
	}
	unread := filepath.Join(abs, ".golem-check-reads-no-home")
	res := ScanAll(Env{
		Home: unread, GOOS: runtime.GOOS, Projects: []string{abs}, Repo: abs,
		ManagedDir: unread, GeminiSystem: filepath.Join(unread, "settings.json"),
	})
	out := Result{Repo: filepath.Base(abs)}
	// Locations come with either separator (DisplayHome writes slashes), so
	// both sides are compared with slashes.
	prefix := filepath.ToSlash(abs) + "/"
	for _, it := range res.Items {
		loc := filepath.ToSlash(it.Location)
		if it.Area == AreaProtections || !strings.HasPrefix(loc, prefix) {
			continue
		}
		it.Location = strings.TrimPrefix(loc, prefix)
		out.Items = append(out.Items, it)
	}
	for _, a := range res.Read {
		if a != AreaProtections {
			out.Read = append(out.Read, a)
		}
	}
	return out
}

// within reports whether path, links resolved, stays inside root. A
// repository can link CLAUDE.md or .mcp.json to any file on the machine, and
// a check run on a stranger's pull request must not read it. A path that does
// not resolve has nothing to read, and is left to the read to fail.
func within(root, path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	return resolved == root || strings.HasPrefix(resolved, root+string(filepath.Separator))
}

func (s *scan) readCapped(path string) ([]byte, os.FileInfo, bool) {
	if s.env.Repo != "" && !within(s.env.Repo, path) {
		return nil, nil, false
	}
	return readCapped(path)
}

func (s *scan) readSettings(path string) map[string]any {
	if s.env.Repo != "" && !within(s.env.Repo, path) {
		return nil
	}
	return readSettings(path)
}

func (s *scan) readCodexTOML(path string) codexTOML {
	if s.env.Repo != "" && !within(s.env.Repo, path) {
		return nil
	}
	return readCodexTOML(path)
}
