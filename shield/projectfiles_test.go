package shield

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestProjectFilesAreHeldFromTheRootDownToTheWorkingDir(t *testing.T) {
	ws := filepath.FromSlash("/w/app")
	p := ProjectFilePaths(Context{Workspace: []string{ws}, WorkingDir: filepath.Join(ws, "a", "b")})
	at := func(rel ...string) string { return filepath.Join(append([]string{ws}, rel...)...) }
	for _, f := range []string{at(".gemini", "settings.json"), at("a", ".gemini", "settings.json"), at("a", "b", ".codex", "config.toml"), at("a", "b", ".devin", "hooks.v1.json")} {
		if !slices.Contains(p.Files, f) {
			t.Errorf("file %s isn't held", f)
		}
	}
	for _, d := range []string{at("a"), at("a", "b"), at(".github"), at("a", "b", ".cursor"), at("a", ".github", "copilot")} {
		if !slices.Contains(p.Folders, d) {
			t.Errorf("folder %s isn't held", d)
		}
	}
	if !slices.Contains(p.Trees, at("a", "b", ".github", "hooks")) {
		t.Error("the working dir's .github/hooks isn't held")
	}
	for _, list := range [][]string{p.Files, p.Folders, p.Trees} {
		for _, x := range list {
			if x == ws || within(x, at("a", "b", "c")) || within(x, at("x")) {
				t.Errorf("%s is held, but only the way down to the working dir should be", x)
			}
		}
	}
}

func TestProjectFilesOutsideTheWorkTreeAreOnlyItsRoot(t *testing.T) {
	ws := filepath.FromSlash("/w/app")
	for _, wd := range []string{"", ws, filepath.FromSlash("/elsewhere/deep")} {
		p := ProjectFilePaths(Context{Workspace: []string{ws}, WorkingDir: wd})
		if len(p.Files) != len(projectFiles) || len(p.Trees) != len(projectTrees) || len(p.Folders) != len(projectFolders()) {
			t.Errorf("working dir %q: %d files, %d trees, %d folders", wd, len(p.Files), len(p.Trees), len(p.Folders))
		}
	}
}
