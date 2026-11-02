package shield

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFindWorkspaceInAPlainRepository(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	ws := FindWorkspace(sub)
	if !slices.Equal(ws.Writable, []string{root}) {
		t.Errorf("writable %v", ws.Writable)
	}
	if !slices.Contains(ws.Protected, filepath.Join(root, ".git", "hooks")) {
		t.Errorf("protected %v", ws.Protected)
	}
}

// In a bare-clone layout the common dir holds every worktree, so opening it
// whole would let a tainted session write into its neighbours.
func TestFindWorkspaceInALinkedWorktreeOpensOnlyWhatACommitWrites(t *testing.T) {
	base := t.TempDir()
	bare := filepath.Join(base, ".bare")
	gitdir := filepath.Join(bare, "worktrees", "wt")
	tree := filepath.Join(base, "wt")
	write(t, filepath.Join(gitdir, "commondir"), "../..\n")
	write(t, filepath.Join(tree, ".git"), "gitdir: "+gitdir+"\n")

	ws := FindWorkspace(tree)
	for _, want := range []string{tree, gitdir, filepath.Join(bare, "objects"), filepath.Join(bare, "refs")} {
		if !slices.Contains(ws.Writable, want) {
			t.Errorf("writable lacks %s: %v", want, ws.Writable)
		}
	}
	if slices.Contains(ws.Writable, bare) {
		t.Errorf("the whole common dir is writable: %v", ws.Writable)
	}
}

func TestFindWorkspaceOutsideARepository(t *testing.T) {
	if ws := FindWorkspace(t.TempDir()); len(ws.Writable) != 0 {
		t.Errorf("writable %v", ws.Writable)
	}
}
