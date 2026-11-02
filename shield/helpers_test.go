package shield

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func itoa(i int) string { return strconv.Itoa(i) }

type llTree struct {
	root, home, ws, tmp string
}

func newLLTree(t *testing.T) llTree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := llTree{root: root, home: filepath.Join(root, "home"), ws: filepath.Join(root, "home", "src", "app"), tmp: filepath.Join(root, "turn")}
	for _, f := range []string{
		".ssh/id_ed25519", ".ssh/config", ".ssh/known_hosts", ".aws/credentials", ".golem/key",
		".zshrc", ".viminfo", ".config/git/config", ".config/nvim/init.lua", ".claude/settings.json",
		".claude/projects/x.jsonl", ".cache/go/x", "src/app/main.go", "src/app/.git/config", "../outside/x",
	} {
		plantFile(t, filepath.Join(tr.home, f))
	}
	if err := os.MkdirAll(tr.tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	return tr
}

func plantFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (tr llTree) context() Context {
	return Context{
		Home:        tr.home,
		Workspace:   []string{tr.ws},
		TurnTmp:     tr.tmp,
		SSHReadable: []string{filepath.Join(tr.home, ".ssh/config"), filepath.Join(tr.home, ".ssh/known_hosts")},
	}
}

func testContext() Context {
	return Context{
		Home:        "/Users/dev",
		Workspace:   []string{"/Users/dev/src/app"},
		TurnTmp:     "/tmp/golem-turn-1",
		AgentSocket: "/Users/dev/.ssh/agent.sock",
	}
}
