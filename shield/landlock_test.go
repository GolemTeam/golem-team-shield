//go:build !windows

package shield

import (
	"os"
	"path/filepath"
	"testing"
)

// access is what Landlock would allow on path under j: every directory rule
// at or above it, and a file rule on it exactly.
func access(j LinuxJail, path string) uint64 {
	var a uint64
	for _, r := range j.Rules {
		if r.Path == path || (r.Dir && within(path, r.Path)) {
			a |= r.Access
		}
	}
	return a
}

func compileLL(t *testing.T, p Policy, c Context, abi int) LinuxJail {
	t.Helper()
	j, err := CompileLandlock(p, c, abi)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return j
}

func TestLandlockCleanTakesCredentialsAndPersistenceOnly(t *testing.T) {
	tr := newLLTree(t)
	j := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants()}, tr.context(), 7)
	h := func(p string) string { return filepath.Join(tr.home, p) }

	for _, p := range []string{".ssh/id_ed25519", ".golem/key"} {
		if access(j, h(p))&(llReadFile|llWriteFile) != 0 {
			t.Errorf("%s is readable or writable", p)
		}
	}
	for _, p := range []string{".ssh/config", ".ssh/known_hosts", ".zshrc", ".aws/credentials", ".config/git/config", "src/app/main.go"} {
		if access(j, h(p))&llReadFile == 0 {
			t.Errorf("%s isn't readable", p)
		}
	}
	for _, p := range []string{".zshrc", ".config/git/config", ".claude/settings.json", ".ssh/config", ".codex/hooks.json", ".codex/config.toml", ".gemini/settings.json", ".hermes/plugins/golem/__init__.py", ".hermes/config.yaml", ".openclaw/extensions/golem/index.js", ".openclaw/openclaw.json", ".copilot/hooks/golem.json", ".copilot/config.json", ".gemini/config/hooks.json"} {
		if access(j, h(p))&llWriteFile != 0 {
			t.Errorf("%s is writable", p)
		}
	}
	for _, p := range []string{".viminfo", ".config/nvim/init.lua", ".claude/projects/x.jsonl", ".cache/go/x", "src/app/main.go", "../outside/x"} {
		if access(j, h(p))&llWriteFile == 0 {
			t.Errorf("%s isn't writable", p)
		}
	}
	if access(j, h(".bashrc"))&llMakeReg != 0 || access(j, h(".config/systemd/user/x.service"))&llMakeReg != 0 {
		t.Error("a startup file can be created")
	}
	if access(j, h("src/new.go"))&llMakeReg == 0 || access(j, h(".cache/new"))&llMakeReg == 0 {
		t.Error("files can't be created below home")
	}
	if access(j, h(".ssh"))&llReadDir == 0 {
		t.Error("listing is meant to stay open everywhere")
	}
	if j.Sockets != SocketsOpen {
		t.Errorf("clean session with every grant refuses %q sockets", j.Sockets)
	}
}

func TestLandlockTaintedWritesOnlyTheWorkspaceTmpAndHarness(t *testing.T) {
	tr := newLLTree(t)
	harness := filepath.Join(tr.root, "claude-ab12-cwd")
	plantFile(t, harness)
	c := tr.context()
	c.HarnessFiles = []string{harness}
	j := compileLL(t, Policy{Enforce: true, State: Tainted, Grants: AllGrants()}, c, 7)

	for _, p := range []string{filepath.Join(tr.ws, "main.go"), filepath.Join(tr.ws, "new.go"), filepath.Join(tr.tmp, "x"), harness, "/dev/null"} {
		if access(j, p)&llWriteFile == 0 {
			t.Errorf("%s isn't writable in a tainted session", p)
		}
	}
	for _, p := range []string{filepath.Join(tr.home, ".viminfo"), filepath.Join(tr.home, ".cache/go/x"), filepath.Join(tr.root, "other")} {
		if access(j, p)&(llWriteFile|llMakeReg) != 0 {
			t.Errorf("%s is writable in a tainted session", p)
		}
	}
	if access(j, filepath.Join(tr.home, ".aws/credentials"))&llReadFile != 0 {
		t.Error("a tainted session keeps the Cloud grant")
	}
	if j.Sockets != SocketsAll {
		t.Errorf("tainted sockets %q", j.Sockets)
	}
}

func TestLandlockGrantsOffCloseStoresAndUnixSockets(t *testing.T) {
	tr := newLLTree(t)
	plantFile(t, filepath.Join(tr.home, ".config/gh/hosts.yml"))
	j := compileLL(t, Policy{Enforce: true, State: Clean}, tr.context(), 7)
	for _, p := range []string{".aws/credentials", ".config/gh/hosts.yml"} {
		if access(j, filepath.Join(tr.home, p))&llReadFile != 0 {
			t.Errorf("%s readable without its grant", p)
		}
	}
	if j.Sockets != SocketsUnix {
		t.Errorf("sockets %q, want unix", j.Sockets)
	}
}

func TestLandlockDeniesALinkedStoreWhereItPoints(t *testing.T) {
	tr := newLLTree(t)
	elsewhere := filepath.Join(tr.root, "disk", "aws")
	plantFile(t, filepath.Join(elsewhere, "credentials"))
	plantFile(t, filepath.Join(tr.root, "disk", "other"))
	if err := os.RemoveAll(filepath.Join(tr.home, ".aws")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(tr.home, ".aws")); err != nil {
		t.Fatal(err)
	}
	j := compileLL(t, Policy{Enforce: true, State: Clean}, tr.context(), 7)
	if access(j, filepath.Join(elsewhere, "credentials"))&llReadFile != 0 {
		t.Error("the store is readable where its link points")
	}
	if access(j, filepath.Join(tr.root, "disk", "other"))&llReadFile == 0 {
		t.Error("the link's neighbours lost their reads")
	}
}

func TestLandlockOlderABIsHandleLess(t *testing.T) {
	tr := newLLTree(t)
	j := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants()}, tr.context(), 1)
	if j.Handled&(llRefer|llTruncate) != 0 {
		t.Errorf("ABI 1 handles %x", j.Handled)
	}
	for _, r := range j.Rules {
		if r.Access&^j.Handled != 0 {
			t.Errorf("rule %s grants %x beyond the handled set", r.Path, r.Access)
		}
		if !r.Dir && r.Access&^llFileRights != 0 {
			t.Errorf("file rule %s carries directory rights %x", r.Path, r.Access)
		}
	}
	if _, err := CompileLandlock(Baseline(), tr.context(), 0); err == nil {
		t.Error("compiled for a kernel without Landlock")
	}
}

func TestLandlockHashFollowsTheRules(t *testing.T) {
	tr := newLLTree(t)
	a := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants()}, tr.context(), 7)
	b := compileLL(t, Policy{Enforce: true, State: Tainted}, tr.context(), 7)
	if len(a.Hash()) != 64 || a.Hash() == b.Hash() {
		t.Errorf("hashes %s %s", a.Hash(), b.Hash())
	}
}
