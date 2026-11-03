//go:build !windows

package shield

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltWorkspaceWritesKeepTheNetworkAndTheDenials(t *testing.T) {
	c := testContext()
	c.SystemTmp = []string{"/var/folders/xy/T"}
	out := mustCompile(t, Policy{Enforce: true, State: Clean, Grants: AllGrants(), Writes: WritesWorkspace, AllowWrite: []string{"~/go/bin"}}, c)
	floor := strings.Index(out, "(deny file-write*)\n")
	allow := ruleBlock(out, "(allow file-write*")
	if floor < 0 || strings.Index(out, "(allow file-write*") < floor {
		t.Fatalf("no write floor before the allows:\n%s", out)
	}
	for _, want := range []string{
		`(subpath "/Users/dev/src/app")`, `(subpath "/private/tmp/golem-turn-1")`, `(subpath "/private/var/folders/xy/T")`,
		`(subpath "/Users/dev/Library/Caches")`, `(subpath "/Users/dev/.npm")`, `(subpath "/Users/dev/go/bin")`,
	} {
		if !strings.Contains(allow, want) {
			t.Errorf("writable roots lack %s", want)
		}
	}
	if i := strings.LastIndex(out, `(literal "/Users/dev/.zshrc")`); i < strings.Index(out, "(allow file-write*") {
		t.Error("protected writes don't come after the roots")
	}
	if strings.Contains(out, "deny network") || strings.Contains(out, "com.apple.dnssd.service") {
		t.Error("workspace writes took the network")
	}
}

func TestSeatbeltAllowlistLetsOutOnlyTheProxyAndKeepsGrantedSockets(t *testing.T) {
	c := testContext()
	c.ProxyPort = 41234
	p := Policy{Enforce: true, State: Clean, Grants: Grants{Agent: true}, Network: NetworkAllowlist, AllowedHosts: []string{"github.com"}}
	out := mustCompile(t, p, c)
	net := strings.Index(out, "(deny network-outbound")
	if net < 0 {
		t.Fatalf("no outbound denial:\n%s", out)
	}
	allow := ruleBlock(out, "(allow network-outbound")
	if !strings.Contains(allow, `(remote ip "localhost:41234")`) || !strings.Contains(allow, `(remote unix-socket (path-regex #"^/"))`) {
		t.Errorf("allow block %q", allow)
	}
	if strings.Count(out, "(remote ip ") != 1 {
		t.Error("something besides the proxy is let out")
	}
	if !strings.Contains(out, `(global-name "com.apple.dnssd.service")`) {
		t.Error("DNS stays open")
	}
	docker := strings.Index(out, `(path-literal "/private/var/run/docker.sock")`)
	if docker < net {
		t.Error("the Docker grant's socket denial must come after the Unix socket allow, or the allow wins")
	}
	if strings.Contains(out, "(deny network*)") {
		t.Error("an allowlisted network is not a tainted one")
	}
	tainted := mustCompile(t, Policy{Enforce: true, State: Tainted, Network: NetworkAllowlist}, c)
	if strings.Contains(tainted, "localhost:41234") || !strings.Contains(tainted, "(deny network*)") {
		t.Error("taint must take the proxy too")
	}
}

func TestLandlockWorkspaceWritesOnlyTheRoots(t *testing.T) {
	tr := newLLTree(t)
	h := func(p string) string { return filepath.Join(tr.home, p) }
	plantFile(t, h("go/bin/tool"))
	plantFile(t, h(".npm/_cacache/x"))
	plantFile(t, filepath.Join(tr.root, "systmp", "x"))
	c := tr.context()
	c.SystemTmp = []string{filepath.Join(tr.root, "systmp")}
	j := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants(), Writes: WritesWorkspace, AllowWrite: []string{"~/go/bin"}}, c, 7)
	for _, p := range []string{"src/app/main.go", ".cache/go/x", ".npm/_cacache/x", "go/bin/tool"} {
		if access(j, h(p))&llWriteFile == 0 {
			t.Errorf("%s isn't writable", p)
		}
	}
	if access(j, filepath.Join(tr.root, "systmp", "x"))&llWriteFile == 0 || access(j, filepath.Join(tr.tmp, "new"))&llMakeReg == 0 {
		t.Error("temp isn't writable")
	}
	for _, p := range []string{".viminfo", ".config/nvim/init.lua", ".claude/projects/x.jsonl", "../outside/x", ".zshrc"} {
		if access(j, h(p))&llWriteFile != 0 {
			t.Errorf("%s is writable outside the roots", p)
		}
	}
	if access(j, h(".config/nvim/init.lua"))&llReadFile == 0 {
		t.Error("reads went with the writes")
	}
	if j.Sockets != SocketsOpen || j.Proxy != 0 {
		t.Errorf("workspace writes changed the network: %+v", j)
	}
}

func TestLandlockAllowlistCarriesTheProxyPort(t *testing.T) {
	tr := newLLTree(t)
	c := tr.context()
	c.ProxyPort = 41234
	j := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants(), Network: NetworkAllowlist}, c, 7)
	if j.Proxy != 41234 {
		t.Errorf("proxy %d", j.Proxy)
	}
	if m, inet := j.NetFallback(); m != NetLandlockPort || inet != InetTCPOnly {
		t.Errorf("ABI 7 falls back to %s/%s", m, inet)
	}
	old := compileLL(t, Policy{Enforce: true, State: Clean, Grants: AllGrants(), Network: NetworkAllowlist}, c, 3)
	if m, inet := old.NetFallback(); m != NetNone || inet != InetAll {
		t.Errorf("ABI 3 falls back to %s/%s", m, inet)
	}
	tainted := compileLL(t, Policy{Enforce: true, State: Tainted, Network: NetworkAllowlist}, c, 7)
	if tainted.Proxy != 0 || tainted.Sockets != SocketsAll {
		t.Errorf("tainted %+v", tainted)
	}
}
