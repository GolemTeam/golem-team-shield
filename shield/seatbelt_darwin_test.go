//go:build darwin

package shield

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fakeHome struct {
	home, ws, tmp string
}

func newFakeHome(t *testing.T) fakeHome {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := fakeHome{home: filepath.Join(root, "home"), ws: filepath.Join(root, "ws"), tmp: filepath.Join(root, "turn")}
	write(t, filepath.Join(f.home, ".ssh", "id_ed25519"), privateKey("OPENSSH"))
	write(t, filepath.Join(f.home, ".ssh", "config"), "Host *")
	write(t, filepath.Join(f.home, ".aws", "credentials"), "AKIA")
	write(t, filepath.Join(f.home, ".golem", "machine.key"), "KEY")
	write(t, filepath.Join(f.home, ".zshrc"), "")
	write(t, filepath.Join(f.ws, "README"), "")
	if err := os.MkdirAll(f.tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

// context is what the shim would build, including its scan of ~/.ssh.
func (f fakeHome) context() Context {
	return Context{Home: f.home, Workspace: []string{f.ws}, TurnTmp: f.tmp, SSHReadable: SSHReadable(f.home)}
}

func privateKey(kind string) string {
	return "-----BEGIN " + kind + " PRIVATE KEY-----\nPRIVATE\n-----END " + kind + " PRIVATE KEY-----\n"
}

// Seatbelt doesn't nest: run inside a sandbox (an agent's own jailed shell),
// these tests can't apply a profile at all, so they say so instead of failing.
var nested = exec.Command(SandboxExec, "-p", "(version 1)(allow default)", "/usr/bin/true").Run() != nil

// jailed runs script under the compiled profile and reports whether it exited 0.
func jailed(t *testing.T, p Policy, c Context, script string) bool {
	t.Helper()
	if nested {
		t.Skip("already inside a sandbox; Seatbelt profiles don't nest")
	}
	profile, err := CompileSeatbelt(p, c)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/sandbox-exec", "-p", profile, "/bin/zsh", "-c", script).CombinedOutput()
	if err != nil && strings.Contains(string(out), "sandbox-exec:") {
		t.Fatalf("profile rejected: %s\n%s", out, profile)
	}
	return err == nil
}

func TestEveryPolicyCompilesToAProfileSeatbeltAccepts(t *testing.T) {
	f := newFakeHome(t)
	c := f.context()
	c.AgentSocket = filepath.Join(f.home, ".ssh", "agent.sock")
	c.WorkspaceProtected = []string{filepath.Join(f.ws, ".git", "hooks")}
	c.ExtraWrite = []string{"/tmp"}
	c.RunTag = "01TEST-run"
	for _, state := range []State{Clean, Tainted} {
		for bits := 0; bits < 8; bits++ {
			g := Grants{Agent: bits&1 != 0, Docker: bits&2 != 0, Cloud: bits&4 != 0}
			if !jailed(t, Policy{Enforce: true, State: state, Grants: g}, c, "true") {
				t.Errorf("%s %+v: true failed", state, g)
			}
		}
	}
}

func TestCleanJail(t *testing.T) {
	f := newFakeHome(t)
	p, c := Policy{Enforce: true, State: Clean}, f.context()
	cases := []struct {
		name, script string
		allowed      bool
	}{
		{"private key", "cat " + f.home + "/.ssh/id_ed25519", false},
		{"key via absolute bash", "/bin/bash -c 'cat " + f.home + "/.ssh/id_ed25519'", false},
		{"key via base64 pipe", "echo " + b64("cat "+f.home+"/.ssh/id_ed25519") + " | base64 -d | sh", false},
		{"key via symlink", "ln -s " + f.home + "/.ssh " + f.ws + "/leak && cat " + f.ws + "/leak/id_ed25519", false},
		{"key via hardlink", "ln " + f.home + "/.ssh/id_ed25519 " + f.ws + "/k && cat " + f.ws + "/k", false},
		{"ssh config", "cat " + f.home + "/.ssh/config", true},
		{"cloud credentials without the grant", "cat " + f.home + "/.aws/credentials", false},
		{"golem key", "cat " + f.home + "/.golem/machine.key", false},
		{"golem tamper", "rm " + f.home + "/.golem/machine.key", false},
		{"shell rc persistence", "echo x >> " + f.home + "/.zshrc", false},
		{"launch agent", "mkdir -p " + f.home + "/Library/LaunchAgents && touch " + f.home + "/Library/LaunchAgents/x.plist", false},
		{"ordinary home write", "touch " + f.home + "/notes.txt", true},
		{"workspace write", "touch " + f.ws + "/out", true},
	}
	for _, tc := range cases {
		if got := jailed(t, p, c, tc.script); got != tc.allowed {
			t.Errorf("%s: allowed=%v, want %v", tc.name, got, tc.allowed)
		}
	}
}

func TestCloudGrantOpensOnlyCloudStores(t *testing.T) {
	f := newFakeHome(t)
	p := Policy{Enforce: true, State: Clean, Grants: Grants{Cloud: true}}
	if !jailed(t, p, f.context(), "cat "+f.home+"/.aws/credentials") {
		t.Error("granted cloud credentials unreadable")
	}
	if jailed(t, p, f.context(), "cat "+f.home+"/.ssh/id_ed25519") {
		t.Error("the cloud grant opened a private key")
	}
}

func TestTaintedJail(t *testing.T) {
	f := newFakeHome(t)
	p := Policy{Enforce: true, State: Tainted, Grants: Grants{Cloud: true}}
	c := f.context()
	cases := []struct {
		name, script string
		allowed      bool
	}{
		{"workspace write", "touch " + f.ws + "/out", true},
		{"turn tmp write", "touch " + f.tmp + "/x", true},
		{"home write", "touch " + f.home + "/notes.txt", false},
		{"grant ignored", "cat " + f.home + "/.aws/credentials", false},
		{"dns", "dscacheutil -q host -a name golem-shield-test.example.com | grep -q address", false},
		{"backgrounded child", "nohup sh -c 'cat " + f.home + "/.ssh/id_ed25519 > " + f.ws + "/bg' >/dev/null 2>&1 & wait; test -s " + f.ws + "/bg", false},
	}
	for _, tc := range cases {
		if got := jailed(t, p, c, tc.script); got != tc.allowed {
			t.Errorf("%s: allowed=%v, want %v", tc.name, got, tc.allowed)
		}
	}
}

func TestTaintedRefusesEvenLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	script := "nc -z -G 2 127.0.0.1 " + itoa(port)
	f := newFakeHome(t)
	if !jailed(t, Baseline(), f.context(), script) {
		t.Error("a clean session can't reach loopback")
	}
	if jailed(t, Policy{Enforce: true, State: Tainted}, f.context(), script) {
		t.Error("a tainted session reached loopback")
	}
}

func TestBaselineGrantsCloudButNeverKeysOrGolem(t *testing.T) {
	f := newFakeHome(t)
	if !jailed(t, Baseline(), f.context(), "cat "+f.home+"/.aws/credentials") {
		t.Error("the baseline withheld a granted cloud credential")
	}
	for _, p := range []string{"/.ssh/id_ed25519", "/.golem/machine.key"} {
		if jailed(t, Baseline(), f.context(), "cat "+f.home+p) {
			t.Errorf("the baseline read %s", p)
		}
	}
}

// Claude Code's project settings override the user's env, and the agents'
// project hooks and MCP servers run outside the jail, so a command that could
// write them could run anything at the agent's next call.
func TestWorkspaceAgentFilesAreUnwritable(t *testing.T) {
	f := newFakeHome(t)
	write(t, filepath.Join(f.ws, ".cursor", "rules", "style.md"), "")
	write(t, filepath.Join(f.ws, ".github", "workflows", "ci.yml"), "")
	for _, state := range []State{Clean, Tainted} {
		p := Policy{Enforce: true, State: state}
		for _, script := range []string{
			"mkdir -p " + f.ws + "/.claude && echo '{}' > " + f.ws + "/.claude/settings.json",
			"echo '{}' > " + f.ws + "/.cursor/hooks.json",
			"echo '{}' > " + f.ws + "/.mcp.json",
			"mkdir -p " + f.ws + "/.codex && echo x > " + f.ws + "/.codex/config.toml",
			"mkdir -p " + f.ws + "/.agents",
			"mkdir -p " + f.ws + "/.github/hooks",
			"mkdir -p " + f.ws + "/.devin",
			"mkdir " + f.ws + "/x && echo '{}' > " + f.ws + "/x/hooks.json && mv " + f.ws + "/x " + f.ws + "/.gemini",
			"mv " + f.ws + "/.cursor " + f.ws + "/cursor-was",
		} {
			if jailed(t, p, f.context(), script) {
				t.Errorf("%s: %s", state, script)
			}
		}
		for _, script := range []string{
			"echo x > " + f.ws + "/.cursor/rules/style.md",
			"echo x > " + f.ws + "/.github/workflows/ci.yml",
			"mkdir -p " + f.ws + "/src/" + string(state) + " && echo x > " + f.ws + "/new-" + string(state),
		} {
			if !jailed(t, p, f.context(), script) {
				t.Errorf("%s: ordinary work refused: %s", state, script)
			}
		}
	}
}

func TestTaintedStillWritesClaudeCodesCwdFile(t *testing.T) {
	f := newFakeHome(t)
	c := f.context()
	c.HarnessTmp = filepath.Dir(f.tmp)
	p := Policy{Enforce: true, State: Tainted}
	if !jailed(t, p, c, "pwd -P >| "+c.HarnessTmp+"/claude-3f2a-cwd") {
		t.Error("the cwd read-back file is unwritable")
	}
	if jailed(t, p, c, "echo x > "+c.HarnessTmp+"/claude-3f2a-cwd.sh") {
		t.Error("the harness tmp is writable beyond the cwd file")
	}
}

// gh reads its hosts file on every command, so it goes with the Agent grant
// rather than the always-unreadable stores: on, gh works; off, the file (and
// any token kept in it) is out of reach.
func TestGhHostsFileFollowsTheAgentGrant(t *testing.T) {
	f := newFakeHome(t)
	write(t, filepath.Join(f.home, ".config", "gh", "hosts.yml"), "github.com:\n  user: dev\n")
	read := "cat " + f.home + "/.config/gh/hosts.yml"
	if !jailed(t, Baseline(), f.context(), read) {
		t.Error("with the Agent grant on, gh's hosts file is unreadable")
	}
	if jailed(t, Policy{Enforce: true, State: Clean}, f.context(), read) {
		t.Error("with the Agent grant off, gh's hosts file is readable")
	}
	if jailed(t, Policy{Enforce: true, State: Tainted, Grants: AllGrants()}, f.context(), read) {
		t.Error("a locked-down session read gh's hosts file")
	}
}

// git signs commits with an SSH key through the agent and needs the public
// key file to do it, so public keys stay readable while private ones don't.
func TestPublicKeysStayReadableForCommitSigning(t *testing.T) {
	f := newFakeHome(t)
	files := map[string]string{
		"id_ed25519.pub":                  "ssh-ed25519 AAAA",
		"id_yubikey_signing_personal.pub": "sk-ssh-ed25519@openssh.com AAAA",
		"id_yubikey_signing_personal":     privateKey("OPENSSH"),
		"deploy_key":                      privateKey("OPENSSH"),
		"deploy_key.pub":                  "ssh-rsa AAAA",
		"github.pem":                      privateKey("RSA"),
		"google_compute_engine":           privateKey("RSA"),
		"known_hosts":                     "github.com ssh-ed25519 AAAA",
		"allowed_signers":                 "dev@x ssh-ed25519 AAAA",
	}
	for name, body := range files {
		write(t, filepath.Join(f.home, ".ssh", name), body)
	}
	for name, readable := range map[string]bool{
		"id_ed25519.pub":                  true,
		"id_yubikey_signing_personal.pub": true,
		"deploy_key.pub":                  true,
		"id_ed25519":                      false,
		"id_yubikey_signing_personal":     false,
		"deploy_key":                      false,
		"github.pem":                      false,
		"google_compute_engine":           false,
		"known_hosts":                     true,
		"allowed_signers":                 true,
	} {
		if got := jailed(t, Baseline(), f.context(), "cat "+f.home+"/.ssh/"+name); got != readable {
			t.Errorf("%s readable=%v, want %v", name, got, readable)
		}
	}
}

// With every grant on, ssh's own files come back wherever they live in ~/.ssh,
// and a private key stays denied whatever it is called.
func TestSSHFilesAreReadByContentNotName(t *testing.T) {
	f := newFakeHome(t)
	readable := map[string]string{
		"config.d/work":     "Host work\n  User don\n",
		"known_hosts.d/gh":  "github.com ssh-ed25519 AAAA\n",
		"1Password/config":  "Host *\n  IdentityAgent ~/.1password/agent.sock\n",
		"conf.d/a/b/nested": "Host nested\n",
	}
	denied := map[string]string{
		"work_laptop":     privateKey("OPENSSH"),
		"legacy_rsa":      privateKey("RSA"),
		"pkcs8.key.txt":   privateKey(""),
		"server.ppk":      "PuTTY-User-Key-File-3: ssh-ed25519\n",
		"binary_blob":     "a\x00b",
		"config.d/secret": privateKey("EC"),
	}
	for name, body := range readable {
		write(t, filepath.Join(f.home, ".ssh", name), body)
	}
	for name, body := range denied {
		write(t, filepath.Join(f.home, ".ssh", name), body)
	}
	c := f.context()
	for name := range readable {
		if !jailed(t, Baseline(), c, "cat "+f.home+"/.ssh/"+name) {
			t.Errorf("%s is ssh's own file and should be readable", name)
		}
	}
	for name := range denied {
		if jailed(t, Baseline(), c, "cat "+f.home+"/.ssh/"+name) {
			t.Errorf("%s holds a secret and was readable", name)
		}
	}
	if !jailed(t, Baseline(), c, "ls "+f.home+"/.ssh/config.d") {
		t.Error("an Include glob needs to list config.d")
	}
	if jailed(t, Baseline(), c, "echo x >> "+f.home+"/.ssh/config.d/work") {
		t.Error("~/.ssh became writable")
	}
}

func TestWorkspaceWritesJail(t *testing.T) {
	f := newFakeHome(t)
	write(t, filepath.Join(f.home, "Library", "Caches", "x"), "")
	write(t, filepath.Join(f.home, "go", "bin", "tool"), "")
	p := Policy{Enforce: true, State: Clean, Grants: AllGrants(), Writes: WritesWorkspace, AllowWrite: []string{"~/go/bin"}}
	c := f.context()
	c.SystemTmp = []string{"/tmp"}
	for _, bits := range []int{0, 7} {
		g := Grants{Agent: bits&1 != 0, Docker: bits&2 != 0, Cloud: bits&4 != 0}
		if !jailed(t, Policy{Enforce: true, State: Clean, Grants: g, Writes: WritesWorkspace, Network: NetworkAllowlist}, c, "true") {
			t.Errorf("%+v: true failed", g)
		}
	}
	cases := []struct {
		name, script string
		allowed      bool
	}{
		{"workspace write", "touch " + f.ws + "/out", true},
		{"turn tmp write", "touch " + f.tmp + "/x", true},
		{"system tmp write", "f=$(mktemp /tmp/golem-shield-test.XXXXXX) && rm $f", true},
		{"cache write", "mkdir -p " + f.home + "/Library/Caches/go-build/aa && touch " + f.home + "/Library/Caches/go-build/aa/x", true},
		{"new cache dir", "mkdir -p " + f.home + "/.npm/_cacache", true},
		{"allow_write", "touch " + f.home + "/go/bin/new", true},
		{"home write", "touch " + f.home + "/notes.txt", false},
		{"shell rc", "echo x >> " + f.home + "/.zshrc", false},
		{"key still unreadable", "cat " + f.home + "/.ssh/id_ed25519", false},
	}
	for _, tc := range cases {
		if got := jailed(t, p, c, tc.script); got != tc.allowed {
			t.Errorf("%s: allowed=%v, want %v", tc.name, got, tc.allowed)
		}
	}
}

func TestAllowlistedNetworkReachesOnlyTheProxy(t *testing.T) {
	listen := func() (int, func()) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
	}
	proxy, closeProxy := listen()
	defer closeProxy()
	other, closeOther := listen()
	defer closeOther()
	f := newFakeHome(t)
	c := f.context()
	c.ProxyPort = proxy
	p := Policy{Enforce: true, State: Clean, Grants: AllGrants(), Network: NetworkAllowlist}
	short, err := os.MkdirTemp("/tmp", "gs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(short)
	sock := filepath.Join(short, "s")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	go func() {
		for {
			conn, err := ul.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	cases := []struct {
		name, script string
		allowed      bool
	}{
		{"the proxy", "nc -z -G 2 127.0.0.1 " + itoa(proxy), true},
		{"another loopback port", "nc -z -G 2 127.0.0.1 " + itoa(other), false},
		{"a public address", "nc -z -G 2 1.1.1.1 443", false},
		{"dns", "dscacheutil -q host -a name golem-shield-test.example.com | grep -q address", false},
		{"a unix socket", "zmodload zsh/net/socket && zsocket " + sock, true},
		{"home write still open", "touch " + f.home + "/notes.txt", true},
	}
	for _, tc := range cases {
		if got := jailed(t, p, c, tc.script); got != tc.allowed {
			t.Errorf("%s: allowed=%v, want %v", tc.name, got, tc.allowed)
		}
	}
}

func TestAConfinedNetworkHandsNothingToAnotherApp(t *testing.T) {
	f := newFakeHome(t)
	c := f.context()
	c.ProxyPort = 1
	script := "osascript -e 'return 1'"
	if !jailed(t, Policy{Enforce: true, State: Clean, Grants: AllGrants()}, c, script) {
		t.Error("osascript doesn't run with the network open")
	}
	for _, p := range []Policy{
		{Enforce: true, State: Clean, Grants: AllGrants(), Network: NetworkAllowlist},
		{Enforce: true, State: Tainted},
	} {
		if jailed(t, p, c, script) {
			t.Errorf("%s/%s: osascript ran", p.State, p.Network)
		}
		if !jailed(t, p, c, "git --version && /usr/bin/xcrun --find clang") {
			t.Errorf("%s/%s: ordinary tools broke", p.State, p.Network)
		}
	}
}

func TestLocalhostInTheListOpensLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	f := newFakeHome(t)
	c := f.context()
	c.ProxyPort = 1
	script := "nc -z -G 2 127.0.0.1 " + itoa(ln.Addr().(*net.TCPAddr).Port)
	if jailed(t, Policy{Enforce: true, State: Clean, Grants: AllGrants(), Network: NetworkAllowlist, AllowedHosts: []string{"github.com"}}, c, script) {
		t.Error("loopback was reachable without localhost in the list")
	}
	local := Policy{Enforce: true, State: Clean, Grants: AllGrants(), Network: NetworkAllowlist, AllowedHosts: []string{"localhost"}}
	if !jailed(t, local, c, script) {
		t.Error("localhost in the list didn't open loopback")
	}
	if jailed(t, local, c, "nc -z -G 2 1.1.1.1 443") {
		t.Error("localhost in the list opened the internet")
	}
}
