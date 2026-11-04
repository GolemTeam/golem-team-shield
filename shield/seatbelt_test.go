//go:build !windows

package shield

import (
	"strings"
	"testing"
)

func mustCompile(t *testing.T, p Policy, c Context) string {
	t.Helper()
	out, err := CompileSeatbelt(p, c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return out
}

func TestCleanWithNoGrantsDeniesCredentialsButLeavesWritesAndNetworkOpen(t *testing.T) {
	out := mustCompile(t, Policy{Enforce: true, State: Clean}, testContext())
	for _, want := range []string{
		`(subpath "/Users/dev/.golem")`,
		`(subpath "/Users/dev/.aws")`,
		`(path-literal "/Users/dev/.ssh/agent.sock")`,
		`(global-name "com.apple.SecurityServer")`,
		`(path-literal "/private/var/run/docker.sock")`,
		`(literal "/Users/dev/.zshrc")`,
		`(literal "/Users/dev/.codex/hooks.json")`,
		`(literal "/Users/dev/.gemini/settings.json")`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ungranted profile lacks %s", want)
		}
	}
	for _, unwanted := range []string{"(deny file-write*)\n", "(deny network*)", "com.apple.dnssd.service"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("clean profile contains %q", unwanted)
		}
	}
}

func TestTaintedClosesNetworkDNSAndWritesAndIgnoresGrants(t *testing.T) {
	p := Policy{Enforce: true, State: Tainted, Grants: Grants{Agent: true, Docker: true, Cloud: true}}
	out := mustCompile(t, p, testContext())
	for _, want := range []string{
		"(deny network*)",
		`(global-name "com.apple.dnssd.service")`,
		"(deny file-write*)\n",
		`(subpath "/Users/dev/src/app")`,
		`(subpath "/private/tmp/golem-turn-1")`,
		`(subpath "/Users/dev/.aws")`,
		`(global-name "com.apple.SecurityServer")`,
		`(path-literal "/private/var/run/docker.sock")`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tainted profile lacks %s", want)
		}
	}
}

func TestGrantsLiftOnlyTheirOwnRules(t *testing.T) {
	c := testContext()
	cases := []struct {
		grants  Grants
		lifted  string
		retains string
	}{
		{Grants{Cloud: true}, `(subpath "/Users/dev/.aws")`, `(global-name "com.apple.SecurityServer")`},
		{Grants{Agent: true}, `(global-name "com.apple.SecurityServer")`, `(subpath "/Users/dev/.aws")`},
		{Grants{Docker: true}, "docker.sock", `(subpath "/Users/dev/.aws")`},
	}
	for _, tc := range cases {
		out := mustCompile(t, Policy{Enforce: true, State: Clean, Grants: tc.grants}, c)
		if strings.Contains(out, tc.lifted) {
			t.Errorf("%+v: still contains %s", tc.grants, tc.lifted)
		}
		if !strings.Contains(out, tc.retains) {
			t.Errorf("%+v: lost %s", tc.grants, tc.retains)
		}
	}
}

func TestBaselineGrantsEverythingButSecretStoresStillHold(t *testing.T) {
	if Baseline().Grants != AllGrants() {
		t.Fatal("grants are on by default")
	}
	out := mustCompile(t, Baseline(), testContext())
	for _, lifted := range []string{`(subpath "/Users/dev/.aws")`, "com.apple.SecurityServer", "docker.sock", `(subpath "/Users/dev/Library/Keychains")`} {
		if strings.Contains(out, lifted) {
			t.Errorf("baseline still denies %s", lifted)
		}
	}
	for _, want := range []string{`(subpath "/Users/dev/.golem")`, `(subpath "/Users/dev/.ssh")`} {
		if !strings.Contains(out, want) {
			t.Errorf("fully granted profile lacks %s", want)
		}
	}
}

// Using the keychain means reading its database (the security tool opens it
// itself), so the database goes with the Agent grant, not the secret stores.
func TestTheKeychainFollowsTheAgentGrant(t *testing.T) {
	for _, tc := range []struct {
		p      Policy
		denied bool
	}{
		{Baseline(), false},
		{Policy{Enforce: true, State: Clean}, true},
		{Policy{Enforce: true, State: Tainted, Grants: AllGrants()}, true},
	} {
		out := mustCompile(t, tc.p, testContext())
		if got := strings.Contains(out, `(subpath "/Users/dev/Library/Keychains")`); got != tc.denied {
			t.Errorf("%+v: keychain denied=%v, want %v", tc.p, got, tc.denied)
		}
	}
}

func TestUnknownStateCompilesAsTainted(t *testing.T) {
	out := mustCompile(t, Policy{Enforce: true, State: "quarantined"}, testContext())
	if !strings.Contains(out, "(deny network*)") {
		t.Fatal("an unknown state must compile as tainted")
	}
}

func TestProtectedDenialsFollowTheTaintedWriteFloor(t *testing.T) {
	c := testContext()
	c.Workspace = []string{"/Users/dev/src/app"}
	c.WorkspaceProtected = []string{"/Users/dev/src/app/.git/hooks"}
	out := mustCompile(t, Policy{Enforce: true, State: Tainted}, c)
	allow := strings.Index(out, "(allow file-write*")
	hooks := strings.Index(out, `(subpath "/Users/dev/src/app/.git/hooks")`)
	golem := strings.LastIndex(out, `(subpath "/Users/dev/.golem")`)
	if allow < 0 || hooks < allow || golem < allow {
		t.Fatalf("protected rules must come after the allow they carve out of (last match wins):\n%s", out)
	}
}

func TestContextIsValidated(t *testing.T) {
	cases := map[string]Context{
		"relative home":        {Home: "dev"},
		"root home":            {Home: "/"},
		"workspace is home":    {Home: "/Users/dev", Workspace: []string{"/Users/dev"}},
		"workspace above home": {Home: "/Users/dev", Workspace: []string{"/Users"}},
		"root workspace":       {Home: "/Users/dev", Workspace: []string{"/"}},
		"relative tmp":         {Home: "/Users/dev", TurnTmp: "tmp"},
		"newline":              {Home: "/Users/dev", ExtraWrite: []string{"/tmp/a\n(allow default)"}},
	}
	for name, c := range cases {
		if _, err := CompileSeatbelt(Baseline(), c); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

func TestPathsAreQuotedAndRegexesEscaped(t *testing.T) {
	c := Context{Home: `/Users/a"b.c`, Workspace: []string{`/Users/x/w"s`}}
	out := mustCompile(t, Policy{Enforce: true, State: Tainted}, c)
	if !strings.Contains(out, `(subpath "/Users/x/w\"s")`) {
		t.Errorf("workspace not quoted:\n%s", out)
	}
	if !strings.Contains(out, `#"^/Users/a\"b\.c/\.ssh/`) {
		t.Errorf("home not escaped in regex:\n%s", out)
	}
}

func TestProfileHashIsStable(t *testing.T) {
	a := mustCompile(t, Baseline(), testContext())
	b := mustCompile(t, Baseline(), testContext())
	if ProfileHash(a) != ProfileHash(b) || len(ProfileHash(a)) != 64 {
		t.Fatal("same policy must hash the same")
	}
}

// Seatbelt's regex engine doesn't support {m,n}: a pattern with one compiles
// and silently never matches.
func TestNoSeatbeltRegexUsesAnInterval(t *testing.T) {
	c := testContext()
	c.HarnessTmp = "/tmp"
	out := mustCompile(t, Policy{Enforce: true, State: Tainted}, c)
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, `#"`); i >= 0 && strings.ContainsAny(line[i:], "{}") {
			t.Errorf("interval in %s", line)
		}
	}
}

// Outside ~/.ssh the socket was never denied, so letting it back only gives a
// command a path it can swap for a link to something that was.
func TestTheAgentSocketIsLetBackOnlyInsideSSH(t *testing.T) {
	c := testContext()
	in := mustCompile(t, Baseline(), c)
	if !strings.Contains(in, `(allow file-read*`) || !strings.Contains(in, `(literal "/Users/dev/.ssh/agent.sock")`) {
		t.Errorf("a socket in ~/.ssh isn't let back:\n%s", in)
	}
	c.AgentSocket = "/private/tmp/com.apple.launchd.x/Listeners"
	out := mustCompile(t, Baseline(), c)
	if strings.Contains(out, "com.apple.launchd.x/Listeners") {
		t.Errorf("a socket outside ~/.ssh was named in the profile:\n%s", out)
	}
}

func TestOnlyPathsInsideSSHAreLetBack(t *testing.T) {
	c := testContext()
	c.SSHReadable = []string{"/Users/dev/.ssh/config.d/work", "/Users/dev/.golem/machine.key", "/Users/dev/.ssh", "/Users/dev/.sshevil/x"}
	out := mustCompile(t, Baseline(), c)
	if !strings.Contains(out, `(literal "/Users/dev/.ssh/config.d/work")`) {
		t.Errorf("an ssh file wasn't let back:\n%s", out)
	}
	for _, bad := range []string{`(literal "/Users/dev/.golem/machine.key")`, `(literal "/Users/dev/.sshevil/x")`} {
		if strings.Contains(out, bad) {
			t.Errorf("%s outside ~/.ssh was let back", bad)
		}
	}
}
