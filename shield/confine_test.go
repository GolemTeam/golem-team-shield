package shield

import (
	"path/filepath"
	"testing"
)

func TestUnknownWritesAndNetworkReadAsTheTighterOnes(t *testing.T) {
	cases := []struct {
		p                Policy
		confined, proxed bool
	}{
		{Policy{State: Clean}, false, false},
		{Policy{State: Clean, Writes: WritesAnywhere, Network: NetworkOpen}, false, false},
		{Policy{State: Clean, Writes: WritesWorkspace, Network: NetworkAllowlist}, true, true},
		{Policy{State: Clean, Writes: "sealed", Network: "offline"}, true, true},
		{Policy{State: Tainted, Writes: WritesWorkspace, Network: NetworkAllowlist}, false, false},
	}
	for _, c := range cases {
		if c.p.ConfinedWrites() != c.confined || c.p.Proxied() != c.proxed {
			t.Errorf("%+v: confined %v proxied %v", c.p, c.p.ConfinedWrites(), c.p.Proxied())
		}
	}
}

func TestCheckHost(t *testing.T) {
	for _, ok := range []string{"github.com", "*.githubusercontent.com", "*", "registry.npmjs.org", "10.0.0.7", "[::1]", "x-y.example.co.uk"} {
		if err := CheckHost(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "GitHub.com", "*.com", "a..b", "-a.com", "https://x.com", "x.com:443", "*x.com", "x.*.com", "a b.com"} {
		if CheckHost(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWritePathsNeverOpenHome(t *testing.T) {
	for _, bad := range []string{"", "~", "~/", "relative/dir", "./x", "~/\nx"} {
		if CheckWritePath(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"~/go/bin", "/opt/homebrew", `C:\tools`} {
		if err := CheckWritePath(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	got := ExpandWritePaths([]string{"~/go/bin", "/Users", "/Users/dev", "/", "/opt/homebrew", "~/../dev"}, "/Users/dev")
	want := []string{"/Users/dev/go/bin", "/opt/homebrew"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("expanded %v, want %v", got, want)
	}
}

func TestWriteRootsDependOnTheStateAndTheSetting(t *testing.T) {
	c := testContext()
	c.SystemTmp = []string{"/tmp"}
	if r := writeRoots(Policy{State: Clean}, c, "darwin"); r != nil {
		t.Errorf("anywhere has roots %v", r)
	}
	tainted := writeRoots(Policy{State: Tainted, Writes: WritesWorkspace, AllowWrite: []string{"~/go/bin"}}, c, "darwin")
	for _, r := range tainted {
		if r == "/tmp" || r == "/Users/dev/go/bin" || r == "/Users/dev/Library/Caches" {
			t.Errorf("a tainted session may write %s", r)
		}
	}
	confined := writeRoots(Policy{State: Clean, Writes: WritesWorkspace, AllowWrite: []string{"~/go/bin"}}, c, "darwin")
	for _, want := range []string{"/Users/dev/src/app", "/tmp/golem-turn-1", "/tmp", "/Users/dev/.cache", "/Users/dev/go/pkg/mod", "/Users/dev/Library/Caches", "/Users/dev/go/bin"} {
		if !contains(confined, want) {
			t.Errorf("confined roots %v lack %s", confined, want)
		}
	}
	if contains(writeRoots(Policy{State: Clean, Writes: WritesWorkspace}, c, "linux"), filepath.Join(c.Home, "Library/Caches")) {
		t.Error("Linux got macOS's cache directory")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
