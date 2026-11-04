package shield

import (
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

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
