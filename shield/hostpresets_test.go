package shield

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestEveryPresetHostIsAnAllowedHostEntry(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range HostPresets {
		if !strings.HasPrefix(p.Name, "@") || p.Label == "" || len(p.Hosts) == 0 {
			t.Errorf("preset %+v", p)
		}
		if seen[p.Name] {
			t.Errorf("%s twice", p.Name)
		}
		seen[p.Name] = true
		if err := CheckHost(p.Name); err != nil {
			t.Errorf("%s is refused: %v", p.Name, err)
		}
		for _, h := range p.Hosts {
			if err := CheckHost(h); err != nil || h == "*" || isLoopbackName(h) {
				t.Errorf("%s: %q is not a plain public host entry (%v)", p.Name, h, err)
			}
		}
	}
}

func TestThePresetsCoverWhatTheirNamesSay(t *testing.T) {
	for name, hosts := range map[string][]string{
		"@model-apis":         {"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"},
		"@package-registries": {"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "proxy.golang.org", "index.crates.io", "repo1.maven.org", "rubygems.org"},
		"@git-hosts":          {"github.com", "*.githubusercontent.com", "gitlab.com"},
	} {
		p, ok := HostPresetNamed(name)
		if !ok {
			t.Errorf("no %s", name)
			continue
		}
		for _, h := range hosts {
			if !slices.Contains(p.Hosts, h) {
				t.Errorf("%s lacks %s", name, h)
			}
		}
	}
}

func TestExpandHostsPutsEachPresetsHostsInItsPlace(t *testing.T) {
	got := ExpandHosts([]string{"example.com", "@git-hosts", "github.com", "@nonsense"})
	git, _ := HostPresetNamed("@git-hosts")
	want := append([]string{"example.com"}, git.Hosts...)
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAPresetNameMustBeOneThisBuildKnows(t *testing.T) {
	for _, h := range []string{"@nonsense", "@", "@Model-APIs"} {
		if CheckHost(h) == nil {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestTheProxyLetsOutAPresetsHosts(t *testing.T) {
	p := NewProxy([]string{"@git-hosts", "@nonsense"})
	p.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	}
	for host, allowed := range map[string]bool{"github.com": true, "raw.githubusercontent.com": true, "example.com": false} {
		if ok, _ := p.match(host); ok != allowed {
			t.Errorf("%s: allowed %v", host, ok)
		}
	}
}
