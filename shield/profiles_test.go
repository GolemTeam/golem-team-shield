package shield

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestEachProfileGivesItsPolicy(t *testing.T) {
	for _, c := range []struct {
		profile string
		cloud   bool
		writes  bool
		proxied bool
	}{
		{ProfileStandard, true, true, false},
		{ProfileStrict, false, true, false},
		{ProfileAllowlist, false, true, true},
	} {
		p := Config{Profile: c.profile}.Policy()
		if p.Grants.Cloud != c.cloud || p.ConfinedWrites() != c.writes || p.Proxied() != c.proxied {
			t.Errorf("%s: %+v", c.profile, p)
		}
		if !p.Enforce || !p.Grants.Agent || !p.Grants.Docker || p.Tainted() {
			t.Errorf("%s changed what profiles leave alone: %+v", c.profile, p)
		}
		if ProfileDescription(c.profile) == "" {
			t.Errorf("%s has no description", c.profile)
		}
	}
	if !slices.Equal(Profiles(), []string{ProfileStandard, ProfileStrict, ProfileAllowlist}) {
		t.Errorf("profiles %v", Profiles())
	}
}

func TestANewInstallIsTheStandardProfile(t *testing.T) {
	if got, want := fmt.Sprintf("%+v", DefaultConfig().Policy()), fmt.Sprintf("%+v", Config{Profile: ProfileStandard}.Policy()); got != want {
		t.Errorf("a new install gets %s, the standard profile %s", got, want)
	}
}

func TestASettingTheFileNamesOutranksItsProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.json")
	body := `{"profile": "strict", "cloud_credentials": true, "network": "allowlist", "allowed_hosts": ["github.com"]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Policy()
	if !p.Grants.Cloud || !p.Proxied() || !slices.Equal(p.AllowedHosts, []string{"github.com"}) || !p.ConfinedWrites() {
		t.Errorf("policy %+v", p)
	}
	if got := c.Overrides(); !slices.Equal(got, []string{"cloud_credentials", "network", "allowed_hosts"}) {
		t.Errorf("overrides %v", got)
	}
}

func TestAnEmptyHostListOutranksAProfileOnlyWhenWritten(t *testing.T) {
	if got := (Config{Profile: ProfileAllowlist}).Overrides(); got != nil {
		t.Errorf("a bare profile overrides %v", got)
	}
	if got := (Config{Profile: ProfileStrict, AllowedHosts: []string{}}).Overrides(); got != nil {
		t.Errorf("an empty list over an empty profile list overrides %v", got)
	}
	c := Config{Profile: ProfileAllowlist, AllowedHosts: []string{}}
	if got := c.Overrides(); !slices.Equal(got, []string{"allowed_hosts"}) || len(c.Policy().AllowedHosts) != 0 {
		t.Errorf("an empty list over the allowlist profile's hosts: overrides %v, policy %+v", got, c.Policy())
	}
}

func TestTheAllowlistProfileOpensTheModelAPIsRegistriesAndGitHosts(t *testing.T) {
	p := Config{Profile: ProfileAllowlist}.Policy()
	if !slices.Equal(p.AllowedHosts, []string{"@model-apis", "@package-registries", "@git-hosts"}) {
		t.Errorf("allowed hosts %v", p.AllowedHosts)
	}
	if hosts := ExpandHosts(p.AllowedHosts); !slices.Contains(hosts, "github.com") || !slices.Contains(hosts, "api.anthropic.com") || !slices.Contains(hosts, "pypi.org") {
		t.Errorf("expanded %v", hosts)
	}
}

func TestAMoveToAProfileKeepsOnlyWhatIsTighter(t *testing.T) {
	off, on := false, true
	c := Config{CloudCredentials: &off, Writes: WritesWorkspace, Network: NetworkOpen, AllowedHosts: []string{}}
	if got := c.TighterThan(ProfileStandard); !slices.Equal(got, []string{"cloud_credentials"}) {
		t.Errorf("to standard keeps %v", got)
	}
	c = Config{CloudCredentials: &on, Writes: WritesAnywhere, Network: NetworkAllowlist, AllowedHosts: []string{"github.com"}}
	if got := c.TighterThan(ProfileStrict); !slices.Equal(got, []string{"network", "allowed_hosts"}) {
		t.Errorf("to strict keeps %v", got)
	}
	if got := c.TighterThan(ProfileAllowlist); !slices.Equal(got, []string{"allowed_hosts"}) {
		t.Errorf("to allowlist keeps %v", got)
	}
}
