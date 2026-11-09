package shield

import (
	"fmt"
	"slices"
	"strings"
)

// The profiles are named starting points for shield.json. A profile decides
// only ProfileSettings; a setting the file names itself outranks it.
const (
	ProfileStandard  = "standard"
	ProfileStrict    = "strict"
	ProfileAllowlist = "allowlist"
)

type configProfile struct {
	name        string
	cloud       bool
	writes      Writes
	network     Network
	hosts       []string
	description string
}

var profiles = []configProfile{
	{ProfileStandard, true, WritesWorkspace, NetworkOpen, nil,
		"writes kept to the project, temp and tool caches; cloud credentials and the network open"},
	{ProfileStrict, false, WritesWorkspace, NetworkOpen, nil,
		"writes kept to the project, temp and tool caches; no cloud credentials; the network open"},
	{ProfileAllowlist, false, WritesWorkspace, NetworkAllowlist, []string{"@model-apis", "@package-registries", "@git-hosts"},
		"writes kept to the project, temp and tool caches; no cloud credentials; only the model APIs, package registries and git hosts reachable"},
}

var ProfileSettings = []string{"cloud_credentials", "writes", "network", "allowed_hosts"}

func Profiles() []string {
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.name
	}
	return names
}

func findProfile(name string) (configProfile, bool) {
	i := slices.IndexFunc(profiles, func(p configProfile) bool { return p.name == name })
	if i < 0 {
		return configProfile{}, false
	}
	return profiles[i], true
}

func ProfileDescription(name string) string {
	p, _ := findProfile(name)
	return p.description
}

func CheckProfile(name string) error {
	if _, ok := findProfile(name); name == "" || ok {
		return nil
	}
	return fmt.Errorf("profile is %q; it must be one of %s", name, strings.Join(Profiles(), ", "))
}

// Resolved is c with its profile's settings filled in wherever c names none.
func (c Config) Resolved() Config {
	p, ok := findProfile(c.Profile)
	if !ok {
		return c
	}
	if c.CloudCredentials == nil {
		cloud := p.cloud
		c.CloudCredentials = &cloud
	}
	if c.Writes == "" {
		c.Writes = p.writes
	}
	if c.Network == "" {
		c.Network = p.network
	}
	if c.AllowedHosts == nil {
		c.AllowedHosts = slices.Clone(p.hosts)
	}
	return c
}

// Overrides are the settings c names itself that differ from its profile.
func (c Config) Overrides() []string {
	p, ok := findProfile(c.Profile)
	if !ok {
		return nil
	}
	var out []string
	if c.CloudCredentials != nil && *c.CloudCredentials != p.cloud {
		out = append(out, "cloud_credentials")
	}
	if c.Writes != "" && c.Writes != p.writes {
		out = append(out, "writes")
	}
	if c.Network != "" && c.Network != p.network {
		out = append(out, "network")
	}
	if c.AllowedHosts != nil && !slices.Equal(c.AllowedHosts, p.hosts) && len(c.AllowedHosts)+len(p.hosts) > 0 {
		out = append(out, "allowed_hosts")
	}
	return out
}

// TighterThan names the settings c names itself that are tighter than the
// profile would make them, which a move to that profile keeps. A list of
// hosts counts as tighter: someone chose it.
func (c Config) TighterThan(name string) []string {
	p, ok := findProfile(name)
	if !ok {
		return nil
	}
	var out []string
	if c.CloudCredentials != nil && !*c.CloudCredentials && p.cloud {
		out = append(out, "cloud_credentials")
	}
	if c.Writes == WritesWorkspace && p.writes != WritesWorkspace {
		out = append(out, "writes")
	}
	if c.Network == NetworkAllowlist && p.network != NetworkAllowlist {
		out = append(out, "network")
	}
	if len(c.AllowedHosts) > 0 {
		out = append(out, "allowed_hosts")
	}
	return out
}
