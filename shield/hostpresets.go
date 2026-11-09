package shield

import (
	"slices"
	"strings"
)

// HostPreset is a name allowed_hosts takes for a set of hosts, so one entry
// opens what a kind of work needs. The console and core-api restate the
// names, and tests hold them to this table.
type HostPreset struct {
	Name  string
	Label string
	Hosts []string
}

var HostPresets = []HostPreset{
	{"@model-apis", "Model APIs", []string{
		"api.anthropic.com",
		"api.openai.com",
		"generativelanguage.googleapis.com",
		"api.mistral.ai",
		"api.cohere.com",
		"api.groq.com",
		"api.deepseek.com",
		"api.x.ai",
		"openrouter.ai",
		"api.together.xyz",
	}},
	{"@package-registries", "Package registries", []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"repo.yarnpkg.com",
		"pypi.org",
		"files.pythonhosted.org",
		"proxy.golang.org",
		"sum.golang.org",
		"crates.io",
		"index.crates.io",
		"static.crates.io",
		"repo.maven.apache.org",
		"repo1.maven.org",
		"rubygems.org",
		"index.rubygems.org",
	}},
	{"@git-hosts", "Git hosts", []string{
		"github.com",
		"api.github.com",
		"codeload.github.com",
		"*.githubusercontent.com",
		"gitlab.com",
	}},
}

func HostPresetNames() []string {
	names := make([]string, len(HostPresets))
	for i, p := range HostPresets {
		names[i] = p.Name
	}
	return names
}

func HostPresetNamed(name string) (HostPreset, bool) {
	i := slices.IndexFunc(HostPresets, func(p HostPreset) bool { return p.Name == name })
	if i < 0 {
		return HostPreset{}, false
	}
	return HostPresets[i], true
}

// ExpandHosts puts each preset's hosts where its name stands, each host once.
// A name this build doesn't know opens nothing, so a list from a newer
// console only loses hosts here.
func ExpandHosts(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		names := []string{h}
		if strings.HasPrefix(h, "@") {
			p, _ := HostPresetNamed(h)
			names = p.Hosts
		}
		for _, n := range names {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}
