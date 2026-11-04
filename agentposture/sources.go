package agentposture

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The sources area: where the agents' plugins come from. A marketplace is code
// a stranger can change and the agent will run, so the report names each one
// that is not the agent vendor's, and says when a cloned repository adds one.

type marketplaceSource struct {
	Source string `json:"source"`
	Repo   string `json:"repo"`
	URL    string `json:"url"`
	Path   string `json:"path"`
	Ref    string `json:"ref"`
}

func vendorMarketplace(src marketplaceSource) bool {
	return src.Source == "github" && strings.HasPrefix(strings.ToLower(src.Repo), "anthropics/")
}

func (src marketplaceSource) where() string {
	switch {
	case src.Repo != "":
		return "github.com/" + src.Repo
	case src.URL != "":
		if u, err := url.Parse(src.URL); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	case src.Path != "":
		return "a local directory"
	}
	return "an unnamed source"
}

func (src marketplaceSource) insecure() bool {
	if src.URL == "" {
		return false
	}
	u, err := url.Parse(src.URL)
	return err == nil && strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname())
}

type sourceAdder func(client, check, sev, scope, path, setting, subject, detail string)

func (s *scan) sourceItems() []Item {
	var out []Item
	add := func(client, check, sev, scope, path, setting, subject, detail string) {
		out = append(out, Item{Client: client, Check: check, Severity: sev, Area: AreaSources, Scope: scope,
			Location: s.display(path), Setting: setting, Subject: subject, Detail: detail})
	}
	home := s.env.Home
	known := filepath.Join(home, ".claude", "plugins", "known_marketplaces.json")
	if b, _, ok := s.readCapped(known); ok {
		s.read[AreaSources] = true
		var doc map[string]struct {
			Source marketplaceSource `json:"source"`
		}
		if json.Unmarshal(b, &doc) == nil {
			names := make([]string, 0, len(doc))
			for name := range doc {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				marketplace(add, "user", known, name, doc[name].Source)
			}
		}
	}
	if s.claudeInUse() {
		for _, f := range s.claudeSettingsFiles() {
			extra, _ := lookup(f.m, "extraKnownMarketplaces").(map[string]any)
			for _, name := range sortedAnyKeys(extra) {
				s.read[AreaSources] = true
				var src marketplaceSource
				if raw, err := json.Marshal(lookup(f.m, "extraKnownMarketplaces", name, "source")); err == nil {
					_ = json.Unmarshal(raw, &src)
				}
				if (f.scope == "project" || f.scope == "local") && !vendorMarketplace(src) {
					add("claude-code", "marketplace_from_project", Suspicious, f.scope, f.path, "extraKnownMarketplaces."+name, name,
						"a repository adds the "+name+" plugin marketplace ("+src.where()+"), so cloning it offers its plugins")
				}
				if src.insecure() {
					add("claude-code", "marketplace_insecure", Suspicious, f.scope, f.path, "extraKnownMarketplaces."+name, name,
						"the "+name+" plugin marketplace is fetched over plain http")
				}
			}
			if f.scope != "project" && f.scope != "local" {
				continue
			}
			enabled, _ := lookup(f.m, "enabledPlugins").(map[string]any)
			for _, p := range sortedAnyKeys(enabled) {
				if v, _ := enabled[p].(bool); v {
					add("claude-code", "plugin_from_project", Info, f.scope, f.path, "enabledPlugins."+p, p,
						"a repository turns on the "+p+" plugin")
				}
			}
		}
	}
	extensions := filepath.Join(home, ".gemini", "extensions")
	if entries, err := os.ReadDir(extensions); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "golem" {
				continue
			}
			dir := filepath.Join(extensions, e.Name())
			if _, err := os.Stat(filepath.Join(dir, "gemini-extension.json")); err != nil {
				continue
			}
			s.read[AreaSources] = true
			var meta struct {
				Source string `json:"source"`
				Type   string `json:"type"`
			}
			from := "a local copy"
			if b, _, ok := s.readCapped(filepath.Join(dir, ".gemini-extension-install.json")); ok && json.Unmarshal(b, &meta) == nil && meta.Source != "" {
				from = marketplaceSource{URL: meta.Source}.where()
				if meta.Type == "local" || !strings.Contains(meta.Source, "://") {
					from = "a local directory"
				}
			}
			add("gemini-cli", "extension_installed", Info, "user", dir, "", e.Name(),
				"the "+e.Name()+" extension is installed, from "+from)
		}
	}
	return out
}

func marketplace(add sourceAdder, scope, path, name string, src marketplaceSource) {
	if vendorMarketplace(src) {
		return
	}
	add("claude-code", "marketplace_third_party", Info, scope, path, "", name,
		"plugins can come from the "+name+" marketplace ("+src.where()+"), which its owner can change")
	if src.insecure() {
		add("claude-code", "marketplace_insecure", Suspicious, scope, path, "", name,
			"the "+name+" plugin marketplace is fetched over plain http")
	}
}
