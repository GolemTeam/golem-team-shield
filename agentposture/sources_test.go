package agentposture

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestWherePluginsComeFrom(t *testing.T) {
	env := postureTestEnv(t)
	project := filepath.Join(t.TempDir(), "repo")
	projects, _ := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{}}})
	writePostureFile(t, filepath.Join(env.Home, ".claude.json"), string(projects))
	writePostureFile(t, filepath.Join(env.Home, ".claude", "plugins", "known_marketplaces.json"), `{
		"claude-plugins-official":{"source":{"source":"github","repo":"anthropics/claude-plugins-official"}},
		"acme-tools":{"source":{"source":"github","repo":"acme/tools"}},
		"old-mirror":{"source":{"source":"url","url":"http://mirror.example/marketplace.json"}}}`)
	writePostureFile(t, filepath.Join(project, ".claude", "settings.json"), `{
		"extraKnownMarketplaces":{"repo-market":{"source":{"source":"git","url":"https://git.example/m.git"}}},
		"enabledPlugins":{"helper@repo-market":true,"off@repo-market":false}}`)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "extensions", "web", "gemini-extension.json"), `{"name":"web"}`)
	writePostureFile(t, filepath.Join(env.Home, ".gemini", "extensions", "web", ".gemini-extension-install.json"),
		`{"source":"https://github.com/acme/gemini-web","type":"git"}`)

	res := ScanAll(env)
	got := map[string]Item{}
	for _, it := range res.Items {
		if it.Area == AreaSources {
			got[it.Check+"/"+it.Subject] = it
		}
	}
	for k, want := range map[string]string{
		"marketplace_third_party/acme-tools":     "plugins can come from the acme-tools marketplace (github.com/acme/tools), which its owner can change",
		"marketplace_third_party/old-mirror":     "plugins can come from the old-mirror marketplace (http://mirror.example), which its owner can change",
		"marketplace_insecure/old-mirror":        "the old-mirror plugin marketplace is fetched over plain http",
		"marketplace_from_project/repo-market":   "a repository adds the repo-market plugin marketplace (https://git.example), so cloning it offers its plugins",
		"plugin_from_project/helper@repo-market": "a repository turns on the helper@repo-market plugin",
		"extension_installed/web":                "the web extension is installed, from https://github.com",
	} {
		if got[k].Detail != want {
			t.Errorf("%s: %q, want %q", k, got[k].Detail, want)
		}
	}
	for _, k := range []string{"marketplace_third_party/claude-plugins-official", "plugin_from_project/off@repo-market"} {
		if _, ok := got[k]; ok {
			t.Errorf("reported %s", k)
		}
	}
	if !contains(res.Read, AreaSources) {
		t.Errorf("read %v", res.Read)
	}
}

func TestAMarketplaceIsReportedOncePerRepositoryAndNeverForTheUsersOwnSettings(t *testing.T) {
	env := postureTestEnv(t)
	repo := filepath.Join(t.TempDir(), "seed")
	wt1 := filepath.Join(repo, ".claude", "worktrees", "a")
	wt2 := filepath.Join(repo, ".claude", "worktrees", "b")
	projects, _ := json.Marshal(map[string]any{"projects": map[string]any{env.Home: map[string]any{}, repo: map[string]any{}, wt1: map[string]any{}, wt2: map[string]any{}}})
	writePostureFile(t, filepath.Join(env.Home, ".claude.json"), string(projects))
	official := `{"extraKnownMarketplaces":{"claude-plugins-official":{"source":{"source":"github","repo":"anthropics/claude-plugins-official"}},
		"team":{"source":{"source":"github","repo":"acme/team-plugins"}}}}`
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"), official)
	for _, dir := range []string{repo, wt1, wt2} {
		writePostureFile(t, filepath.Join(dir, ".claude", "settings.json"), official)
	}
	n := map[string]int{}
	for _, it := range ScanAll(env).Items {
		if it.Check == "marketplace_from_project" {
			n[it.Subject]++
			if strings.HasPrefix(it.Location, "~") {
				t.Errorf("the user's own settings read as a repository's: %+v", it)
			}
		}
	}
	if n["team"] != 1 || n["claude-plugins-official"] != 0 {
		t.Errorf("got %v", n)
	}
}
