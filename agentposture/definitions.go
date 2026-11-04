package agentposture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// Where the agents keep the skills and plugins they load. The Golem agent
// records each as an inventory definition (witness/skill_definitions.go) and
// golem-check scans the same files, so both find the same ones.

const (
	MaxDefinitionFiles     = 600
	MaxDefinitionReadBytes = 64 << 20
)

// SkillRoot is a directory of skills, each a subdirectory with a SKILL.md,
// filed Depth levels down at most.
type SkillRoot struct {
	Client string
	Dir    string
	Depth  int
}

// ClientSkillRoots are the skill directories of the agents other than Claude
// Code, whose skills are read with its projects and plugins.
func ClientSkillRoots(home, codexHome, openclawDir string) []SkillRoot {
	return []SkillRoot{
		{"cursor", filepath.Join(home, ".cursor", "skills"), 1},
		{"antigravity", filepath.Join(home, ".gemini", "config", "skills"), 1},
		{"antigravity", filepath.Join(home, ".gemini", "antigravity", "skills"), 1},
		{"codex", filepath.Join(codexHome, "skills"), 2},
		{"openclaw", filepath.Join(openclawDir, "skills"), 1},
		{"hermes", filepath.Join(home, ".hermes", "skills"), 2},
	}
}

// PluginRoot is a directory of plugins, each a subdirectory with Manifest.
type PluginRoot struct {
	Client   string
	Dir      string
	Manifest string
}

func ClientPluginRoots(home, openclawDir string) []PluginRoot {
	return []PluginRoot{
		{"gemini", filepath.Join(home, ".gemini", "extensions"), "gemini-extension.json"},
		{"openclaw", filepath.Join(openclawDir, "extensions"), "openclaw.plugin.json"},
		{"hermes", filepath.Join(home, ".hermes", "plugins"), "plugin.yaml"},
	}
}

// SkillDirs is each subdirectory of root that holds a SKILL.md.
func SkillDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if info, err := os.Stat(filepath.Join(dir, "SKILL.md")); err == nil && info.Mode().IsRegular() {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// NestedSkillDirs is SkillDirs that also looks depth levels down, for agents
// that file skills under a category (hermes/skills/<category>/<skill>).
func NestedSkillDirs(root string, depth int) []string {
	dirs := SkillDirs(root)
	if depth <= 1 {
		return dirs
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return dirs
	}
	have := map[string]bool{}
	for _, d := range dirs {
		have[d] = true
	}
	for _, e := range entries {
		sub := filepath.Join(root, e.Name())
		if have[sub] || !e.IsDir() {
			continue
		}
		dirs = append(dirs, NestedSkillDirs(sub, depth-1)...)
	}
	sort.Strings(dirs)
	return dirs
}

// FrontmatterName is the name: a markdown file's frontmatter gives, or "".
func FrontmatterName(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "---" {
		return ""
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "---" {
			return ""
		}
		if v, ok := strings.CutPrefix(line, "name:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// InstalledClaudePlugins reads installed_plugins.json for each plugin's
// install directory. A plugin installed at several scopes is read from the one
// updated last, so a host with two versions does not alternate between them.
func InstalledClaudePlugins(home string) []string {
	b, _, ok := readCapped(filepath.Join(home, ".claude", "plugins", "installed_plugins.json"))
	if !ok {
		return nil
	}
	var doc struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
			LastUpdated string `json:"lastUpdated"`
		} `json:"plugins"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var roots []string
	for _, installs := range doc.Plugins {
		best, when := "", ""
		for _, in := range installs {
			if in.InstallPath != "" && filepath.IsAbs(in.InstallPath) && in.LastUpdated >= when {
				best, when = in.InstallPath, in.LastUpdated
			}
		}
		if info, err := os.Stat(best); best != "" && err == nil && info.IsDir() {
			roots = append(roots, best)
		}
	}
	sort.Strings(roots)
	return roots
}

// ManagedAssetPaths are the skills and files Golem installed itself
// (~/.golem/managed-assets.json), which are not the user's to review.
func ManagedAssetPaths(home string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(home, ".golem", "managed-assets.json"))
	if err != nil {
		return out
	}
	var doc struct {
		Assets map[string]json.RawMessage `json:"assets"`
	}
	if json.Unmarshal(b, &doc) == nil {
		for p := range doc.Assets {
			out[p] = true
		}
	}
	return out
}

// DefinitionFiles walks dir without following links. A link is recorded as
// where it points, because a skill whose helper is a link to ~/.ssh says so
// only there. Past the file or byte budget a file is named but not read.
func DefinitionFiles(home, dir string, skip map[string]bool) []definition.Part {
	var parts []definition.Part
	read := 0
	_ = filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if path != dir && (e.Name() == ".git" || skip[path]) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if len(parts) >= MaxDefinitionFiles {
			return filepath.SkipAll
		}
		if e.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err == nil {
				parts = append(parts, definition.Text(definition.KindFile, rel, []byte("symlink → "+DisplayHome(home, target))))
			}
			return nil
		}
		if !e.Type().IsRegular() {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return nil
		}
		if read+int(info.Size()) > MaxDefinitionReadBytes {
			parts = append(parts, definition.Part{Kind: definition.KindFile, Name: rel, Size: int(info.Size()), Truncated: true})
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		p, err := definition.File(rel, f)
		f.Close()
		if err != nil {
			return nil
		}
		read += p.Size
		parts = append(parts, p)
		return nil
	})
	return parts
}

// DisplayHome spells paths with forward slashes on every OS, so the same skill
// reads the same in the console whichever machine reported it.
func DisplayHome(home, path string) string {
	sep := string(filepath.Separator)
	if home != "" && (path == home || strings.HasPrefix(path, home+sep)) {
		return "~" + filepath.ToSlash(strings.TrimPrefix(path, home))
	}
	return filepath.ToSlash(path)
}
