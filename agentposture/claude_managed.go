package agentposture

import (
	"encoding/json"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

// Claude Code's managed settings come from three admin sources, highest first:
// server-managed settings (cached in ~/.claude/remote-settings.json), MDM or OS
// policy (the com.anthropic.claudecode managed preferences plist, or the HKLM
// registry value), and the managed-settings.json files. Claude Code applies only
// the highest one that sets a policy key, unless that one asks to merge, and
// reads the user-writable HKCU value only when no admin source is present
// (code.claude.com/docs/en/managed-settings). The posture checks judge the
// policy Claude Code would apply, not every document on the disk.

const claudeRegistryPath = `SOFTWARE\Policies\ClaudeCode`

type adminSource []settingsFile

func (a adminSource) hasPolicyKey() bool {
	for _, f := range a {
		for k, v := range f.m {
			if v != nil && k != "managedSourcesBehavior" && k != "wslInheritsWindowsSettings" {
				return true
			}
		}
	}
	return false
}

func (a adminSource) merges() bool {
	for _, f := range a {
		if lookupString(f.m, "managedSourcesBehavior") == "merge" {
			return true
		}
	}
	return false
}

func managedPrefsPaths() []string {
	const dir = "/Library/Managed Preferences"
	const domain = "com.anthropic.claudecode.plist"
	paths := []string{filepath.Join(dir, domain)}
	if u, err := user.Current(); err == nil && u.Username != "" && !strings.ContainsAny(u.Username, `/\`) {
		paths = append(paths, filepath.Join(dir, u.Username, domain))
	}
	return paths
}

func readPlistSettings(path string) map[string]any {
	b, _, ok := readCapped(path)
	if !ok {
		return nil
	}
	v, err := parsePlist(b)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func parseRegistrySettings(raw string) map[string]any {
	var m map[string]any
	if json.Unmarshal(StripJSONC([]byte(raw)), &m) != nil {
		return nil
	}
	return m
}

func (s *scan) claudeAdminSources() []adminSource {
	var server, mdm, files adminSource
	remote := filepath.Join(s.env.Home, ".claude", "remote-settings.json")
	if m := readSettings(remote); m != nil {
		server = append(server, settingsFile{"managed", remote, m})
	}
	for _, p := range s.env.ManagedPrefs {
		if m := readPlistSettings(p); m != nil {
			mdm = append(mdm, settingsFile{"managed", p, m})
		}
	}
	if s.env.Registry != nil {
		if m := s.env.Registry("HKLM"); m != nil {
			mdm = append(mdm, settingsFile{"managed", `HKLM\` + claudeRegistryPath, m})
		}
	}
	if s.env.ManagedDir != "" {
		if m := readSettings(filepath.Join(s.env.ManagedDir, "managed-settings.json")); m != nil {
			files = append(files, settingsFile{"managed", filepath.Join(s.env.ManagedDir, "managed-settings.json"), m})
		}
		drop, _ := filepath.Glob(filepath.Join(s.env.ManagedDir, "managed-settings.d", "*.json"))
		sort.Strings(drop)
		for _, p := range drop {
			if m := readSettings(p); m != nil {
				files = append(files, settingsFile{"managed", p, m})
			}
		}
	}
	return []adminSource{server, mdm, files}
}

// claudeManagedFiles is the managed policy Claude Code applies: the selected
// admin source, every admin source when it merges, or the HKCU value when no
// admin source sets anything.
func (s *scan) claudeManagedFiles() []settingsFile {
	sources := s.claudeAdminSources()
	for i, src := range sources {
		if !src.hasPolicyKey() {
			continue
		}
		if !src.merges() {
			return src
		}
		var all []settingsFile
		for _, rest := range sources[i:] {
			all = append(all, rest...)
		}
		return all
	}
	if s.env.Registry != nil {
		if m := s.env.Registry("HKCU"); m != nil {
			return []settingsFile{{"user", `HKCU\` + claudeRegistryPath, m}}
		}
	}
	return nil
}

// ManagedSettings is the managed policy Claude Code applies on this machine,
// one document per source, highest precedence first.
func (env Env) ManagedSettings() []map[string]any {
	files := (&scan{env: env}).claudeManagedFiles()
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		out = append(out, f.m)
	}
	return out
}
