package agentposture

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/secretpattern"
)

// The secrets area: a literal credential in an agent's settings, and the
// agents' own credential stores left readable by other users. An item names
// the file and the key, never the value or any part of it.

var secretKeyRE = regexp.MustCompile(`(?i)token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential`)

// literalSecret is a value that is a credential rather than a reference to
// one: a known token shape, or a long opaque value under a credential's name.
func literalSecret(key, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || placeholderRe.MatchString(v) || secretpattern.Placeholder(v) {
		return false
	}
	if _, ok := secretpattern.Find(v); ok {
		return true
	}
	return secretKeyRE.MatchString(key) && len(v) >= 16 && !strings.ContainsAny(v, " /")
}

func (s *scan) secretItems() []Item {
	var out []Item
	add := func(client, check, sev, scope, path, setting, detail string) {
		out = append(out, Item{Client: client, Check: check, Severity: sev, Area: AreaSecrets, Scope: scope,
			Location: s.display(path), Setting: setting, Detail: detail})
	}
	plaintext := func(client, scope, path string, env map[string]string, block string) {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		info, err := os.Stat(path)
		loose := err == nil && unixModes && info.Mode().Perm()&0o044 != 0
		for _, k := range keys {
			if !literalSecret(k, env[k]) {
				continue
			}
			sev, detail := Info, "has a credential in plain text in "+block+" "+k
			switch {
			case scope == "project":
				sev, detail = Suspicious, detail+", in a repository file, so probably committed"
			case loose:
				sev, detail = Suspicious, detail+", in a file other users on this machine can read"
			}
			add(client, "config_plaintext_secret", sev, scope, path, block+"."+k, detail)
		}
	}
	if s.claudeInUse() {
		for _, f := range s.claudeSettingsFiles() {
			if env, ok := lookup(f.m, "env").(map[string]any); ok {
				plaintext("claude-code", f.scope, f.path, stringValues(env), "env")
			}
		}
	}
	for _, p := range []struct{ client, path string }{
		{"gemini-cli", filepath.Join(s.env.Home, ".gemini", ".env")},
	} {
		if b, _, ok := s.readCapped(p.path); ok {
			plaintext(p.client, "user", p.path, dotenv(b), ".env")
		}
	}
	if unixModes {
		stores := []struct{ client, path string }{
			{"claude-code", filepath.Join(s.env.Home, ".claude", ".credentials.json")},
			{"gemini-cli", filepath.Join(s.env.Home, ".gemini", "oauth_creds.json")},
		}
		for _, dir := range s.env.CodexHomes {
			stores = append(stores, struct{ client, path string }{"codex", filepath.Join(dir, "auth.json")})
		}
		for _, c := range stores {
			if info, err := os.Stat(c.path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o044 != 0 {
				add(c.client, "credential_file_readable", Suspicious, "user", c.path, "",
					"the agent's sign-in credentials are in a file other users on this machine can read")
			}
		}
	}
	return out
}

func dotenv(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}
