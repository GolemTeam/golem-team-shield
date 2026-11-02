package shield

import "strings"

var secretNameParts = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "PRIVATE_KEY",
	"CREDENTIAL", "ACCESS_KEY", "SESSION_KEY", "COOKIE",
}

var secretPrefixes = []string{
	"GH_", "GITHUB_", "ANTHROPIC_", "OPENAI_",
	"CLAUDE_CODE_OAUTH", "CLAUDE_CODE_MESSAGING_", "NPM_CONFIG__AUTH", "NPM_CONFIG_//",
}

// cloudVars belong to the Cloud grant: with it on, the CLIs keep their
// configuration and keys as well as their credential files.
var cloudVars = []string{"AWS_", "AZURE_", "CLOUDSDK_", "GOOGLE_APPLICATION_CREDENTIALS", "KUBECONFIG"}

// FilterEnv drops secret-shaped variables by name. It is a denylist because an
// allowlist breaks toolchains (GOPATH, NVM_DIR, JAVA_HOME, PYENV_ROOT, ...).
// The workspace adjusts it: p.EnvDeny strips a name whatever it looks like,
// and p.EnvAllow keeps a secret-shaped one, but not in a tainted session.
// It returns the names it dropped, never their values, for the run record.
// A non-empty tmp becomes TMPDIR.
func FilterEnv(env []string, p Policy, tmp string) (kept, dropped []string) {
	g := p.Effective()
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if name == "TMPDIR" && tmp != "" {
			continue
		}
		strip := matchesAny(name, p.EnvDeny) ||
			(secretVar(strings.ToUpper(name), g) && (p.Tainted() || !matchesAny(name, p.EnvAllow)))
		if strip {
			dropped = append(dropped, name)
			continue
		}
		kept = append(kept, kv)
	}
	if tmp != "" {
		kept = append(kept, "TMPDIR="+tmp)
	}
	return kept, dropped
}

func secretVar(name string, g Grants) bool {
	switch {
	case name == "SSH_AUTH_SOCK":
		return !g.Agent
	case strings.HasPrefix(name, "DOCKER_"):
		return !g.Docker
	}
	for _, p := range cloudVars {
		if strings.HasPrefix(name, p) {
			return !g.Cloud
		}
	}
	for _, p := range secretPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, part := range secretNameParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

// matchesAny reports whether name is one of patterns, each a name or a prefix
// ending in *. Names are case-sensitive, as the environment is.
func matchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if prefix != "" && strings.HasPrefix(name, prefix) {
				return true
			}
			continue
		}
		if name == p {
			return true
		}
	}
	return false
}
