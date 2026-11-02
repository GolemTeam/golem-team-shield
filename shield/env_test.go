package shield

import (
	"slices"
	"testing"
)

func TestFilterEnvDropsSecretsAndKeepsToolchains(t *testing.T) {
	env := []string{
		"PATH=/usr/bin", "HOME=/Users/dev", "GOPATH=/Users/dev/go", "NVM_DIR=/Users/dev/.nvm",
		"CLAUDE_CODE_SESSION_ID=abc", "TMPDIR=/var/folders/x",
		"GITHUB_TOKEN=t", "GH_TOKEN=t", "ANTHROPIC_API_KEY=k", "OPENAI_API_KEY=k",
		"AWS_SECRET_ACCESS_KEY=s", "AWS_PROFILE=p", "KUBECONFIG=/k", "CLOUDSDK_CONFIG=/c",
		"CLAUDE_CODE_OAUTH_TOKEN=o", "CLAUDE_CODE_MESSAGING_TOKEN=m", "CLAUDE_CODE_MESSAGING_SOCKET=/s",
		"GOLEM_API_KEY=g", "db_password=x", "MY_SERVICE_SECRET=x", "NPM_CONFIG__AUTH=x",
		"SSH_AUTH_SOCK=/s", "DOCKER_HOST=unix:///d",
	}
	kept, dropped := FilterEnv(env, Policy{Enforce: true, State: Clean}, "/tmp/turn")
	for _, want := range []string{"PATH=/usr/bin", "HOME=/Users/dev", "GOPATH=/Users/dev/go", "NVM_DIR=/Users/dev/.nvm", "CLAUDE_CODE_SESSION_ID=abc", "TMPDIR=/tmp/turn"} {
		if !slices.Contains(kept, want) {
			t.Errorf("dropped %s", want)
		}
	}
	if len(kept) != 6 {
		t.Errorf("kept %v", kept)
	}
	if !slices.Contains(dropped, "db_password") || slices.Contains(dropped, "TMPDIR") {
		t.Errorf("dropped %v", dropped)
	}
}

func TestFilterEnvFollowsGrants(t *testing.T) {
	env := []string{"SSH_AUTH_SOCK=/s", "DOCKER_HOST=unix:///d", "AWS_PROFILE=p", "KUBECONFIG=/k", "GITHUB_TOKEN=t"}
	all := Grants{Agent: true, Docker: true, Cloud: true}
	kept, _ := FilterEnv(env, Policy{Enforce: true, State: Clean, Grants: all}, "")
	if !slices.Equal(kept, env[:4]) {
		t.Errorf("granted clean kept %v", kept)
	}
	kept, _ = FilterEnv(env, Policy{Enforce: true, State: Tainted, Grants: all}, "")
	if len(kept) != 0 {
		t.Errorf("tainted kept %v", kept)
	}
}

func TestTheWorkspaceAdjustsWhatIsStripped(t *testing.T) {
	env := []string{"NPM_TOKEN=n", "MYCO_API_KEY=m", "MYCO_SIGNING=s", "GITHUB_TOKEN=g", "PATH=/usr/bin"}
	p := Policy{Enforce: true, State: Clean, EnvAllow: []string{"NPM_TOKEN", "MYCO_*"}, EnvDeny: []string{"MYCO_SIGNING"}}
	kept, _ := FilterEnv(env, p, "")
	if !slices.Equal(kept, []string{"NPM_TOKEN=n", "MYCO_API_KEY=m", "PATH=/usr/bin"}) {
		t.Errorf("clean: kept %v", kept)
	}
	p.State = Tainted
	kept, _ = FilterEnv(env, p, "")
	if !slices.Equal(kept, []string{"PATH=/usr/bin"}) {
		t.Errorf("a locked-down session kept %v", kept)
	}
}

func TestTheStripListWinsAndReachesOrdinaryNames(t *testing.T) {
	p := Policy{Enforce: true, State: Clean, EnvAllow: []string{"FOO"}, EnvDeny: []string{"FOO", "INTERNAL_*"}}
	kept, dropped := FilterEnv([]string{"FOO=1", "INTERNAL_URL=x", "HOME=/h"}, p, "")
	if !slices.Equal(kept, []string{"HOME=/h"}) || !slices.Equal(dropped, []string{"FOO", "INTERNAL_URL"}) {
		t.Errorf("kept %v dropped %v", kept, dropped)
	}
}

func TestAPrefixPatternNeedsAPrefix(t *testing.T) {
	if matchesAny("ANYTHING", []string{"*"}) || matchesAny("npm_token", []string{"NPM_TOKEN"}) {
		t.Error("a bare * or a different case matched")
	}
}
