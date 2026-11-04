package secretpattern

import (
	"strings"
	"testing"
)

func TestFindNamesTheTypeOnly(t *testing.T) {
	for _, c := range []struct{ value, want string }{
		{"ghp_" + strings.Repeat("a1", 18), GitHubToken},
		{"sk-ant-" + strings.Repeat("x", 30), AnthropicKey},
		{"AKIA" + strings.Repeat("A", 16), AWSAccessKey},
		{"postgres://app:s3cretpassw0rd@db:5432/x", DBPassword},
		{"Bearer " + strings.Repeat("abc123", 4), BearerToken},
	} {
		if got, ok := Find(c.value); !ok || got != c.want {
			t.Errorf("Find(%q) = %q, %v; want %q", c.value, got, ok, c.want)
		}
	}
}

func TestPlaceholdersAreNotSecrets(t *testing.T) {
	for _, v := range []string{
		"Bearer your_token_goes_here_ok",
		"postgres://app:changeme@db/x",
		"api_key=xxxxxxxxxxxxxxxxxxxx",
		"token: <paste-your-token-here>",
		"${GITHUB_TOKEN}",
		"",
	} {
		if got, ok := Find(v); ok {
			t.Errorf("Find(%q) = %q", v, got)
		}
	}
}
