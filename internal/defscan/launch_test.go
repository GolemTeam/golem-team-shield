package defscan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestALaunchKeepsWhatItRuns(t *testing.T) {
	for _, tc := range []struct {
		name, transport, command string
		args                     []string
		url                      string
		want                     Launch
	}{
		{"npx pinned", "", "npx", []string{"-y", "@Acme/MCP-Server@1.2.0", "--port", "3000"}, "",
			Launch{Transport: "stdio", Runner: "npx", Ecosystem: "npm", Package: "@acme/mcp-server", Version: "1.2.0"}},
		{"npx unpinned with -p", "", "/usr/local/bin/npx", []string{"-p", "evil-pkg", "evil-bin"}, "",
			Launch{Transport: "stdio", Runner: "npx", Ecosystem: "npm", Package: "evil-pkg"}},
		{"uvx", "", "uvx", []string{"--python", "3.12", "mcp-server-fetch==0.6.2"}, "",
			Launch{Transport: "stdio", Runner: "uvx", Ecosystem: "PyPI", Package: "mcp-server-fetch", Version: "0.6.2"}},
		{"uvx --from", "", "uvx", []string{"--from", "Git_Hub.MCP", "github-mcp"}, "",
			Launch{Transport: "stdio", Runner: "uvx", Ecosystem: "PyPI", Package: "git-hub-mcp"}},
		{"docker", "", "docker", []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server:v0.4"}, "",
			Launch{Transport: "stdio", Runner: "docker", Image: "ghcr.io/github/github-mcp-server:v0.4"}},
		{"local node", "", "node", []string{"/Users/alice/work/server.js"}, "",
			Launch{Transport: "stdio", Runner: "node", Local: true}},
		{"local binary", "", "/Users/alice/bin/my-mcp", []string{"serve"}, "",
			Launch{Transport: "stdio", Local: true}},
		{"remote", "sse", "", nil, "https://user:pw@MCP.Example.com:8443/sse?token=abc",
			Launch{Transport: "sse", URL: "https://mcp.example.com:8443"}},
	} {
		got, ok := ParseLaunch(tc.transport, tc.command, tc.args, tc.url)
		if !ok || got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// Whatever a config carries in its arguments or URL, the projection holds none
// of it unless it is the package or image itself.
func TestALaunchNeverCarriesASecret(t *testing.T) {
	secrets := []string{
		"sk-proj-abcdefghijklmnopqrstuvwxyz012345", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		"postgres://admin:hunter2@db.internal:5432/prod", "hunter2", "abc", "/Users/alice",
	}
	cases := [][]string{
		{"npx", "-y", "@modelcontextprotocol/server-postgres", "postgres://admin:hunter2@db.internal:5432/prod"},
		{"npx", "-y", "some-mcp", "--api-key", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"},
		{"npx", "-y", "--token=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "some-mcp"},
		{"npx", "-y", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"},
		{"docker", "run", "-e", "API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345", "mcp/fetch"},
		{"uvx", "mcp-server-git", "--repository", "/Users/alice/secret-project"},
		{"node", "/Users/alice/server.js", "--password", "hunter2"},
	}
	for _, c := range cases {
		l, ok := ParseLaunch("", c[0], c[1:], "")
		b, _ := json.Marshal(l)
		for _, s := range secrets {
			if ok && strings.Contains(string(b), s) {
				t.Errorf("%v: the projection %s carries %q", c, b, s)
			}
		}
	}
	l, _ := ParseLaunch("http", "", nil, "https://x:hunter2@mcp.example.com/v1?key=abc")
	if b, _ := json.Marshal(l); strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "abc") {
		t.Errorf("remote projection %s", b)
	}
}
