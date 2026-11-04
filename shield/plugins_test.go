package shield

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginCoverage(t *testing.T) {
	ready := func(string) bool { return true }
	for _, tc := range []struct {
		name, client, dir, plugin, src, goos string
		want                                 Coverage
		detail                               string
	}{
		{"Hermes with the rewrite", "hermes", ".hermes", ".hermes/plugins/golem/__init__.py", "def on_shield_rewrite(tool_name=None):", "linux", Jailed, "through the Golem plugin"},
		{"Hermes with an old plugin", "hermes", ".hermes", ".hermes/plugins/golem/__init__.py", "def on_pre_tool_call():", "darwin", NotJailed, "golem update hermes-plugin"},
		{"Hermes with no plugin", "hermes", ".hermes", "", "", "darwin", NotJailed, "isn't installed"},
		{"Hermes on Windows with a plugin from before it", "hermes", ".hermes", ".hermes/plugins/golem/__init__.py", "def on_shield_rewrite(tool_name=None):", "windows", NotJailed, "golem update hermes-plugin"},
		{"OpenClaw with the rewrite", "openclaw", ".openclaw/agents", ".openclaw/extensions/golem/index.js", "export function shieldRewrite(toolName) {}", "darwin", Jailed, "through the Golem plugin"},
		{"OpenClaw on Windows", "openclaw", ".openclaw/agents", ".openclaw/extensions/golem/index.js", "export function shieldRewrite(toolName) {}", "windows", NotJailed, "golem setup-client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, tc.dir), 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.plugin != "" {
				p := filepath.Join(home, tc.plugin)
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(tc.src), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var c *AgentCoverage
			for _, l := range CoverageOf(CoverageEnv{Home: home, GOOS: tc.goos, ShimReady: ready, CodexHomes: []string{}}) {
				if l.Client == tc.client {
					c = &l
				}
			}
			if c == nil || c.Coverage != tc.want || !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("got %+v", c)
			}
		})
	}
}

// The coverage check looks for these in the installed plugins; a rename there
// would turn a jailed agent into one reported as out of date.
func TestThePluginsCarryWhatCoverageLooksFor(t *testing.T) {
	for file, mark := range map[string]string{
		"../../hermes-plugin/golem/__init__.py":                pluginAgents[0].rewrites,
		"../../witness/assets/openclaw/golem/index.js":         pluginAgents[1].rewrites,
		"../../witness/assets/openclaw/golem/index.js#windows": pluginAgents[1].windowsRewrites,
		"../../hermes-plugin/golem/__init__.py#windows":        pluginAgents[0].windowsRewrites,
		"../../witness/assets/hooks/cursor-hook.sh":            cursorScriptRewrites,
	} {
		src, err := os.ReadFile(strings.TrimSuffix(file, "#windows"))
		if os.IsNotExist(err) {
			t.Skipf("%s is not in this tree (the public repo)", file)
		}
		if err != nil || !strings.Contains(string(src), mark) {
			t.Errorf("%s doesn't carry %q", file, mark)
		}
	}
}

func TestOpenClawOnWindowsIsJailedThroughThePowerShellShim(t *testing.T) {
	home := t.TempDir()
	plugin := filepath.Join(home, ".openclaw", "extensions", "golem", "index.js")
	for p, body := range map[string]string{
		filepath.Join(home, ".openclaw", "agents", "x"): "",
		plugin: "export function shieldRewrite(x) {}\nexport function shieldWrapPowerShell(s, c) {}",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	line := func(ready func(string) bool) *AgentCoverage {
		for _, l := range CoverageOf(CoverageEnv{Home: home, GOOS: "windows", ShimReady: ready, CodexHomes: []string{}}) {
			if l.Client == "openclaw" {
				return &l
			}
		}
		return nil
	}
	var asked string
	if c := line(func(p string) bool { asked = p; return true }); c == nil || c.Coverage != Jailed || filepath.Base(asked) != "pwsh.exe" {
		t.Fatalf("got %+v, asked about %q", c, asked)
	}
	if c := line(func(string) bool { return false }); c == nil || c.Coverage != NotJailed {
		t.Fatalf("with no PowerShell shim: %+v", c)
	}
}

func TestHermesOnWindowsIsJailedThroughTheGitBashShim(t *testing.T) {
	home := t.TempDir()
	plugin := filepath.Join(home, ".hermes", "plugins", "golem", "__init__.py")
	if err := os.MkdirAll(filepath.Dir(plugin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plugin, []byte("def on_shield_rewrite(x):\ndef shield_msys_path(w):\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var asked string
	for _, l := range CoverageOf(CoverageEnv{Home: home, GOOS: "windows", ShimReady: func(p string) bool { asked = p; return true }, CodexHomes: []string{}}) {
		if l.Client != "hermes" {
			continue
		}
		_, plain := MSYSPath(filepath.Join(ShimDir(home), "bash.exe"))
		switch {
		case !plain && l.Coverage != NotJailed:
			t.Fatalf("a home Git Bash can't name: %+v", l)
		case plain && (l.Coverage != Jailed || filepath.Base(asked) != "bash.exe"):
			t.Fatalf("got %+v, asked about %q", l, asked)
		}
		return
	}
	t.Fatal("no line for Hermes")
}
