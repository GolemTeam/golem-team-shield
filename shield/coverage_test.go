package shield

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func coverageHome(t *testing.T, settings string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if settings != "" {
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func claudeLine(t *testing.T, env CoverageEnv) AgentCoverage {
	t.Helper()
	for _, c := range CoverageOf(env) {
		if c.Client == "claude-code" {
			return c
		}
	}
	t.Fatal("no line for Claude Code")
	return AgentCoverage{}
}

func TestClaudeCodeCoverage(t *testing.T) {
	ready := func(string) bool { return true }
	missing := func(string) bool { return false }
	for _, tc := range []struct {
		name     string
		goos     string
		settings string
		ready    func(string) bool
		want     Coverage
		detail   string
	}{
		{"the shim", "darwin", `{"env": {"CLAUDE_CODE_SHELL": "HOME/.golem/bin/golem-zsh"}}`, ready, Jailed, "run in the Golem jail"},
		{"nothing set", "darwin", `{"model": "x"}`, ready, NotJailed, "is not set"},
		{"no settings file", "linux", ``, ready, NotJailed, "is not set"},
		{"the person's own shell", "darwin", `{"env": {"CLAUDE_CODE_SHELL": "/bin/zsh"}}`, ready, NotJailed, "is /bin/zsh"},
		{"a shim that isn't there", "linux", `{"env": {"CLAUDE_CODE_SHELL": "HOME/.golem/bin/golem-bash"}}`, missing, NotJailed, "not installed"},
		{"Windows with PowerShell off", "windows", `{"env": {"CLAUDE_CODE_GIT_BASH_PATH": "HOME/.golem/bin/bash.exe", "CLAUDE_CODE_USE_POWERSHELL_TOOL": "0"}}`, ready, Jailed, "CLAUDE_CODE_GIT_BASH_PATH"},
		{"Windows with PowerShell on", "windows", `{"env": {"CLAUDE_CODE_GIT_BASH_PATH": "HOME/.golem/bin/bash.exe"}}`, ready, Partial, "PowerShell tool is on"},
		{"Windows reads its own variable", "windows", `{"env": {"CLAUDE_CODE_SHELL": "HOME/.golem/bin/golem-zsh"}}`, ready, NotJailed, "is not set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tc.goos != "windows" {
				t.Skip("a Unix home's paths need a Unix host")
			}
			home := coverageHome(t, "")
			if tc.settings != "" {
				s := strings.ReplaceAll(tc.settings, "HOME", filepath.ToSlash(home))
				if tc.goos == "windows" {
					s = strings.ReplaceAll(s, "/", `\\`)
				}
				if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(s), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c := claudeLine(t, CoverageEnv{Home: home, GOOS: tc.goos, ShimReady: tc.ready})
			if c.Coverage != tc.want || !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("got %s %q, want %s with %q", c.Coverage, c.Detail, tc.want, tc.detail)
			}
		})
	}
}

func TestNoLineForAnAgentThatIsNotInstalled(t *testing.T) {
	home := t.TempDir()
	if got := CoverageOf(CoverageEnv{Home: home, GOOS: "darwin", CodexHomes: []string{filepath.Join(home, ".codex")}}); len(got) != 0 {
		t.Fatalf("lines for nothing installed: %+v", got)
	}
}

func TestCoverageReadsTheShimItself(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Unix shim layout; Windows's is bash.exe")
	}
	home := coverageHome(t, "")
	shim := filepath.Join(ShimDir(home), "golem-zsh")
	settings := `{"env": {"CLAUDE_CODE_SHELL": "` + shim + `"}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := claudeLine(t, CoverageEnv{Home: home, GOOS: "darwin"}); c.Coverage != NotJailed {
		t.Fatalf("no shim on disk, yet %s", c.Coverage)
	}
	if err := os.MkdirAll(filepath.Dir(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if c := claudeLine(t, CoverageEnv{Home: home, GOOS: "darwin"}); c.Coverage != Jailed || c.Location != filepath.Join("~", ".claude", "settings.json") {
		t.Fatalf("got %+v", c)
	}
}

func TestFromInsideTheJailTheShimStillCounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Unix shim layout; Windows's is bash.exe")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads through a denied directory")
	}
	home := coverageHome(t, "")
	shim := filepath.Join(ShimDir(home), "golem-zsh")
	settings := `{"env": {"CLAUDE_CODE_SHELL": "` + shim + `"}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ShimDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	golem := filepath.Join(home, ".golem")
	if err := os.Chmod(golem, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(golem, 0o700) })
	if _, err := os.Stat(shim); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("this system doesn't deny the stat: %v", err)
	}
	c := claudeLine(t, CoverageEnv{Home: home, GOOS: "darwin"})
	if c.Coverage != Jailed || !strings.Contains(c.Detail, "inside the jail") {
		t.Fatalf("got %s %q", c.Coverage, c.Detail)
	}
}
