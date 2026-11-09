package shield

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestVSCodeSettingsAreWhereEachOSKeepsThem(t *testing.T) {
	home := t.TempDir()
	for goos, dir := range map[string]string{
		"darwin":  "Library/Application Support/Code/User",
		"linux":   ".config/Code - Insiders/User",
		"windows": "AppData/Roaming/Code/User",
	} {
		if got := VSCodeSettings(home, goos); len(got) != 0 {
			t.Fatalf("%s: settings with nothing installed: %v", goos, got)
		}
		plantBody(t, filepath.Join(home, filepath.FromSlash(dir), "x"), "")
		if got := VSCodeSettings(home, goos); len(got) != 1 || got[0] != filepath.Join(home, filepath.FromSlash(dir), "settings.json") {
			t.Errorf("%s: %v", goos, got)
		}
	}
}

func TestVSCodeProfilePathReadsJSONWithComments(t *testing.T) {
	src := []byte(`{
  // mine
  "editor.fontSize": 13,
  "chat.tools.terminal.terminalProfile.osx": {"path": "/h/.golem/bin/hook/zsh",},
}`)
	if got, ok := VSCodeProfilePath(src, "darwin"); !ok || got != "/h/.golem/bin/hook/zsh" {
		t.Fatalf("%q %v", got, ok)
	}
	if _, ok := VSCodeProfilePath(src, "linux"); ok {
		t.Fatal("read the macOS profile for Linux")
	}
}

func TestVSCodeIsJailedPerTerminalThroughItsProfile(t *testing.T) {
	ready := func(string) bool { return true }
	for _, tc := range []struct {
		name, settings string
		on             bool
		ready          func(string) bool
		want           Coverage
		detail         string
	}{
		{"switch off", `{}`, false, ready, NotJailed, "would jail them anyway"},
		{"the profile names the shim", `{"chat.tools.terminal.terminalProfile.linux": {"path": "HOME/.golem/bin/hook/bash"}}`, true, ready, Partial, "one jail per terminal"},
		{"the shim isn't installed", `{"chat.tools.terminal.terminalProfile.linux": {"path": "HOME/.golem/bin/hook/bash"}}`, true, func(string) bool { return false }, NotJailed, "not installed"},
		{"the person's own profile", `{"chat.tools.terminal.terminalProfile.linux": {"path": "/bin/fish"}}`, true, ready, NotJailed, "left alone"},
		{"switch on, nothing set", `{}`, true, ready, NotJailed, "no terminal profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			plantBody(t, filepath.Join(home, ".config", "Code", "User", "settings.json"), strings.ReplaceAll(tc.settings, "HOME", filepath.ToSlash(home)))
			if err := SetPastApproval(home, tc.on); err != nil {
				t.Fatal(err)
			}
			var c *AgentCoverage
			for _, l := range CoverageOf(CoverageEnv{Home: home, GOOS: "linux", LoginShell: "/bin/bash", ShimReady: tc.ready, CodexHomes: []string{}}) {
				if l.Client == "vscode" {
					c = &l
				}
			}
			if c == nil || c.Coverage != tc.want || !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("got %+v", c)
			}
			if c.PastApproval != strings.Contains(c.Detail, "would jail them anyway") {
				t.Fatalf("only the switch would jail it, but PastApproval is %v: %+v", c.PastApproval, c)
			}
		})
	}
}
