package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

type fakeSetup struct {
	*setup
	out, errs bytes.Buffer
	ran       []string
}

// hostLayout is the shim layout this machine can really build: a Unix one's
// symlinks and execute bits don't exist on Windows.
func hostLayout() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return "darwin"
}

func newFakeSetup(t *testing.T, goos string) *fakeSetup {
	t.Helper()
	if goos != "windows" && runtime.GOOS == "windows" {
		t.Skip("a Unix shim layout needs a Unix host")
	}
	f := &fakeSetup{}
	f.setup = &setup{
		home: t.TempDir(), goos: goos, exe: os.Args[0], loginShell: "/bin/zsh",
		stdout: &f.out, stderr: &f.errs,
		canJail:   func() bool { return true },
		agentRuns: func() bool { return false },
		selfTest: func(shim, command string) (int, error) {
			f.ran = append(f.ran, command)
			if strings.HasPrefix(command, "cat ") {
				return 1, nil
			}
			return 0, nil
		},
	}
	return f
}

func (f *fakeSetup) settingsEnv(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(f.settingsPath())
	if err != nil {
		return nil
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Env
}

func TestInstallSetsUpTheShimTheSettingsAndClaudeCode(t *testing.T) {
	f := newFakeSetup(t, "darwin")
	if code := f.install(false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	for _, name := range []string{"golem-exec", "golem-zsh", "golem-bash"} {
		if fi, err := os.Stat(filepath.Join(f.binDir(), name)); err != nil || fi.Mode()&0o111 == 0 {
			t.Errorf("%s not installed: %v", name, err)
		}
	}
	if dest, _ := os.Readlink(filepath.Join(f.binDir(), "golem-zsh")); dest != "golem-exec" {
		t.Errorf("golem-zsh -> %q", dest)
	}
	if got := f.settingsEnv(t)["CLAUDE_CODE_SHELL"]; got != filepath.Join(f.binDir(), "golem-zsh") {
		t.Errorf("CLAUDE_CODE_SHELL = %q", got)
	}
	cfg, found, err := shield.LoadConfig(shield.ConfigPath(f.home))
	if !found || err != nil || !cfg.Policy().Grants.Cloud {
		t.Errorf("default settings: found=%v err=%v %+v", found, err, cfg)
	}
	if len(f.ran) != 2 || !strings.Contains(f.out.String(), "Self-test passed") {
		t.Errorf("self-test ran %v:\n%s", f.ran, f.out.String())
	}

	f.out.Reset()
	if code := f.install(false); code != 0 || strings.Contains(f.out.String(), "Claude Code: ") {
		t.Errorf("a second install changed Claude Code again:\n%s", f.out.String())
	}
}

func TestStrictKeepsTheCloudCredentialsOut(t *testing.T) {
	f := newFakeSetup(t, "linux")
	f.loginShell = "/usr/bin/bash"
	if code := f.install(true); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	if cfg, _, _ := shield.LoadConfig(shield.ConfigPath(f.home)); cfg.Policy().Grants.Cloud {
		t.Error("--strict left the cloud credentials on")
	}
	if got := f.settingsEnv(t)["CLAUDE_CODE_SHELL"]; filepath.Base(got) != "golem-bash" {
		t.Errorf("a bash user got %q", got)
	}
}

func TestInstallLeavesTheUsersOwnShellAndSaysHow(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	shellVar := f.claudeShell().Var()
	writeFile(t, f.settingsPath(), `{"env": {"`+shellVar+`": "/opt/homebrew/bin/fish"}}`)
	if code := f.install(false); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := f.settingsEnv(t)[shellVar]; got != "/opt/homebrew/bin/fish" {
		t.Errorf("the user's shell was replaced with %q", got)
	}
	if !strings.Contains(f.out.String(), "left alone") {
		t.Errorf("no note about the user's shell:\n%s", f.out.String())
	}
}

func TestSettingsThatDoNotParseGetTheLineToAdd(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	writeFile(t, f.settingsPath(), "{ // comments are not JSON\n}")
	if code := f.install(false); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(f.errs.String(), `"`+f.claudeShell().Var()+`"`) {
		t.Errorf("no line to add:\n%s", f.errs.String())
	}
}

func TestAFailedSelfTestFailsTheInstall(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	f.selfTest = func(string, string) (int, error) { return 0, nil }
	if code := f.install(false); code != 1 || !strings.Contains(f.errs.String(), "Do not rely on the jail") {
		t.Errorf("exit %d:\n%s", code, f.errs.String())
	}
}

func TestWithTheAgentNothingIsTouched(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	f.agentRuns = func() bool { return true }
	if code := f.install(false); code != 0 || !strings.Contains(f.out.String(), "Golem agent runs the shield") {
		t.Fatalf("exit %d:\n%s", code, f.out.String())
	}
	if _, err := os.Stat(f.binDir()); err == nil {
		t.Error("installed beside the agent")
	}
	if code := f.uninstall(false); code != 1 {
		t.Errorf("uninstall beside the agent exited %d", code)
	}
}

func TestNoJailMeansNoInstall(t *testing.T) {
	f := newFakeSetup(t, "linux")
	f.canJail = func() bool { return false }
	if code := f.install(false); code != 1 || !strings.Contains(f.errs.String(), "Landlock") {
		t.Errorf("exit %d:\n%s", code, f.errs.String())
	}
	if f.settingsEnv(t) != nil {
		t.Error("pointed Claude Code at a shim that cannot jail")
	}
}

func TestUninstallPutsClaudeCodeBack(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	writeFile(t, f.settingsPath(), `{"model": "x"}`)
	f.install(false)
	if code := f.uninstall(true); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	b, _ := os.ReadFile(f.settingsPath())
	if strings.TrimSpace(string(b)) != "{\n  \"model\": \"x\"\n}" {
		t.Errorf("settings after uninstall: %s", b)
	}
	for _, p := range append(f.shims(), filepath.Join(f.binDir(), "golem-exec"), shield.ConfigPath(f.home)) {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
}

func TestWindowsInstallsGitBashAndTurnsPowerShellOff(t *testing.T) {
	f := newFakeSetup(t, "windows")
	if code := f.install(false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	env := f.settingsEnv(t)
	if env["CLAUDE_CODE_GIT_BASH_PATH"] != filepath.Join(f.binDir(), "bash.exe") || env["CLAUDE_CODE_USE_POWERSHELL_TOOL"] != "0" {
		t.Errorf("env %v", env)
	}
}

func TestStatusSaysWhatCommandsGet(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	f.status()
	if !strings.Contains(f.out.String(), "not installed") || !strings.Contains(f.out.String(), "baseline") {
		t.Errorf("before install:\n%s", f.out.String())
	}
	f.install(false)
	if err := shield.WriteConfig(shield.ConfigPath(f.home), shield.Config{Lockdown: true}); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	f.status()
	for _, want := range []string{"(jailed)", "lockdown on", "cloud credentials off"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("missing %q:\n%s", want, f.out.String())
		}
	}
}

func TestOnlyItsOwnNameRunsTheCommands(t *testing.T) {
	for name, want := range map[string]bool{"golem-exec": true, "golem-exec.exe": true, "GOLEM-EXEC.EXE": true, "golem-zsh": false, "bash.exe": false, "bash": false} {
		if isSelf(name) != want {
			t.Errorf("isSelf(%q) = %v", name, !want)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
