package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// hookPowerShell builds golem-exec into a throwaway home as the hook shim an
// agent's rewrite names, and returns it with that home.
func hookPowerShell(t *testing.T) (shim, home string) {
	t.Helper()
	home = t.TempDir()
	shim = filepath.Join(shield.HookShimDir(home), "powershell.exe")
	if err := os.MkdirAll(filepath.Dir(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", shim, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return shim, home
}

// runAsAgent runs a rewritten command the way the agents do on Windows:
// powershell.exe -NoProfile -NonInteractive -Command <command>.
func runAsAgent(t *testing.T, home, command string) (string, int) {
	t.Helper()
	cmd := exec.Command(windowsPowerShell(), "-NoProfile", "-NonInteractive", "-Command", command)
	cmd.Env = append(os.Environ(), "USERPROFILE="+home, "HOME="+home, "GOLEM_WITNESS_URL=http://127.0.0.1:1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode()
	}
	if err != nil {
		t.Fatalf("powershell: %v", err)
	}
	return string(out), 0
}

func TestAWrappedPowerShellCommandRunsJailedAndUnchanged(t *testing.T) {
	shim, home := hookPowerShell(t)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(testKey), 0o600); err != nil {
		t.Fatal(err)
	}

	wrap := func(c string) string {
		w, err := shield.WrapPowerShell(shim, c)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	out, code := runAsAgent(t, home, wrap(`Write-Output 'it''s "quoted" $HOME'; Write-Output "two words"`))
	if code != 0 || !strings.Contains(out, `it's "quoted" $HOME`) || !strings.Contains(out, "two words") {
		t.Errorf("the command reached PowerShell changed (exit %d): %q", code, out)
	}

	if _, code := runAsAgent(t, home, wrap(`exit 7`)); code != 7 {
		t.Errorf("exit status %d, want 7", code)
	}

	out, _ = runAsAgent(t, home, wrap(`Get-Content -Raw '`+key+`'; if ($?) { 'LEAKED' }`))
	if strings.Contains(out, "PRIVATE") || strings.Contains(out, "LEAKED") {
		t.Errorf("the jail let PowerShell read the key: %q", out)
	}

	escaped := filepath.Join(home, ".golem", "escaped")
	dressed := "$LASTEXITCODE = 126; & " + shield.QuotePowerShell(shim) + " -NoProfile -NonInteractive -EncodedCommand " +
		shield.EncodePowerShell("$null") + "; New-Item -ItemType File '" + escaped + "'; exit $LASTEXITCODE <# x #>"
	runAsAgent(t, home, wrap(dressed))
	if _, err := os.Stat(escaped); err == nil {
		t.Error("a command dressed as a wrap ran its middle outside the jail")
	}

	if b, err := os.ReadFile(key); err != nil || !strings.Contains(string(b), "PRIVATE") {
		t.Errorf("the user lost their own key: %v", err)
	}
}

// Hermes runs its commands in Git Bash on Windows, and its plugin rewrites one
// to name the bash.exe shim by its Git Bash path (/c/Users/...).
func TestGitBashRunsTheShimByItsGitBashPath(t *testing.T) {
	bash := gitBash(t)
	// A runner's own temp directory is an 8.3 name (RUNNER~1), which Git Bash
	// can't name unquoted; RUNNER_TEMP is a plain one.
	home := t.TempDir()
	if rt := os.Getenv("RUNNER_TEMP"); rt != "" {
		var err error
		if home, err = os.MkdirTemp(rt, "golem-hermes-"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(home) })
	}
	shim := filepath.Join(shield.ShimDir(home), "bash.exe")
	if err := os.MkdirAll(filepath.Dir(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", shim, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	msys, plain := shield.MSYSPath(shim)
	switch {
	case !plain && os.Getenv("RUNNER_TEMP") != "":
		t.Fatalf("Git Bash can't name %s unquoted, so CI would not have run this", shim)
	case !plain:
		t.Skipf("Git Bash can't name %s unquoted", shim)
	}
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(testKey), 0o600); err != nil {
		t.Fatal(err)
	}
	keyMSYS, _ := shield.MSYSPath(key)
	wrapped, err := shield.Wrap(msys, `printf '%s|' "it's"; cat '`+keyMSYS+`' && echo LEAKED; exit 3`)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "-c", wrapped)
	cmd.Env = append(os.Environ(), "USERPROFILE="+home, "GOLEM_WITNESS_URL=http://127.0.0.1:1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("exit %v: %s", err, out)
	}
	if !strings.Contains(string(out), "it's|") {
		t.Errorf("the command reached the shell changed: %q", out)
	}
	if strings.Contains(string(out), "PRIVATE") || strings.Contains(string(out), "LEAKED") {
		t.Errorf("the jail let Git Bash read the key: %q", out)
	}
}
