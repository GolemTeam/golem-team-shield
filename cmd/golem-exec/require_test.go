package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

func managedFrom(t *testing.T, body string) func() shield.Managed {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed-shield.json")
	writeFile(t, path, body)
	return func() shield.Managed { return shield.LoadManaged(path, nil) }
}

func TestInstallRequireSetsItAndStatusSaysWhatLacksIt(t *testing.T) {
	f := newFakeSetup(t, "darwin")
	if code := runCommand(f.setup, []string{"install", "--require"}); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	cfg, _, err := shield.LoadConfig(shield.ConfigPath(f.home))
	if err != nil || !cfg.RequireJail {
		t.Fatalf("require_jail not set: %+v %v", cfg, err)
	}
	if err := os.MkdirAll(filepath.Join(f.home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.home, ".cursor", "hooks.json"), `{}`)
	f.out.Reset()
	f.status()
	for _, want := range []string{"required     every agent here must be jailed (" + shield.ConfigPath(f.home) + ")", "DANGEROUS: the jail is required here"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("missing %q:\n%s", want, f.out.String())
		}
	}
}

func TestRefreshPutsBackTheJailOnlyWhereItIsRequired(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	if code := f.install("", false, false); code != 0 {
		t.Fatalf("install exited %d", code)
	}
	shellVar := f.claudeShell().Var()
	writeFile(t, f.settingsPath(), `{}`)
	if code := runCommand(f.setup, []string{"install", "--refresh"}); code != 0 {
		t.Fatalf("refresh exited %d", code)
	}
	if got := f.settingsEnv(t)[shellVar]; got != "" {
		t.Errorf("refresh re-wired Claude Code where the jail is not required: %q", got)
	}
	f.managed = managedFrom(t, `{"require_jail": true}`)
	f.out.Reset()
	if code := runCommand(f.setup, []string{"install", "--refresh"}); code != 0 {
		t.Fatalf("refresh exited %d", code)
	}
	if got := f.settingsEnv(t)[shellVar]; got != f.claudeShell().Shim {
		t.Errorf("refresh left Claude Code unjailed where the jail is required: %q\n%s", got, f.out.String())
	}
	if !strings.Contains(f.out.String(), "The jail is required here") {
		t.Errorf("no word of why:\n%s", f.out.String())
	}
}

func TestStatusShowsTheManagedSettingsAndFollowsThem(t *testing.T) {
	f := newFakeSetup(t, "darwin")
	writeFile(t, shield.ConfigPath(f.home), `{"cloud_credentials": true, "enforce": false}`)
	f.managed = managedFrom(t, `{"profile": "strict", "require_jail": true}`)
	f.status()
	for _, want := range []string{"managed      ", "which outranks the user's settings", "jail on", "cloud credentials off", "required     "} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("missing %q:\n%s", want, f.out.String())
		}
	}
}

func TestStatusSaysAManagedFileIsIgnored(t *testing.T) {
	f := newFakeSetup(t, "darwin")
	path := filepath.Join(t.TempDir(), "managed-shield.json")
	writeFile(t, path, `{"enforce": false}`)
	f.managed = func() shield.Managed {
		return shield.LoadManaged(path, func(string) error { return os.ErrPermission })
	}
	f.status()
	if !strings.Contains(f.out.String(), "is ignored") || !strings.Contains(f.out.String(), "jail on") {
		t.Errorf("%s", f.out.String())
	}
}

func TestTheShimFollowsTheManagedSettings(t *testing.T) {
	s, _, _ := testShim(t, "http://127.0.0.1:1")
	writeFile(t, shield.ConfigPath(s.home), `{"enforce": false}`)
	s.managed = managedFrom(t, `{"require_jail": true}`)
	p := s.configPolicy()
	if !p.Enforce || !p.RequireJail {
		t.Errorf("policy %+v", p)
	}
	s.managed = managedFrom(t, `{"enforce": nope}`)
	if p := s.configPolicy(); !p.Tainted() {
		t.Errorf("a managed file that can't be followed did not lock down: %+v", p)
	}
}
