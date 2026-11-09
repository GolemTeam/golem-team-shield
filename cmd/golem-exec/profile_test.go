package main

import (
	"os"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

func TestInstallWritesTheProfileItIsGiven(t *testing.T) {
	for _, args := range [][]string{{"install", "--profile", "allowlist"}, {"install", "--profile=allowlist"}} {
		f := newFakeSetup(t, hostLayout())
		if code := runCommand(f.setup, args); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, f.errs.String())
		}
		cfg, _, err := shield.LoadConfig(shield.ConfigPath(f.home))
		if err != nil || cfg.Profile != shield.ProfileAllowlist || !cfg.Policy().Proxied() || cfg.Policy().Grants.Cloud {
			t.Errorf("%v: %+v %v", args, cfg, err)
		}
	}
}

func TestInstallRefusesAProfileItDoesNotKnow(t *testing.T) {
	for _, args := range [][]string{{"install", "--profile", "paranoid"}, {"install", "--profile"}} {
		f := newFakeSetup(t, hostLayout())
		if code := runCommand(f.setup, args); code != 2 || !strings.Contains(f.errs.String(), "standard, strict, allowlist") {
			t.Errorf("%v: exit %d: %s", args, code, f.errs.String())
		}
		if _, err := os.Stat(shield.ConfigPath(f.home)); err == nil {
			t.Errorf("%v wrote settings", args)
		}
	}
}

func TestANewInstallIsStandardAndStrictIsAProfile(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	if code := runCommand(f.setup, []string{"install"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if cfg, _, _ := shield.LoadConfig(shield.ConfigPath(f.home)); cfg.Profile != shield.ProfileStandard {
		t.Errorf("a new install has profile %q", cfg.Profile)
	}
	f = newFakeSetup(t, hostLayout())
	if code := runCommand(f.setup, []string{"install", "--strict"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if cfg, _, _ := shield.LoadConfig(shield.ConfigPath(f.home)); cfg.Profile != shield.ProfileStrict {
		t.Errorf("--strict wrote profile %q", cfg.Profile)
	}
}

func TestAProfileOnAnExistingFileTakesOutWhatItDecidesUnlessTighter(t *testing.T) {
	f := newFakeSetup(t, hostLayout())
	writeFile(t, shield.ConfigPath(f.home), `{
  "enforce": true,
  "cloud_credentials": true,
  "writes": "workspace",
  "network": "allowlist",
  "allowed_hosts": ["github.com"],
  "env_allow": ["MY_TOKEN"]
}`)
	if code := f.install(shield.ProfileStrict, false, false); code != 0 {
		t.Fatalf("exit %d: %s", code, f.errs.String())
	}
	cfg, _, err := shield.LoadConfig(shield.ConfigPath(f.home))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != shield.ProfileStrict || cfg.CloudCredentials != nil || cfg.Writes != "" {
		t.Errorf("the looser settings stayed: %+v", cfg)
	}
	if cfg.Network != shield.NetworkAllowlist || len(cfg.AllowedHosts) != 1 || len(cfg.EnvAllow) != 1 {
		t.Errorf("a tighter or unrelated setting went: %+v", cfg)
	}
	for _, want := range []string{"Took out cloud_credentials, writes", "Kept network, allowed_hosts"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("missing %q:\n%s", want, f.out.String())
		}
	}
}

func TestStatusShowsTheProfileAndWhatOutranksIt(t *testing.T) {
	f := newFakeSetup(t, "darwin")
	writeFile(t, shield.ConfigPath(f.home), `{"profile": "strict", "cloud_credentials": true}`)
	f.status()
	for _, want := range []string{"profile      strict: ", "outranked by the file's own cloud_credentials", "cloud credentials on"} {
		if !strings.Contains(f.out.String(), want) {
			t.Errorf("missing %q:\n%s", want, f.out.String())
		}
	}
}
