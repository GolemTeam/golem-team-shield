package shield

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAMissingConfigIsNotAnError(t *testing.T) {
	_, found, err := LoadConfig(filepath.Join(t.TempDir(), "shield.json"))
	if found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestAnEmptyConfigIsTheBaseline(t *testing.T) {
	if got := (Config{}).Policy(); !reflect.DeepEqual(got, Baseline()) {
		t.Errorf("got %+v, want %+v", got, Baseline())
	}
	if got := DefaultConfig().Policy(); got.Enforce != true || got.Grants != AllGrants() || got.Tainted() {
		t.Errorf("the default config is not the baseline: %+v", got)
	}
}

func TestANewInstallKeepsWritesToTheProjectAndAnOldFileDoesNot(t *testing.T) {
	if !DefaultConfig().Policy().ConfinedWrites() {
		t.Error("a new install writes anywhere")
	}
	path := filepath.Join(t.TempDir(), "shield.json")
	if err := os.WriteFile(path, []byte(`{"enforce": true, "cloud_credentials": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, _, err := LoadConfig(path); err != nil || c.Policy().ConfinedWrites() {
		t.Errorf("a file from before writes existed is now confined: %+v %v", c, err)
	}
}

func TestStrictTakesTheCloudCredentialsAwayAndKeepsWritesToTheWorkspace(t *testing.T) {
	p := NewConfig(ProfileStrict).Policy()
	if g := p.Grants; g.Cloud || !g.Agent || !g.Docker {
		t.Errorf("strict grants %+v", g)
	}
	if !p.ConfinedWrites() || p.Proxied() {
		t.Errorf("strict policy %+v", p)
	}
}

func TestLockdownIsATaintedSession(t *testing.T) {
	p := Config{Lockdown: true}.Policy()
	if !p.Tainted() || p.Effective() != (Grants{}) || !p.Enforce {
		t.Errorf("lockdown policy %+v", p)
	}
}

func TestDefaultConfigNamesEverySettingItsProfileLeavesAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.json")
	if err := WriteConfig(path, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, key := range []string{"profile", "enforce", "lockdown", "ssh_agent", "docker", "env_allow", "env_deny", "allow_write", "jail_past_approval", "require_jail"} {
		if !strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("%s is missing from the default file:\n%s", key, b)
		}
	}
	for _, key := range ProfileSettings {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("%s is in the default file, where it would outrank the profile:\n%s", key, b)
		}
	}
}

func TestAnUnreadableFileGetsTheTightestPolicy(t *testing.T) {
	if p := Unreadable(); !p.Enforce || !p.Tainted() {
		t.Errorf("unreadable policy %+v", p)
	}
}

func TestConfigRoundTripsAndRefusesWhatItDoesNotKnow(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".golem", "shield.json")
	want := NewConfig(ProfileStrict)
	want.EnvAllow = []string{"MY_TOKEN"}
	want.EnvDeny = []string{"INTERNAL_*"}
	want.Network, want.AllowedHosts = NetworkAllowlist, []string{"github.com", "*.npmjs.org"}
	want.AllowWrite = []string{"~/go/bin"}
	if err := WriteConfig(path, want); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	got, found, err := LoadConfig(path)
	if !found || err != nil || !reflect.DeepEqual(got.Policy(), want.Policy()) {
		t.Fatalf("round trip: found=%v err=%v got %+v", found, err, got)
	}
	for name, body := range map[string]string{
		"a typo":             `{"cloud_credential": false}`,
		"not JSON":           `{"enforce": tru}`,
		"a bad env pattern":  `{"env_allow": ["*"]}`,
		"a pattern with a =": `{"env_deny": ["A=B"]}`,
		"an unknown writes":  `{"writes": "nowhere"}`,
		"an unknown network": `{"network": "closed"}`,
		"a URL for a host":   `{"allowed_hosts": ["https://github.com"]}`,
		"a relative path":    `{"allow_write": ["build"]}`,
		"home itself":        `{"allow_write": ["~/"]}`,
		"an unknown profile": `{"profile": "paranoid"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, found, err := LoadConfig(path); !found || err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
