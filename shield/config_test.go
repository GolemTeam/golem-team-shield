package shield

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestStrictTakesTheCloudCredentialsAway(t *testing.T) {
	if g := StrictConfig().Policy().Grants; g.Cloud || !g.Agent || !g.Docker {
		t.Errorf("strict grants %+v", g)
	}
}

func TestLockdownIsATaintedSession(t *testing.T) {
	p := Config{Lockdown: true}.Policy()
	if !p.Tainted() || p.Effective() != (Grants{}) || !p.Enforce {
		t.Errorf("lockdown policy %+v", p)
	}
}

func TestDefaultConfigNamesEverySetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.json")
	if err := WriteConfig(path, DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, key := range []string{"enforce", "lockdown", "ssh_agent", "docker", "cloud_credentials", "env_allow", "env_deny"} {
		if !strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("%s is missing from the default file:\n%s", key, b)
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
	want := StrictConfig()
	want.EnvAllow = []string{"MY_TOKEN"}
	want.EnvDeny = []string{"INTERNAL_*"}
	if err := WriteConfig(path, want); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
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
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, found, err := LoadConfig(path); !found || err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
