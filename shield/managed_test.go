package shield

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func writeManaged(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed-shield.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeUserConfig(t *testing.T, home, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".golem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ConfigPath(home), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestManagedSettingsOutrankTheUsersAndLeaveTheRest(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `{"profile": "standard", "cloud_credentials": true, "docker": false, "network": "open"}`)
	m := LoadManaged(writeManaged(t, `{"profile": "allowlist", "ssh_agent": false}`), nil)
	c, found, err := MachineConfig(home, m)
	if !found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
	p := c.Policy()
	if p.Grants.Cloud || p.Grants.Agent || p.Grants.Docker || !p.Proxied() {
		t.Errorf("the managed profile and ssh_agent did not hold, or the user's docker was lost: %+v", p)
	}
	if !slices.Equal(p.AllowedHosts, []string{"@model-apis", "@package-registries", "@git-hosts"}) {
		t.Errorf("hosts %v", p.AllowedHosts)
	}
}

func TestLockdownAndRequireOnlyTighten(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `{"lockdown": true, "require_jail": true}`)
	m := LoadManaged(writeManaged(t, `{"lockdown": false, "require_jail": false}`), nil)
	c, _, _ := MachineConfig(home, m)
	if !c.Lockdown || !c.RequireJail {
		t.Errorf("the managed false loosened the user's true: %+v", c)
	}
}

func TestManagedSettingsNoOneButAnAdministratorWroteAreIgnored(t *testing.T) {
	home := t.TempDir()
	m := LoadManaged(writeManaged(t, `{"enforce": false}`), func(string) error { return errors.New("not root's") })
	if m.Applies() || m.Ignored == nil {
		t.Fatalf("followed: %+v", m)
	}
	if c, _, _ := MachineConfig(home, m); !c.Policy().Enforce {
		t.Error("an untrusted managed file turned the jail off")
	}
}

func TestAManagedFileThatCantBeFollowedLocksDown(t *testing.T) {
	m := LoadManaged(writeManaged(t, `{"enforce": tru}`), nil)
	if m.Err == nil {
		t.Fatal("accepted")
	}
	if _, _, err := MachineConfig(t.TempDir(), m); err == nil {
		t.Error("MachineConfig followed it")
	}
}

func TestNoManagedFileIsTheUsersSettings(t *testing.T) {
	home := t.TempDir()
	m := LoadManaged(filepath.Join(t.TempDir(), "absent.json"), AdminOwned)
	if m.Found || m.Applies() {
		t.Fatalf("%+v", m)
	}
	if _, found, err := MachineConfig(home, m); found || err != nil {
		t.Errorf("found=%v err=%v", found, err)
	}
}

func TestRequiringTheJailKeepsItOn(t *testing.T) {
	off := false
	p := Config{Enforce: &off, RequireJail: true}.Policy()
	if !p.Enforce || !p.RequireJail {
		t.Errorf("policy %+v", p)
	}
}

func TestWhoRequiresTheJail(t *testing.T) {
	home := t.TempDir()
	none := LoadManaged("", nil)
	if on, _ := JailRequired(home, none); on {
		t.Error("required with nothing set")
	}
	writeUserConfig(t, home, `{"require_jail": true}`)
	if on, by := JailRequired(home, none); !on || by != ConfigPath(home) {
		t.Errorf("shield.json: %v %q", on, by)
	}
	if err := SetJailRequired(home, false); err != nil {
		t.Fatal(err)
	}
	if on, _ := JailRequired(home, none); on {
		t.Error("the agent's off did not outrank a shield.json left from before it")
	}
	path := writeManaged(t, `{"require_jail": true}`)
	if on, by := JailRequired(home, LoadManaged(path, nil)); !on || by != path {
		t.Errorf("managed: %v %q", on, by)
	}
	if err := SetJailRequired(home, true); err != nil {
		t.Fatal(err)
	}
	if on, by := JailRequired(home, none); !on || by != "the workspace's profile" {
		t.Errorf("agent: %v %q", on, by)
	}
}

func TestAdminOwnedRefusesAUsersFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a Unix user other than root")
	}
	if err := AdminOwned(writeManaged(t, `{}`)); err == nil {
		t.Error("a file a user owns was trusted")
	}
}
