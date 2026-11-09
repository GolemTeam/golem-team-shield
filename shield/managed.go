package shield

import (
	"bytes"
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

// Managed settings are shield.json keys an administrator sets for every user
// of a machine, in a file only an administrator can write, which MDM tools
// deploy as they deploy Claude Code's and Copilot CLI's managed settings. A
// key the file names outranks the user's shield.json; lockdown and
// require_jail only ever tighten, so a user's true holds against the file's
// false. Like shield.json, they are followed when no Golem agent answers; with
// the agent, the workspace's profile is the administrator's.
type Managed struct {
	Path   string
	Config Config
	Keys   []string
	Found  bool
	// Err is a file that can't be followed, which locks every command down.
	Err error
	// Ignored is a file someone other than an administrator could change,
	// which is not followed at all.
	Ignored error
}

// ManagedConfigPath is where the managed settings live on goos.
func ManagedConfigPath(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/Golem/managed-shield.json"
	case "windows":
		return filepath.Join(cmp.Or(os.Getenv("ProgramFiles"), `C:\Program Files`), "Golem", "managed-shield.json")
	}
	return "/etc/golem/managed-shield.json"
}

// LoadManaged reads the managed settings at path. trusted says whether only
// an administrator could have written it; nil trusts it.
func LoadManaged(path string, trusted func(string) error) Managed {
	m := Managed{Path: path}
	if path == "" {
		return m
	}
	c, found, err := LoadConfig(path)
	if !found {
		return m
	}
	m.Found = true
	if trusted != nil {
		if terr := trusted(path); terr != nil {
			m.Ignored = terr
			return m
		}
	}
	if err != nil {
		m.Err = err
		return m
	}
	b, _ := os.ReadFile(path)
	var keys map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&keys); err != nil {
		m.Err = err
		return m
	}
	for k := range keys {
		m.Keys = append(m.Keys, k)
	}
	if c.Profile != "" {
		m.Keys = append(m.Keys, ProfileSettings...)
	}
	slices.Sort(m.Keys)
	m.Keys = slices.Compact(m.Keys)
	m.Config = c.Resolved()
	return m
}

// Applies reports whether the managed settings are there to be followed.
func (m Managed) Applies() bool { return m.Found && m.Err == nil && m.Ignored == nil }

// Under is c with the managed settings over it.
func (c Config) Under(m Managed) Config {
	if !m.Applies() {
		return c
	}
	lockdown, require := c.Lockdown, c.RequireJail
	cv, mv := reflect.ValueOf(&c).Elem(), reflect.ValueOf(m.Config)
	for i := 0; i < cv.NumField(); i++ {
		name, _, _ := strings.Cut(cv.Type().Field(i).Tag.Get("json"), ",")
		if slices.Contains(m.Keys, name) {
			cv.Field(i).Set(mv.Field(i))
		}
	}
	c.Lockdown = c.Lockdown || lockdown
	c.RequireJail = c.RequireJail || require
	return c
}

// MachineConfig is what golem-exec follows with no Golem agent: the user's
// shield.json under the managed settings. found is false when neither is
// there; an error is a file that can't be followed.
func MachineConfig(home string, m Managed) (c Config, found bool, err error) {
	if m.Err != nil {
		return Config{}, true, m.Err
	}
	c, found, err = LoadConfig(ConfigPath(home))
	if err != nil {
		return Config{}, true, err
	}
	return c.Under(m), found || m.Applies(), nil
}

// RequireJailPath is where the Golem agent leaves the workspace's
// require_jail switch, "on" or "off", for golem check and golem-exec, which
// run as processes of their own.
func RequireJailPath(home string) string {
	return filepath.Join(home, ".golem", "shield", "require-jail")
}

// SetJailRequired records the Golem agent's switch.
func SetJailRequired(home string, on bool) error {
	v := "off\n"
	if on {
		v = "on\n"
	}
	path := RequireJailPath(home)
	if b, err := os.ReadFile(path); err == nil && string(b) == v {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(v), 0o600)
}

// JailRequired reports whether this machine requires its agents to be
// jailed, and who says so: the managed settings, else the Golem agent's
// workspace where it left its switch, else shield.json.
func JailRequired(home string, m Managed) (bool, string) {
	if m.Applies() && m.Config.RequireJail {
		return true, m.Path
	}
	if b, err := os.ReadFile(RequireJailPath(home)); err == nil {
		if strings.TrimSpace(string(b)) == "on" {
			return true, "the workspace's profile"
		}
		return false, ""
	}
	if c, found, err := LoadConfig(ConfigPath(home)); found && err == nil && c.RequireJail {
		return true, ConfigPath(home)
	}
	return false, ""
}
