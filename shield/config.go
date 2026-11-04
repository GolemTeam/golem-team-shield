package shield

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Config is a machine's own shield settings, which golem-exec follows when no
// Golem agent answers: ~/.golem/shield.json. With the agent, the agent decides
// and its cached decisions outrank this file, so a file left from before the
// agent cannot loosen an agent machine. A jailed command can neither read nor
// write ~/.golem, so the agent being watched cannot change it.
//
// A setting left out keeps the baseline's value.
type Config struct {
	// Enforce false runs commands without a jail.
	Enforce *bool `json:"enforce"`
	// Lockdown jails every command as a tainted session: no network, no
	// credentials, and no writes outside the workspace.
	Lockdown bool `json:"lockdown"`
	// SSHAgent is the SSH agent socket and the keychain.
	SSHAgent *bool `json:"ssh_agent"`
	// Docker is the Docker socket.
	Docker *bool `json:"docker"`
	// CloudCredentials are the AWS, gcloud, Azure, kubectl, Docker, npm and
	// PyPI credential files and the cloud CLIs' variables.
	CloudCredentials *bool `json:"cloud_credentials"`
	// EnvAllow keeps secret-shaped variables a command would otherwise lose,
	// and EnvDeny strips ones it would keep. Each is a name, or a prefix
	// ending in *. Lockdown ignores EnvAllow.
	EnvAllow []string `json:"env_allow"`
	EnvDeny  []string `json:"env_deny"`
	// Writes "workspace" keeps writes to the project, temp, the tool caches
	// and AllowWrite; "anywhere" leaves them as the baseline has them.
	Writes     Writes   `json:"writes"`
	AllowWrite []string `json:"allow_write"`
	// Network "allowlist" lets commands reach AllowedHosts only, through a
	// proxy, with everything else refused; "open" leaves the network be.
	Network      Network  `json:"network"`
	AllowedHosts []string `json:"allowed_hosts"`
}

const maxConfigBytes = 64 << 10

var envPatternRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\*?$`)

// ConfigPath is where a machine's shield settings live.
func ConfigPath(home string) string { return filepath.Join(home, ".golem", "shield.json") }

// DefaultConfig is what a new install writes, in full so every setting is
// there to edit: the baseline, with writes kept to the project as in Claude
// Code's sandbox. A file from before writes existed has none, and keeps
// writing anywhere.
func DefaultConfig() Config {
	on := true
	return Config{Enforce: &on, SSHAgent: &on, Docker: &on, CloudCredentials: &on, EnvAllow: []string{}, EnvDeny: []string{},
		Writes: WritesWorkspace, AllowWrite: []string{}, Network: NetworkOpen, AllowedHosts: []string{}}
}

// StrictConfig is the default without the cloud credentials, for a machine
// whose agents should not reach a cloud account from a shell.
func StrictConfig() Config {
	c := DefaultConfig()
	off := false
	c.CloudCredentials = &off
	return c
}

// LoadConfig reads path. A missing file is not an error: found is false. A
// file that does not parse, or names a setting this version does not know, is
// an error, and callers then use Unreadable, so a typo never loosens the jail.
func LoadConfig(path string) (c Config, found bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, true, err
	}
	if len(b) > maxConfigBytes {
		return Config{}, true, fmt.Errorf("larger than %d bytes", maxConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, true, err
	}
	for _, p := range append(append([]string{}, c.EnvAllow...), c.EnvDeny...) {
		if !envPatternRE.MatchString(p) {
			return Config{}, true, fmt.Errorf("%q is not a variable name or a prefix ending in *", p)
		}
	}
	if err := c.checkConfinement(); err != nil {
		return Config{}, true, err
	}
	return c, true, nil
}

// WriteConfig writes c to path, private to its owner.
func WriteConfig(path string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Unreadable is the policy for a settings file that is there but cannot be
// followed: the tightest one. Falling back to the baseline would quietly drop
// a lockdown the file asked for, while a too-tight jail is noticed and fixed.
func Unreadable() Policy { return Config{Lockdown: true}.Policy() }

// Policy is the shield policy the settings ask for.
func (c Config) Policy() Policy {
	p := Baseline()
	p.Enforce = orTrue(c.Enforce)
	if c.Lockdown {
		p.State = Tainted
	}
	p.Grants = Grants{Agent: orTrue(c.SSHAgent), Docker: orTrue(c.Docker), Cloud: orTrue(c.CloudCredentials)}
	p.EnvAllow, p.EnvDeny = c.EnvAllow, c.EnvDeny
	p.Writes, p.AllowWrite = c.Writes, c.AllowWrite
	p.Network, p.AllowedHosts = c.Network, c.AllowedHosts
	return p
}

func (c Config) checkConfinement() error {
	switch c.Writes {
	case "", WritesAnywhere, WritesWorkspace:
	default:
		return fmt.Errorf("writes is %q; it must be \"anywhere\" or \"workspace\"", c.Writes)
	}
	switch c.Network {
	case "", NetworkOpen, NetworkAllowlist:
	default:
		return fmt.Errorf("network is %q; it must be \"open\" or \"allowlist\"", c.Network)
	}
	if len(c.AllowWrite) > MaxAllowWrite || len(c.AllowedHosts) > MaxAllowedHosts {
		return fmt.Errorf("at most %d allow_write and %d allowed_hosts entries", MaxAllowWrite, MaxAllowedHosts)
	}
	for _, w := range c.AllowWrite {
		if err := CheckWritePath(w); err != nil {
			return fmt.Errorf("allow_write: %w", err)
		}
	}
	for _, h := range c.AllowedHosts {
		if err := CheckHost(h); err != nil {
			return fmt.Errorf("allowed_hosts: %w", err)
		}
	}
	return nil
}

func orTrue(b *bool) bool { return b == nil || *b }
