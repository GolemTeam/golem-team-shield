// Package shield is the local shield's policy: what a jailed agent shell may
// touch, and the compilers that turn it into a kernel sandbox profile
// (https://docs.golem.team/shield). The witness decides the policy and the shell
// shim applies it, so both share this one definition.
package shield

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type State string

const (
	Clean   State = "clean"
	Tainted State = "tainted"
)

// Grants are on unless a profile in the console turns one off; a tainted
// session loses every one.
type Grants struct {
	Agent  bool `json:"agent"`  // the ssh-agent socket and the keychain
	Docker bool `json:"docker"` // the Docker socket
	Cloud  bool `json:"cloud"`  // gcloud, aws, kubectl, azure credential files
}

// Policy travels from the witness to the shim as JSON, so it holds decisions
// only; what the shim can see for itself is in Context.
type Policy struct {
	// Enforce is false only when the workspace switched the shield off.
	Enforce bool   `json:"enforce"`
	State   State  `json:"state"`
	Grants  Grants `json:"grants"`
	// EnvAllow lets through variables FilterEnv would strip, in a clean
	// session only; EnvDeny strips variables it would keep, always. Each is a
	// name, or a prefix ending in *.
	EnvAllow []string `json:"env_allow,omitempty"`
	EnvDeny  []string `json:"env_deny,omitempty"`
}

func AllGrants() Grants { return Grants{Agent: true, Docker: true, Cloud: true} }

// Baseline is what the shim applies when the witness doesn't answer and it
// knows nothing better about this machine.
func Baseline() Policy { return Policy{Enforce: true, State: Clean, Grants: AllGrants()} }

// Tainted treats any state other than clean as tainted, so a state from a
// newer witness that this build doesn't know reads as the tighter one.
func (p Policy) Tainted() bool { return p.State != Clean }

func (p Policy) Effective() Grants {
	if p.Tainted() {
		return Grants{}
	}
	return p.Grants
}

type Context struct {
	Home string
	// Workspace is where a tainted session may still write (FindWorkspace).
	Workspace []string
	// WorkspaceProtected stays unwritable to a tainted session inside
	// Workspace (see Workspace.Protected).
	WorkspaceProtected []string
	// TurnTmp is the command's private TMPDIR.
	TurnTmp     string
	AgentSocket string
	// SSHReadable is what the shim found in ~/.ssh that isn't a private key
	// (see SSHReadable); the profile lets those paths back, and only those
	// inside ~/.ssh.
	SSHReadable []string
	ExtraWrite  []string
	// HarnessTmp is where the agent harness has the shell write its own
	// bookkeeping: Claude Code records the cwd in a temp file after every
	// command, and a tainted session must not break that.
	HarnessTmp string
	// HarnessFiles are the harness's own files the shim created before the
	// command ran, for a jail that can only open paths that already exist
	// (Landlock): a tainted session may write them and nothing else there.
	HarnessFiles []string
	// RunTag marks every denial the kernel logs for this command, so the
	// witness can attribute what the jail refused to the run that did it.
	RunTag string
}

var runTagRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

var errRelative = errors.New("path must be absolute")

func (c Context) validate() error {
	if err := checkPath(c.Home); err != nil {
		return fmt.Errorf("home: %w", err)
	}
	if c.Home == "/" {
		return errors.New("home: must not be /")
	}
	for _, w := range c.Workspace {
		if err := checkPath(w); err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
		// A workspace holding the home directory would make every credential
		// store writable to a tainted session.
		if within(c.Home, w) {
			return fmt.Errorf("workspace %q contains the home directory", w)
		}
	}
	if c.RunTag != "" && !runTagRE.MatchString(c.RunTag) {
		return errors.New("run tag must be 1-64 letters, digits or dashes")
	}
	others := append([]string{c.TurnTmp, c.AgentSocket, c.HarnessTmp}, c.ExtraWrite...)
	others = append(others, c.HarnessFiles...)
	for _, p := range append(append(others, c.WorkspaceProtected...), c.SSHReadable...) {
		if p == "" {
			continue
		}
		if err := checkPath(p); err != nil {
			return err
		}
	}
	return nil
}

func checkPath(p string) error {
	if p == "" || !filepath.IsAbs(p) {
		return errRelative
	}
	if strings.ContainsAny(p, "\x00\n\r") {
		return errors.New("path contains a control character")
	}
	return nil
}

func within(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	if path == dir || dir == "/" {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}
