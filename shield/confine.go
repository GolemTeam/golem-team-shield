package shield

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

type Writes string

const (
	WritesAnywhere  Writes = "anywhere"
	WritesWorkspace Writes = "workspace"
)

type Network string

const (
	NetworkOpen      Network = "open"
	NetworkAllowlist Network = "allowlist"
)

// ConfinedWrites reports whether a clean session writes only its roots. A
// value this build doesn't know reads as the tighter one.
func (p Policy) ConfinedWrites() bool {
	return !p.Tainted() && p.Writes != "" && p.Writes != WritesAnywhere
}

// Proxied reports whether a clean session's network goes only through the
// shim's proxy. A tainted session has none at all.
func (p Policy) Proxied() bool {
	return !p.Tainted() && p.Network != "" && p.Network != NetworkOpen
}

// toolCaches are writable to a session confined to the workspace, because a
// build that can't write its cache fails. Where tools install executables
// (~/go/bin, ~/.cargo/bin, ~/.local/bin) is left out: that is where a
// compromise persists.
var toolCaches = []string{
	".cache", ".npm", ".yarn", ".pnpm-store", ".bun/install/cache", "go/pkg/mod",
	".cargo/registry", ".cargo/git", ".gradle/caches", ".m2/repository",
}

var darwinToolCaches = []string{"Library/Caches"}

var windowsToolCaches = []string{
	"AppData/Local/npm-cache", "AppData/Local/go-build", "AppData/Local/pip", "AppData/Local/Yarn",
	"AppData/Local/pnpm-store", "AppData/Local/NuGet", ".nuget/packages",
}

// ToolCaches are the cache directories under home a confined session may
// write on goos.
func ToolCaches(home, goos string) []string {
	rel := toolCaches
	switch goos {
	case "darwin":
		rel = append(append([]string{}, toolCaches...), darwinToolCaches...)
	case "windows":
		rel = append(append([]string{}, toolCaches...), windowsToolCaches...)
	}
	out := make([]string, len(rel))
	for i, r := range rel {
		out[i] = filepath.Join(home, filepath.FromSlash(r))
	}
	return out
}

const (
	MaxAllowWrite   = 64
	MaxAllowedHosts = 256
)

// CheckWritePath validates an allow_write entry: an absolute path or one
// under ~/. Whether it holds the home directory is only known on the machine,
// where ExpandWritePaths drops it.
func CheckWritePath(p string) error {
	if strings.ContainsAny(p, "\x00\n\r") || len(p) > 1024 {
		return errors.New("must be a path")
	}
	rest, home := strings.CutPrefix(p, "~/")
	if !home && !strings.HasPrefix(p, "/") && !driveRE.MatchString(p) {
		return fmt.Errorf("%q must be absolute or start with ~/", p)
	}
	if home && strings.Trim(rest, "/") == "" {
		return fmt.Errorf("%q is the home directory", p)
	}
	return nil
}

// ExpandWritePaths resolves allow_write entries against home and drops any
// that is, or holds, home: that would open every credential store to writes.
func ExpandWritePaths(entries []string, home string) []string {
	var out []string
	for _, e := range entries {
		if CheckWritePath(e) != nil {
			continue
		}
		p := e
		if rest, ok := strings.CutPrefix(e, "~/"); ok {
			p = filepath.Join(home, filepath.FromSlash(rest))
		}
		p = filepath.Clean(p)
		if within(home, p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

var driveRE = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

var hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// CheckHost validates an allowed_hosts entry: a host name, an address, a
// *.suffix wildcard (any subdomain, not the suffix itself), or * for any
// public host.
func CheckHost(h string) error {
	if h == "*" {
		return nil
	}
	if strings.HasPrefix(h, "@") {
		if _, ok := HostPresetNamed(h); !ok {
			return fmt.Errorf("%q is not a preset; the presets are %s", h, strings.Join(HostPresetNames(), ", "))
		}
		return nil
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return nil
	}
	name := strings.TrimPrefix(h, "*.")
	if len(name) > 253 || name != strings.ToLower(name) {
		return fmt.Errorf("%q must be a lower-case host name, *.suffix or *", h)
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 && strings.HasPrefix(h, "*.") {
		return fmt.Errorf("%q matches a whole top-level domain", h)
	}
	for _, l := range labels {
		if !hostLabelRE.MatchString(l) {
			return fmt.Errorf("%q must be a lower-case host name, *.suffix or *", h)
		}
	}
	return nil
}

// AllowsLoopback reports whether an allowlist names the machine itself. Only
// then may a command reach a server on loopback, its own test server
// included: the local daemons, the Golem agent among them, are otherwise a
// way around the list.
func AllowsLoopback(hosts []string) bool {
	for _, h := range hosts {
		if isLoopbackName(h) {
			return true
		}
	}
	return false
}

func isLoopbackName(h string) bool {
	switch strings.Trim(strings.ToLower(h), "[]") {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// writeRoots are where a confined session may write, or nil when its writes
// aren't confined.
func writeRoots(p Policy, c Context, goos string) []string {
	if !p.Tainted() && !p.ConfinedWrites() {
		return nil
	}
	roots := append(append([]string{c.TurnTmp}, c.Workspace...), c.ExtraWrite...)
	if p.ConfinedWrites() {
		if len(c.Workspace) == 0 {
			roots = append(roots, c.WorkingDir)
		}
		roots = append(roots, c.SystemTmp...)
		roots = append(roots, ToolCaches(c.Home, goos)...)
		roots = append(roots, ExpandWritePaths(p.AllowWrite, c.Home)...)
	}
	var out []string
	for _, r := range roots {
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}
