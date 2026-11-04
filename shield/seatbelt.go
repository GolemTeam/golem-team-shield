package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

type match struct {
	kind string // literal | subpath | regex
	path string // relative to home unless abs
	abs  bool
}

func lit(p string) match    { return match{kind: "literal", path: p} }
func sub(p string) match    { return match{kind: "subpath", path: p} }
func rx(p string) match     { return match{kind: "regex", path: p} }
func absLit(p string) match { return match{kind: "literal", path: p, abs: true} }
func absSub(p string) match { return match{kind: "subpath", path: p, abs: true} }
func absRx(p string) match  { return match{kind: "regex", path: p, abs: true} }

// ~/.ssh is unreadable whole, so a private key is out of reach whatever it is
// called (google_compute_engine, deploy keys, a YubiKey stub). sshReadable and
// Context.SSHReadable then open what isn't a key.
var secretStores = []match{
	sub(".ssh"),
	sub(".gnupg/private-keys-v1.d"),
	lit(".netrc"),
	lit(".git-credentials"),
	sub(".golem"),
	lit(".zsh_history"),
	lit(".bash_history"),
	sub(".zsh_sessions"),
}

// agentStores go with the Agent grant, because using the keychain means
// reading them: the security tool (which gh and git's credential helper use)
// opens the keychain database itself, and gh reads its hosts file on every
// command. The database stays encrypted and each item keeps its access list.
var agentStores = []match{
	sub("Library/Keychains"),
	lit(".config/gh/hosts.yml"),
}

// sshReadable is allowed back after secretStores (the last matching rule
// wins): public keys, config, known hosts, authorized keys and allowed signers.
// None of them is a secret, and ssh or git signing reads each one.
var sshReadable = []match{
	lit(".ssh"),
	rx(`/\.ssh/[^/]*\.pub$`),
	lit(".ssh/config"),
	rx(`/\.ssh/known_hosts[^/]*$`),
	rx(`/\.ssh/authorized_keys[^/]*$`),
	lit(".ssh/allowed_signers"),
}

var cloudStores = []match{
	sub(".aws"),
	sub(".config/gcloud"),
	sub(".kube"),
	sub(".azure"),
	lit(".docker/config.json"),
	lit(".npmrc"),
	lit(".pypirc"),
}

// protectedWrites are where a write would switch Golem off or make a
// compromise outlive the session.
var protectedWrites = []match{
	sub(".golem"),
	sub(".ssh"),
	lit(".claude.json"),
	lit(".claude/settings.json"),
	lit(".claude/settings.local.json"),
	sub(".claude/hooks"),
	lit(".cursor/mcp.json"),
	lit(".cursor/hooks.json"),
	lit(".codex/hooks.json"),
	lit(".codex/config.toml"),
	lit(".gemini/settings.json"),
	lit(".zshrc"),
	lit(".zprofile"),
	lit(".zshenv"),
	lit(".zlogin"),
	lit(".bashrc"),
	lit(".bash_profile"),
	lit(".profile"),
	lit(".gitconfig"),
	lit(".config/git/config"),
	sub("Library/LaunchAgents"),
}

var dockerSockets = []match{
	absLit("/private/var/run/docker.sock"),
	lit(".docker/run/docker.sock"),
	lit(".orbstack/run/docker.sock"),
	lit(".rd/docker.sock"),
	rx(`/\.colima/[^/]+/docker\.sock$`),
}

var agentSockets = []match{
	absRx(`^/private/tmp/com\.apple\.launchd\.[^/]+/Listeners$`),
	lit("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
	rx(`/\.gnupg/S\.gpg-agent[^/]*$`),
}

var keychainServices = []string{"com.apple.SecurityServer", "com.apple.securityd.xpc"}

// DNS goes to mDNSResponder over Mach IPC, not a socket, so denying the
// network alone leaves it open as an exfiltration channel.
var resolverServices = []string{"com.apple.dnssd.service", "com.apple.mDNSResponder"}

var deviceWrites = []match{
	absLit("/dev/null"),
	absLit("/dev/zero"),
	absLit("/dev/tty"),
	absLit("/dev/dtracehelper"),
	absLit("/dev/stdout"),
	absLit("/dev/stderr"),
	absLit("/dev/autofs_nowait"),
	absRx(`^/dev/ttys[0-9]+$`),
	absRx(`^/dev/fd/`),
}

// workspaceSettings would let a command re-point the agent's shell: Claude
// Code's project settings override the user's env, CLAUDE_CODE_SHELL
// included, and the work tree is otherwise writable.
var workspaceSettings = []string{".claude/settings.json", ".claude/settings.local.json"}

// claudeCwdFile is where Claude Code has the shell record its cwd after every
// command ($CLAUDE_CODE_TMPDIR or /tmp, claude-<id>-cwd).
const claudeCwdFile = `/claude-[A-Za-z0-9-]+-cwd$`

// CompileSeatbelt renders p as a macOS sandbox profile. Seatbelt applies the
// last rule that matches, so the order is the policy: open by default, then
// the write floor (tainted, or confined to the workspace), the network
// confined to the proxy, then the denials that hold in every state.
func CompileSeatbelt(p Policy, c Context) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	home := darwinPath(c.Home)
	g := p.Effective()
	w := &profile{tag: c.RunTag}
	b := &w.b
	b.WriteString("(version 1)\n(allow default)\n")
	w.bare("deny mach-priv-task-port")

	if roots := writeRoots(p, c, "darwin"); roots != nil {
		w.bare("deny file-write*")
		writable := append([]match{}, deviceWrites...)
		for _, r := range roots {
			writable = append(writable, absSub(r))
		}
		if c.HarnessTmp != "" {
			writable = append(writable, absRx("^"+reQuote(darwinPath(c.HarnessTmp))+claudeCwdFile))
		}
		w.paths("allow file-write*", home, writable)
		if len(c.WorkspaceProtected) > 0 {
			var protected []match
			for _, w := range c.WorkspaceProtected {
				protected = append(protected, absSub(w))
			}
			w.paths("deny file-write*", home, protected)
		}
	}

	protected := append([]match{}, protectedWrites...)
	for _, ws := range c.Workspace {
		for _, f := range workspaceSettings {
			protected = append(protected, absLit(filepath.Join(ws, f)))
		}
	}
	w.paths("deny file-write*", home, protected)
	w.paths("deny file-read* file-write*", home, append(append([]match{}, secretStores...), darwinAppStores...))
	readable := append([]match{}, sshReadable...)
	// Only a socket in ~/.ssh needs letting back: that is the one place the
	// deny above covers it, and the jail can't write there to swap it for a
	// link to a key. Anywhere else the path is the command's to replace.
	sshDir := filepath.Join(c.Home, ".ssh")
	if g.Agent && c.AgentSocket != "" && within(c.AgentSocket, sshDir) {
		readable = append(readable, absLit(c.AgentSocket))
	}
	for _, p := range c.SSHReadable {
		if within(p, sshDir) && filepath.Clean(p) != sshDir {
			readable = append(readable, absLit(p))
		}
	}
	w.paths("allow file-read*", home, readable)
	if p.Proxied() {
		// Seatbelt names no host but localhost, so the allowlist is the
		// proxy's to enforce; the jail lets nothing else out, DNS included.
		// Unix sockets stay as the grants below leave them.
		w.bare("deny network-outbound")
		w.b.WriteString("(allow network-outbound\n  (remote unix-socket (path-regex #\"^/\"))")
		if c.ProxyPort > 0 {
			w.b.WriteString(fmt.Sprintf("\n  (remote ip \"localhost:%d\")", c.ProxyPort))
		}
		w.b.WriteString(")\n")
		w.services(resolverServices)
	}
	if !g.Cloud {
		w.paths("deny file-read* file-write*", home, cloudStores)
	}
	if !g.Docker {
		w.sockets(home, dockerSockets)
	}
	if !g.Agent {
		sockets := append([]match{}, agentSockets...)
		if c.AgentSocket != "" {
			sockets = append(sockets, absLit(c.AgentSocket))
		}
		w.sockets(home, sockets)
		w.services(keychainServices)
		w.paths("deny file-read* file-write*", home, agentStores)
	}
	if p.Tainted() {
		w.bare("deny network*")
		w.services(resolverServices)
	}
	return b.String(), nil
}

// ProfileHash goes on the ledger so a verifier can tell which rules held for a
// run without the profile itself being there.
func ProfileHash(profile string) string {
	sum := sha256.Sum256([]byte(profile))
	return hex.EncodeToString(sum[:])
}

// DenialTag is the line the kernel appends to a logged denial from a run
// compiled with Context.RunTag.
const DenialTag = "golem-run "

type profile struct {
	b   strings.Builder
	tag string
}

func (w *profile) end(verb string) {
	if w.tag != "" && strings.HasPrefix(verb, "deny") {
		w.b.WriteString(" (with message " + quote(DenialTag+w.tag) + ")")
	}
	w.b.WriteString(")\n")
}

func (w *profile) bare(verb string) {
	w.b.WriteString("(" + verb)
	w.end(verb)
}

func (w *profile) paths(verb, home string, ms []match) {
	w.b.WriteString("(" + verb)
	for _, m := range ms {
		w.b.WriteString("\n  " + filter(m, home, false))
	}
	w.end(verb)
}

func (w *profile) sockets(home string, ms []match) {
	w.b.WriteString("(deny network-outbound")
	for _, m := range ms {
		w.b.WriteString("\n  (remote unix-socket " + filter(m, home, true) + ")")
	}
	w.end("deny")
}

func (w *profile) services(names []string) {
	w.b.WriteString("(deny mach-lookup")
	for _, n := range names {
		w.b.WriteString("\n  (global-name " + quote(n) + ")")
	}
	w.end("deny")
}

// Socket filters take path-literal and path-regex where file filters take
// literal and regex; a socket has no subpath.
func filter(m match, home string, socket bool) string {
	if m.kind == "regex" {
		re := m.path
		if !m.abs {
			re = "^" + reQuote(home) + re
		}
		op := "regex"
		if socket {
			op = "path-regex"
		}
		return "(" + op + ` #"` + strings.ReplaceAll(re, `"`, `\"`) + `")`
	}
	op := m.kind
	if socket {
		op = "path-literal"
	}
	return "(" + op + " " + quote(resolve(m, home)) + ")"
}

func resolve(m match, home string) string {
	if m.abs {
		return darwinPath(m.path)
	}
	return filepath.Join(home, m.path)
}

// darwinPath maps /tmp, /var and /etc to /private, because Seatbelt matches
// the resolved path and a rule written against /tmp/x never fires.
func darwinPath(p string) string {
	for _, top := range []string{"/tmp", "/var", "/etc"} {
		if p == top || strings.HasPrefix(p, top+"/") {
			return "/private" + p
		}
	}
	return p
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func reQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
