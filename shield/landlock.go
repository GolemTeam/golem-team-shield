package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

// Landlock filesystem rights, as include/uapi/linux/landlock.h numbers them.
const (
	llExecute    uint64 = 1 << 0
	llWriteFile  uint64 = 1 << 1
	llReadFile   uint64 = 1 << 2
	llReadDir    uint64 = 1 << 3
	llRemoveDir  uint64 = 1 << 4
	llRemoveFile uint64 = 1 << 5
	llMakeChar   uint64 = 1 << 6
	llMakeDir    uint64 = 1 << 7
	llMakeReg    uint64 = 1 << 8
	llMakeSock   uint64 = 1 << 9
	llMakeFifo   uint64 = 1 << 10
	llMakeBlock  uint64 = 1 << 11
	llMakeSym    uint64 = 1 << 12
	llRefer      uint64 = 1 << 13 // ABI 2
	llTruncate   uint64 = 1 << 14 // ABI 3
)

const (
	llRead  = llReadFile | llReadDir
	llWrite = llWriteFile | llRemoveDir | llRemoveFile | llMakeChar | llMakeDir | llMakeReg |
		llMakeSock | llMakeFifo | llMakeBlock | llMakeSym | llRefer | llTruncate
	// llFileRights are the only rights a rule on a file (not a directory) may
	// carry; the kernel refuses the rest.
	llFileRights = llExecute | llWriteFile | llReadFile | llTruncate
)

// LandlockMinABI is the first kernel interface the Linux jail can use (5.13).
const LandlockMinABI = 1

// llSupported is what each ABI knows how to restrict. Execute is never
// handled: the shield doesn't restrict what runs, only what it can touch.
func llSupported(abi int) uint64 {
	s := llRead | llWrite
	if abi < 2 {
		s &^= llRefer
	}
	if abi < 3 {
		s &^= llTruncate
	}
	return s
}

// SocketDeny is what the Linux jail's seccomp filter refuses at socket().
// Landlock can't tell one Unix socket from another, so a grant switched off
// takes every Unix socket with it rather than leaving the Docker daemon or the
// ssh agent reachable.
type SocketDeny string

const (
	SocketsOpen SocketDeny = ""
	SocketsUnix SocketDeny = "unix"
	SocketsAll  SocketDeny = "all"
)

// LinuxJail is the compiled Linux policy: Landlock rules the shim's jail stage
// applies to itself before it execs the shell, and the sockets seccomp
// refuses. It travels from the shim to its jail stage as JSON.
type LinuxJail struct {
	ABI     int            `json:"abi"`
	Handled uint64         `json:"handled"`
	Rules   []LandlockRule `json:"rules"`
	Sockets SocketDeny     `json:"sockets,omitempty"`
}

// LandlockRule grants Access on Path and everything beneath it.
type LandlockRule struct {
	Path   string `json:"path"`
	Access uint64 `json:"access"`
	Dir    bool   `json:"dir"`
}

// Hash goes on the ledger as the run's policy hash.
func (j LinuxJail) Hash() string {
	raw, _ := json.Marshal(j)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// linuxAgentStores are what the Agent grant opens on Linux: gh's token file
// and the GNOME keyring's databases (the Secret Service the keyring serves
// over D-Bus is a Unix socket, which SocketsUnix closes).
var linuxAgentStores = []match{
	lit(".config/gh/hosts.yml"),
	sub(".local/share/keyrings"),
}

// linuxProtectedWrites add the places a Linux session starts things from.
var linuxProtectedWrites = []match{
	sub(".config/systemd"),
	sub(".config/autostart"),
	sub(".config/environment.d"),
	lit(".bash_login"),
	lit(".bash_logout"),
	lit(".pam_environment"),
	lit(".xprofile"),
	lit(".xsessionrc"),
}

// linuxDeviceWrites stay writable to a tainted session.
var linuxDeviceWrites = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/ptmx", "/dev/pts", "/dev/shm"}

// maxDirEntries bounds how many entries one directory on the way to a denied
// path contributes. Entries past it get no rule, which only makes the jail
// stricter.
const maxDirEntries = 2048

// CompileLandlock renders p as a Landlock ruleset for a kernel offering abi.
//
// Landlock only allows, so every denial is a complement: the jail grants a
// right on each directory that holds no denied path, and walks down into the
// ones that do. A directory on the way to a denied path gets nothing itself
// (a right on a directory reaches everything beneath it); its existing files
// get the file rights, so they can still be read or written in place, but
// nothing can be created or removed directly in it, nor moved in or out.
// Listing is allowed everywhere, so the names in ~/.ssh show though no key
// reads.
func CompileLandlock(p Policy, c Context, abi int) (LinuxJail, error) {
	if abi < LandlockMinABI {
		return LinuxJail{}, errors.New("landlock is not available")
	}
	if err := c.validate(); err != nil {
		return LinuxJail{}, err
	}
	g := p.Effective()
	supported := llSupported(abi)
	r := newRules(supported)

	readDeny := homePaths(c.Home, secretStores)
	writeDeny := append(homePaths(c.Home, protectedWrites), homePaths(c.Home, linuxProtectedWrites)...)
	writeDeny = append(writeDeny, readDeny...)
	if !g.Cloud {
		readDeny = append(readDeny, homePaths(c.Home, cloudStores)...)
		writeDeny = append(writeDeny, homePaths(c.Home, cloudStores)...)
	}
	if !g.Agent {
		readDeny = append(readDeny, homePaths(c.Home, linuxAgentStores)...)
		writeDeny = append(writeDeny, homePaths(c.Home, linuxAgentStores)...)
	}
	readDeny, writeDeny = withTargets(readDeny), withTargets(writeDeny)

	r.grant("/", llReadDir, true)
	r.complement("/", readDeny, llReadFile, llReadFile)
	sshDir := filepath.Join(c.Home, ".ssh")
	for _, p := range c.SSHReadable {
		if within(p, sshDir) && filepath.Clean(p) != sshDir {
			if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
				r.grant(p, llReadFile, false)
			}
		}
	}

	if p.Tainted() {
		roots := append(append([]string{c.TurnTmp}, c.Workspace...), c.ExtraWrite...)
		for _, w := range roots {
			if w != "" {
				r.complement(w, writeDeny, llWrite, llWriteFile|llTruncate)
			}
		}
		for _, d := range linuxDeviceWrites {
			if fi, err := os.Stat(d); err == nil {
				r.grant(d, llWrite, fi.IsDir())
			}
		}
		for _, f := range c.HarnessFiles {
			if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
				r.grant(f, llWriteFile|llTruncate, false)
			}
		}
	} else {
		r.complement("/", writeDeny, llWrite, llWriteFile|llTruncate)
	}

	j := LinuxJail{ABI: abi, Handled: supported, Rules: r.list()}
	switch {
	case p.Tainted():
		j.Sockets = SocketsAll
	case !g.Agent || !g.Docker:
		j.Sockets = SocketsUnix
	}
	return j, nil
}

func homePaths(home string, ms []match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if m.kind == "regex" {
			continue
		}
		if m.abs {
			out = append(out, m.path)
			continue
		}
		out = append(out, filepath.Join(home, m.path))
	}
	return out
}

// withTargets adds where each denied path resolves to: a ~/.aws that links to
// another disk must be denied there too, since the complement never follows
// a link.
func withTargets(paths []string) []string {
	out := append([]string{}, paths...)
	for _, p := range paths {
		if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
			out = append(out, r)
		}
	}
	return out
}

type rules struct {
	supported uint64
	byPath    map[string]LandlockRule
}

func newRules(supported uint64) *rules {
	return &rules{supported: supported, byPath: map[string]LandlockRule{}}
}

func (r *rules) grant(path string, access uint64, dir bool) {
	access &= r.supported
	if !dir {
		access &= llFileRights
	}
	if access == 0 {
		return
	}
	cur := r.byPath[path]
	r.byPath[path] = LandlockRule{Path: path, Access: cur.Access | access, Dir: dir}
}

func (r *rules) list() []LandlockRule {
	out := make([]LandlockRule, 0, len(r.byPath))
	for _, rule := range r.byPath {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// complement grants access on root's hierarchy except beneath any of deny.
// Symlinks get no rule: the kernel checks the path they resolve to, which has
// rules of its own.
func (r *rules) complement(root string, deny []string, access, fileAccess uint64) {
	root = filepath.Clean(root)
	var inside []string
	for _, d := range deny {
		if within(root, d) {
			return
		}
		if within(d, root) {
			inside = append(inside, d)
		}
	}
	fi, err := os.Lstat(root)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return
	}
	if !fi.IsDir() {
		r.grant(root, fileAccess, false)
		return
	}
	if len(inside) == 0 {
		r.grant(root, access, true)
		return
	}
	f, err := os.Open(root)
	if err != nil {
		return
	}
	entries, _ := f.ReadDir(maxDirEntries)
	f.Close()
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		switch t := e.Type(); {
		case t&os.ModeSymlink != 0:
		case t.IsDir():
			r.complement(p, inside, access, fileAccess)
		default:
			if !deniedPath(p, inside) {
				r.grant(p, fileAccess, false)
			}
		}
	}
}

func deniedPath(p string, deny []string) bool {
	for _, d := range deny {
		if within(p, d) {
			return true
		}
	}
	return false
}
