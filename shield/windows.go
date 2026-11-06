package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Access rights a WindowsACE denies, as winnt.h numbers them. On a directory
// the first two are "add file" and "add subdirectory".
const (
	winReadData        uint32 = 0x1
	winWriteData       uint32 = 0x2
	winAppendData      uint32 = 0x4
	winReadEA          uint32 = 0x8
	winWriteEA         uint32 = 0x10
	winExecute         uint32 = 0x20
	winDeleteChild     uint32 = 0x40
	winWriteAttributes uint32 = 0x100
	winDelete          uint32 = 0x10000
	winWriteDAC        uint32 = 0x40000
	winWriteOwner      uint32 = 0x80000

	keySetValue     uint32 = 0x2
	keyCreateSubKey uint32 = 0x4
)

const (
	// WinDenyRead keeps attributes and the security descriptor readable, so
	// a listing still shows the file.
	WinDenyRead = winReadData | winReadEA | winExecute
	// WinDenyWrite includes the right to change the ACL or the owner, so a
	// jailed command can't take the denial off its own file.
	WinDenyWrite = winWriteData | winAppendData | winWriteEA | winWriteAttributes |
		winDelete | winDeleteChild | winWriteDAC | winWriteOwner
	// winDenyNewFile on a directory refuses new files and removing or
	// renaming existing entries, but leaves the entries themselves alone and
	// lets new folders be made. winDenyCreate refuses new folders too.
	winDenyNewFile = winWriteData | winDeleteChild | winDelete | winWriteDAC | winWriteOwner
	winDenyCreate  = winDenyNewFile | winAppendData
	winDenyKey     = keySetValue | keyCreateSubKey | winDelete | winWriteDAC | winWriteOwner
	// winDenyEntry keeps a folder where it is: it can't be removed or
	// renamed, nor anything in it through it. What is in it stays writable.
	winDenyEntry = winDelete | winDeleteChild | winWriteDAC | winWriteOwner
)

// WindowsACE is a deny entry for the shield's SID that the shim keeps on one
// of the user's own files, directories or registry keys. The shell runs with
// a restricted token whose restricting SIDs carry that SID, so the entry
// binds the jailed command and nothing else the user runs. Each entry also
// carries an allow for OWNER RIGHTS, which takes away the owner's implicit
// right to rewrite the ACL; the owner keeps full control through it.
type WindowsACE struct {
	Path    string `json:"path"`
	Deny    uint32 `json:"deny"`
	Inherit bool   `json:"inherit,omitempty"`
	// Optional: a command still runs when this entry can't be put in place.
	// An app's own store can be held open by the app while it runs, and
	// failing every command for that would leave the jail switched off.
	Optional bool `json:"optional,omitempty"`
}

// WindowsJail is the compiled Windows policy.
type WindowsJail struct {
	Files    []WindowsACE `json:"files"`
	Registry []WindowsACE `json:"registry"`
	// DropGroups are left out of the restricting SIDs, so whatever only they
	// are allowed (Docker Desktop's pipe, for docker-users) is refused.
	DropGroups []string `json:"drop_groups,omitempty"`
	// Refuse: Windows can take the network from a process only inside an
	// AppContainer, which can't read the user's toolchains, so a tainted
	// session's commands don't run at all.
	Refuse bool `json:"refuse,omitempty"`
	// LowIntegrity runs the shell at low integrity, and LowRoots are the
	// directories the shim labels low so it may still write them. Windows
	// refuses a low-integrity process every write to an object labelled
	// higher, whatever its ACL, and leaves reads alone: the allow list that
	// deny entries can't express.
	LowIntegrity bool     `json:"low_integrity,omitempty"`
	LowRoots     []string `json:"low_roots,omitempty"`
	// Hold are folders the shim makes before the command runs, so that the
	// entries on them can keep the agents' project files from being created.
	Hold []string `json:"hold,omitempty"`
	// Firewalled puts ShieldNetSIDString in the shell's restricting SIDs, so
	// the shield's firewall filters, where installed, hold its network to the
	// proxy.
	Firewalled bool `json:"firewalled,omitempty"`
}

func (j WindowsJail) Hash() string {
	raw, _ := json.Marshal(j)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var windowsSecretStores = []match{
	lit("_netrc"),
	sub("AppData/Roaming/gnupg/private-keys-v1.d"),
}

var windowsProtectedWrites = []match{
	sub("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
	sub("Documents/WindowsPowerShell"),
	sub("Documents/PowerShell"),
	lit("AppData/Roaming/Code/User/settings.json"),
	lit("AppData/Roaming/Code - Insiders/User/settings.json"),
}

var macOnly = map[string]bool{"Library/LaunchAgents": true, "Library/Keychains": true}

var windowsCloudStores = []match{
	sub("AppData/Roaming/gcloud"),
}

var windowsAgentStores = []match{
	lit("AppData/Roaming/GitHub CLI/hosts.yml"),
}

// windowsPersistenceKeys are HKCU keys whose values run or shape every later
// session: Run and RunOnce, cmd.exe's AutoRun, and the user's environment.
var windowsPersistenceKeys = []string{
	`CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`,
	`CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`CURRENT_USER\Software\Microsoft\Command Processor`,
	`CURRENT_USER\Environment`,
}

// CompileWindows renders p as the deny entries the shim keeps in place and
// the groups the restricted token leaves out.
//
// Nothing can be created or removed directly in the home directory, so a
// startup file that doesn't exist yet can't be created there; its existing
// folders stay writable. A protected path that doesn't exist makes its
// nearest existing parent refuse new files, and new folders too when what's
// missing is a folder. ~/.ssh refuses every write, and each file in it that
// isn't on c.SSHReadable (a private key, judged by content) refuses reads.
func CompileWindows(p Policy, c Context) (WindowsJail, error) {
	if err := c.validate(); err != nil {
		return WindowsJail{}, err
	}
	if p.Tainted() {
		return WindowsJail{Refuse: true}, nil
	}
	g := p.Effective()
	acl := map[string]WindowsACE{}
	optional := false
	add := func(path string, deny uint32, inherit bool) {
		e, seen := acl[path]
		e.Path, e.Deny, e.Inherit = path, e.Deny|deny, e.Inherit || inherit
		e.Optional = optional && (!seen || e.Optional)
		acl[path] = e
	}
	// A credential store that isn't there has nothing to read, so only a
	// missing protected path guards its parent against being created.
	place := func(ms []match, deny uint32) {
		for _, m := range ms {
			if m.kind == "regex" || macOnly[m.path] {
				continue
			}
			path := filepath.FromSlash(filepath.Join(c.Home, m.path))
			fi, err := os.Lstat(path)
			switch {
			case err == nil && fi.Mode()&os.ModeSymlink != 0:
				if r, err := filepath.EvalSymlinks(path); err == nil {
					if rfi, err := os.Stat(r); err == nil {
						add(r, deny, rfi.IsDir())
					}
				}
			case err == nil:
				add(path, deny, fi.IsDir())
			case deny&WinDenyRead != 0:
			default:
				parent := existingParent(path, c.Home)
				switch {
				case parent == "":
				case m.kind == "literal" && parent == filepath.Dir(path):
					add(parent, winDenyNewFile, false)
				default:
					add(parent, winDenyCreate, false)
				}
			}
		}
	}

	stores := append(append([]match{}, secretStores...), windowsSecretStores...)
	var ssh []match
	for _, m := range stores {
		if m.path != ".ssh" {
			ssh = append(ssh, m)
		}
	}
	place(ssh, WinDenyRead|WinDenyWrite)
	optional = true
	place(windowsAppStores, WinDenyRead|WinDenyWrite)
	optional = false
	place(append(append([]match{}, protectedWrites...), windowsProtectedWrites...), WinDenyWrite)
	place([]match{sub(".ssh")}, WinDenyWrite)
	for _, k := range sshKeys(c.Home, c.SSHReadable) {
		add(k, WinDenyRead|WinDenyWrite, false)
	}
	if !g.Cloud {
		place(append(append([]match{}, cloudStores...), windowsCloudStores...), WinDenyRead|WinDenyWrite)
	}
	if !g.Agent {
		place(append(append([]match{}, linuxAgentStores[:1]...), windowsAgentStores...), WinDenyRead|WinDenyWrite)
	}
	add(c.Home, winDenyCreate, false)
	hold := projectDenies(c, add)

	j := WindowsJail{Hold: hold}
	for _, e := range acl {
		j.Files = append(j.Files, e)
	}
	sort.Slice(j.Files, func(a, b int) bool { return j.Files[a].Path < j.Files[b].Path })
	for _, k := range windowsPersistenceKeys {
		j.Registry = append(j.Registry, WindowsACE{Path: k, Deny: winDenyKey})
	}
	if !g.Docker {
		j.DropGroups = []string{"docker-users"}
	}
	j.Firewalled = p.Proxied()
	if p.ConfinedWrites() {
		j.LowIntegrity = true
		for _, r := range writeRoots(p, c, "windows") {
			if fi, err := os.Lstat(r); err == nil && fi.IsDir() {
				j.LowRoots = append(j.LowRoots, r)
			}
		}
	}
	return j, nil
}

// projectDenies keeps the agents' project files (ProjectFilePaths) from the
// command. An entry on a file or folder can't stop it being removed or
// renamed through its parent, which FILE_DELETE_CHILD there allows whatever
// the entry says, so each parent refuses that too; the files beside them are
// still removed through their own DELETE. A missing one makes its folder
// refuse new files, or new folders, except at a root (the work tree's, or a
// folder on the way to the working directory), where that would stop
// ordinary work. The work tree's .claude, which Claude Code, Cursor, Copilot
// CLI, VS Code's agent and Devin all read, is made when missing so that it
// can be held; the other folders missing at a root are not held.
func projectDenies(c Context, add func(string, uint32, bool)) []string {
	var hold []string
	held := map[string]bool{}
	for _, ws := range c.Workspace {
		ws = filepath.Clean(ws)
		claude := filepath.Join(ws, ".claude")
		if _, err := os.Lstat(filepath.Join(ws, ".git")); err != nil {
			continue
		}
		if _, err := os.Lstat(claude); errors.Is(err, fs.ErrNotExist) && !held[claude] {
			held[claude] = true
			hold = append(hold, claude)
		}
	}
	roots := map[string]bool{}
	for _, r := range projectRoots(c) {
		roots[r] = true
	}
	present := func(p string) bool {
		_, err := os.Lstat(p)
		return err == nil || held[p]
	}
	guard := func(p string, deny uint32, inherit bool, missing uint32) {
		parent := filepath.Dir(p)
		switch {
		case present(p):
			add(p, deny, inherit)
			add(parent, winDeleteChild|winWriteDAC|winWriteOwner, false)
		case roots[parent] || !present(parent):
		default:
			add(parent, missing|winWriteDAC|winWriteOwner, false)
		}
	}
	pp := ProjectFilePaths(c)
	for _, f := range pp.Files {
		guard(f, WinDenyWrite, false, winWriteData)
	}
	for _, t := range pp.Trees {
		guard(t, WinDenyWrite, true, winAppendData)
	}
	for _, d := range pp.Folders {
		guard(d, winDenyEntry, false, winAppendData)
	}
	return hold
}

// sshKeys lists the files in ~/.ssh that SSHReadable left out.
func sshKeys(home string, readable []string) []string {
	ok := map[string]bool{}
	for _, r := range readable {
		ok[filepath.Clean(r)] = true
	}
	root := filepath.Join(home, ".ssh")
	var keys []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() && !ok[filepath.Clean(p)] {
			keys = append(keys, p)
		}
		return nil
	})
	return keys
}

func existingParent(path, home string) string {
	for d := filepath.Dir(path); within(d, home); d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
		if d == home {
			break
		}
	}
	return ""
}
