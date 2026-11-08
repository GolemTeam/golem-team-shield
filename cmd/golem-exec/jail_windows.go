package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/GolemTeam/golem-team-shield/shield"
)

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
	procSetFileSecurityW      = advapi32.NewProc("SetFileSecurityW")
)

const (
	disableMaxPrivilege = 0x1
	fileAllAccess       = 0x1F01FF
	keyAllAccess        = 0xF003F
)

func canJail() bool { return true }

// shieldSID is the SID the deny entries name. It is no account and no group:
// it exists only in the restricting SIDs of the shell's token, so nothing
// else the user runs ever matches it. It sits under the resource manager
// authority (S-1-9); CreateRestrictedToken refuses a capability SID
// (S-1-15-3) as a restricting SID.
func shieldSID() (*windows.SID, error) {
	return windows.StringToSid(shield.ShieldSIDString())
}

// jailed runs the shell with a restricted token: every access must pass the
// usual check and a second one against the token's restricting SIDs, which
// are the user's own enabled SIDs plus the shield's. The deny entries the shim
// keeps on credential stores and startup files name the shield's SID, so they
// fail the second check for the jailed command and its children (a child
// inherits the token), and for nothing else.
func (s *shim) jailed(rec *shield.RunRecord, p shield.Policy, tmp string, argv, env []string) bool {
	c := s.context(tmp, rec.RunTag)
	j, err := shield.CompileWindows(p, c)
	if err != nil {
		j, err = shield.CompileWindows(p, withoutWorkspace(c))
	}
	if err != nil {
		return false
	}
	rec.Jail = shield.JailToken
	rec.PolicyHash = j.Hash()
	if p.Proxied() {
		rec.Net = shield.NetAdvisory
		if on, err := shield.FirewallInstalled(); err == nil && on {
			rec.Net = shield.NetFirewall
		}
	}
	if j.Refuse {
		fmt.Fprintln(s.stderr, "golem-exec: this session is locked down, and on Windows a locked-down session can't run shell commands")
		rec.ExitCode = 126
		return true
	}
	sid, err := shieldSID()
	if err != nil {
		return false
	}
	for _, d := range j.Hold {
		_ = os.Mkdir(d, 0o755)
	}
	if err := applyDenies(j, sid); err != nil {
		return false
	}
	extra := []*windows.SID{sid}
	if j.Firewalled {
		net, err := windows.StringToSid(shield.ShieldNetSIDString())
		if err != nil {
			return false
		}
		extra = append(extra, net)
	}
	tok, err := restrictedToken(extra, j.DropGroups)
	if err != nil {
		return false
	}
	defer tok.Close()
	if j.LowIntegrity {
		for _, r := range j.LowRoots {
			_ = labelLow(r)
		}
		if err := lowerIntegrity(tok); err != nil {
			return false
		}
		rec.Writes = string(shield.WritesWorkspace)
	}
	cmd := exec.Command(argv[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), CmdLine: commandLine(argv)}
	rec.ExitCode = s.start(cmd, env, nil)
	return true
}

// lowLabel is a low mandatory label that every file and folder below
// inherits, with the default no-write-up policy.
const lowLabel = "S:(ML;OICI;NW;;;LW)"

const systemMandatoryLabelACEType = 0x11

// labelLow lets a low-integrity shell write path and everything below it. A
// directory already labelled low is left as it is, so the walk that relabels
// what is inside happens once. A root it can't label stays unwritable to the
// shell, which only makes the jail stricter.
func labelLow(path string) error {
	low, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		return err
	}
	if sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION); err == nil {
		if sacl, _, err := sd.SACL(); err == nil && sacl != nil && hasLabel(sacl, low) {
			return nil
		}
	}
	want, err := windows.SecurityDescriptorFromString(lowLabel)
	if err != nil {
		return err
	}
	sacl, _, err := want.SACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION, nil, nil, nil, sacl)
}

func hasLabel(acl *windows.ACL, sid *windows.SID) bool {
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != systemMandatoryLabelACEType {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) && ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0 {
			return true
		}
	}
	return false
}

// lowerIntegrity sets tok to low integrity. Lowering a token's own level
// needs no privilege, and everything the shell starts inherits it.
func lowerIntegrity(tok windows.Token) error {
	low, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		return err
	}
	tml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	return windows.SetTokenInformation(tok, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&tml)), tml.Size())
}

// commandLine passes on the string the agent gave the shim, unchanged: Git
// Bash parses its command line itself, and splitting and re-quoting it could
// change the command. Only the program name is swapped for the real shell.
func commandLine(argv []string) string {
	if slices.Equal(argv[1:], os.Args[1:]) {
		return syscall.EscapeArg(argv[0]) + skipArg0(windows.UTF16PtrToString(windows.GetCommandLine()))
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = syscall.EscapeArg(a)
	}
	return strings.Join(quoted, " ")
}

// skipArg0 drops the program name the way the C runtime reads it: up to the
// closing quote if it starts with one, else up to the first space or tab.
func skipArg0(cmdline string) string {
	if strings.HasPrefix(cmdline, `"`) {
		if i := strings.IndexByte(cmdline[1:], '"'); i >= 0 {
			return cmdline[i+2:]
		}
		return ""
	}
	if i := strings.IndexAny(cmdline, " \t"); i >= 0 {
		return cmdline[i:]
	}
	return ""
}

// applyDenies puts each deny entry in place if it isn't already. A credential
// store it can't protect stops the command; a startup file it can't protect
// doesn't, since the user can't usually write one they don't own either, and
// nor does an app's store the app holds open (WindowsACE.Optional).
func applyDenies(j shield.WindowsJail, sid *windows.SID) error {
	for _, e := range j.Files {
		if err := ensureDeny(e.Path, windows.SE_FILE_OBJECT, sid, e.Deny, e.Inherit); err != nil && e.Deny&shield.WinDenyRead != 0 && !e.Optional {
			return err
		}
	}
	for _, e := range j.Registry {
		if k, _, err := registry.CreateKey(registry.CURRENT_USER, strings.TrimPrefix(e.Path, `CURRENT_USER\`), registry.QUERY_VALUE); err == nil {
			k.Close()
		}
		_ = ensureDeny(e.Path, windows.SE_REGISTRY_KEY, sid, e.Deny, false)
	}
	return nil
}

func ensureDeny(path string, kind windows.SE_OBJECT_TYPE, sid *windows.SID, deny uint32, inherit bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, kind, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return err
	}
	if hasACE(dacl, windows.ACCESS_DENIED_ACE_TYPE, sid, deny, inherit) && hasACE(dacl, windows.ACCESS_ALLOWED_ACE_TYPE, ownerRights, 0, false) {
		return nil
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if inherit {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	all := uint32(fileAllAccess)
	if kind == windows.SE_REGISTRY_KEY {
		all = keyAllAccess
	}
	trustee := func(s *windows.SID) windows.TRUSTEE {
		return windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(s)}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{AccessPermissions: windows.ACCESS_MASK(deny), AccessMode: windows.DENY_ACCESS, Inheritance: inheritance, Trustee: trustee(sid)},
		{AccessPermissions: windows.ACCESS_MASK(all), AccessMode: windows.GRANT_ACCESS, Inheritance: inheritance, Trustee: trustee(ownerRights)},
	}, dacl)
	if err != nil {
		return err
	}
	if inherit || kind != windows.SE_FILE_OBJECT {
		return windows.SetNamedSecurityInfo(path, kind, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}
	return setFileDACL(path, sd, acl)
}

// setFileDACL writes acl on path alone. SetNamedSecurityInfo would walk every
// child to recompute what it inherits, which for the home directory is the
// whole profile; an entry that doesn't inherit changes nothing below.
func setFileDACL(path string, old *windows.SECURITY_DESCRIPTOR, acl *windows.ACL) error {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return err
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return err
	}
	if ctrl, _, err := old.Control(); err == nil {
		keep := windows.SECURITY_DESCRIPTOR_CONTROL(windows.SE_DACL_AUTO_INHERITED | windows.SE_DACL_PROTECTED)
		_ = sd.SetControl(keep, ctrl&keep)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, e := procSetFileSecurityW.Call(uintptr(unsafe.Pointer(p)), uintptr(windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd)))
	if r == 0 {
		return e
	}
	return nil
}

// hasACE reports whether dacl holds an explicit entry of aceType for sid
// covering mask, inheritable when inherit is set.
func hasACE(dacl *windows.ACL, aceType uint8, sid *windows.SID, mask uint32, inherit bool) bool {
	if dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil {
			return false
		}
		if ace.Header.AceType != aceType || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			continue
		}
		if inherit && ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			continue
		}
		if uint32(ace.Mask)&mask != mask {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return true
		}
	}
	return false
}

// restrictedToken is this process's token with every privilege but bypass
// traverse taken away (an elevated shell's backup privilege would read past
// any ACL) and the restricting SIDs set: the user, each enabled group but
// those in drop, and the shield. Administrators stays in for an elevated
// shell: without it Git Bash can't create its own pipes, because an elevated
// token's default owner is that group.
func restrictedToken(shieldSIDs []*windows.SID, drop []string) (windows.Token, error) {
	var proc windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &proc); err != nil {
		return 0, err
	}
	defer proc.Close()
	user, err := proc.GetTokenUser()
	if err != nil {
		return 0, err
	}
	groups, err := proc.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	var dropped []*windows.SID
	for _, name := range drop {
		if sid, _, _, err := windows.LookupSID("", name); err == nil {
			dropped = append(dropped, sid)
		}
	}
	restrict := []windows.SIDAndAttributes{{Sid: user.User.Sid}}
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_ENABLED == 0 || g.Attributes&(windows.SE_GROUP_USE_FOR_DENY_ONLY|windows.SE_GROUP_INTEGRITY) != 0 {
			continue
		}
		if slices.ContainsFunc(dropped, g.Sid.Equals) {
			continue
		}
		restrict = append(restrict, windows.SIDAndAttributes{Sid: g.Sid})
	}
	for _, s := range shieldSIDs {
		restrict = append(restrict, windows.SIDAndAttributes{Sid: s})
	}
	var out windows.Token
	r, _, e := procCreateRestrictedToken.Call(uintptr(proc), disableMaxPrivilege, 0, 0, 0, 0,
		uintptr(len(restrict)), uintptr(unsafe.Pointer(&restrict[0])), uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		if e == nil {
			e = errors.New("CreateRestrictedToken failed")
		}
		return 0, e
	}
	return out, nil
}

func runJailStage([]string, bool) int { return 126 }
