package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
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
	sum := sha256.Sum256([]byte("golem-shield"))
	s := "S-1-9-1"
	for i := 0; i < 4; i++ {
		s += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[i*4:])), 10)
	}
	return windows.StringToSid(s)
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
	if j.Refuse {
		fmt.Fprintln(s.stderr, "golem-exec: this session is locked down, and on Windows a locked-down session can't run shell commands")
		rec.ExitCode = 126
		return true
	}
	sid, err := shieldSID()
	if err != nil {
		return false
	}
	if err := applyDenies(j, sid); err != nil {
		return false
	}
	tok, err := restrictedToken(sid, j.DropGroups)
	if err != nil {
		return false
	}
	defer tok.Close()
	cmd := exec.Command(argv[0])
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), CmdLine: commandLine(argv)}
	rec.ExitCode = s.start(cmd, env, nil)
	return true
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
// doesn't, since the user can't usually write one they don't own either.
func applyDenies(j shield.WindowsJail, sid *windows.SID) error {
	for _, e := range j.Files {
		if err := ensureDeny(e.Path, windows.SE_FILE_OBJECT, sid, e.Deny, e.Inherit); err != nil && e.Deny&shield.WinDenyRead != 0 {
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
func restrictedToken(shieldSID *windows.SID, drop []string) (windows.Token, error) {
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
	restrict = append(restrict, windows.SIDAndAttributes{Sid: shieldSID})
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

func runJailStage([]string) int { return 126 }
