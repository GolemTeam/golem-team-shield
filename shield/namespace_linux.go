package shield

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const userNSRestrict = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

// UserNSRestricted is Ubuntu's (23.10 on) kernel.apparmor_restrict_unprivileged_userns.
func UserNSRestricted() bool {
	b, err := os.ReadFile(userNSRestrict)
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// UserNSRestrictable is whether this kernel has that switch at all.
func UserNSRestrictable() bool {
	_, err := os.Stat(userNSRestrict)
	return err == nil
}

// LinuxNamespaces says whether golem-exec, the build at golemExec, can make
// each command's namespace here.
func LinuxNamespaces(golemExec string) Namespaces {
	if UserNSRestricted() && os.Geteuid() != 0 {
		installed, current := AppArmorCopy(golemExec)
		switch {
		case current:
			return NamespacesProfiled
		case installed:
			return NamespacesStaleProfile
		default:
			return NamespacesNoProfile
		}
	}
	if !probeNamespace() {
		return NamespacesNone
	}
	return NamespacesOpen
}

// AppArmorCopy says whether golem-exec's profile is installed, with the
// root-owned copy it names, and whether that copy is the build at golemExec.
func AppArmorCopy(golemExec string) (installed, current bool) {
	if _, err := os.Stat(AppArmorProfile); err != nil || !RootOwned(AppArmorStage) {
		return false, false
	}
	return true, SameBuild(golemExec, AppArmorStage)
}

// probeNamespace starts true in a user and mount namespace, as the jail
// would. A container's seccomp profile, or user.max_user_namespaces=0,
// refuses it.
func probeNamespace() bool {
	bin := ""
	for _, p := range []string{"/bin/true", "/usr/bin/true"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		return false
	}
	uid, gid := os.Getuid(), os.Getgid()
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
	}
	return cmd.Run() == nil
}

// RootOwned is a regular file that root owns and no one else may write, in a
// folder the same holds for.
func RootOwned(path string) bool {
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&0o022 != 0 || (p == path && !fi.Mode().IsRegular()) {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
	}
	return true
}

// SameBuild compares Go build IDs, which survive stripping: the jail stage
// reads its spec as JSON, and an older build would drop a field it doesn't
// know without a word.
func SameBuild(a, b string) bool {
	ia, err := goBuildID(a)
	if err != nil {
		return false
	}
	ib, err := goBuildID(b)
	return err == nil && bytes.Equal(ia, ib)
}

func goBuildID(path string) ([]byte, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sec := f.Section(".note.go.buildid")
	if sec == nil {
		return nil, errors.New("no Go build ID")
	}
	b, err := sec.Data()
	if err != nil || len(b) == 0 {
		return nil, errors.New("no Go build ID")
	}
	return b, nil
}
