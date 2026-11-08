package shield

import (
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

// LinuxNamespaces says whether golem-exec can make each command's namespace
// here.
func LinuxNamespaces() Namespaces {
	if UserNSRestricted() && os.Geteuid() != 0 {
		installed, current := AppArmorCopy()
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

// AppArmorInstalled is golem-exec's profile with the root-owned copy it
// names.
func AppArmorInstalled() bool {
	_, err := os.Stat(AppArmorProfile)
	return err == nil && RootOwned(AppArmorStage)
}

// AppArmorCopy says whether the profile is installed, and whether its copy
// speaks this build's setup protocol: an older one refuses, and commands get
// no namespace until root installs the profile again.
func AppArmorCopy() (installed, current bool) {
	if !AppArmorInstalled() {
		return false, false
	}
	cmd := exec.Command(AppArmorStage, AppArmorProtocolQuery)
	cmd.Args[0] = AppArmorLauncherRole
	out, err := cmd.Output()
	return true, err == nil && strings.TrimSpace(string(out)) == NamespaceSetupProtocol
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
