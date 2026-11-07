package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// Ubuntu (23.10 on) keeps unprivileged user namespaces from every program
// whose AppArmor profile doesn't allow them
// (kernel.apparmor_restrict_unprivileged_userns), so there the jail can't
// make its network namespace. `golem-exec apparmor install` puts a copy of
// golem-exec where only root can change it, with a profile that lets that
// copy make namespaces; the shim runs the copy as its launcher while the copy
// is the same build. The profile:
//   - names a root-owned file, since whatever runs the named file gets it;
//   - keeps the copy in it only to exec itself, and stacks everything the
//     stage execs with golem-exec-command, which denies every capability: the
//     command can make a namespace, as anyone can under the restriction, but
//     hold no capability in it. Stacking, not unconfined, because the stage
//     sets no_new_privs, which forbids any other transition (as with
//     Ubuntu's own bubblewrap profile);
//   - lets golem-exec's processes trace and read only each other, so the
//     command can't read into the user's other processes. AppArmor never
//     stops an unconfined tracer, so the launcher makes itself undumpable
//     once its child is out; another process of the user's can still join a
//     running command's namespace, as with any program a profile lets make
//     one (docs/design-shield-workspace-and-egress.md, Ubuntu).
const (
	appArmorProfile = shield.AppArmorProfile
	appArmorStage   = shield.AppArmorStage
)

var appArmorParsers = []string{"/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"}

var errAppArmorNotNeeded = errors.New("this kernel doesn't restrict user namespaces")

func appArmorProfileText(stage string) string {
	return `# Written by golem-exec apparmor install; removed by golem-exec apparmor remove.
# Lets golem-exec's jail make a user and network namespace for a shell command
# whose network is held to its allowed hosts.
abi <abi/4.0>,
include <tunables/global>

profile golem-exec ` + stage + ` flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
  allow ptrace peer=golem-exec*,

  allow ` + stage + ` ix,
  allow px /** -> golem-exec//&golem-exec-command,

  include if exists <local/golem-exec>
}

profile golem-exec-command flags=(attach_disconnected,mediate_deleted) {
  allow file rwlkmix /{**,},
  allow network,
  allow unix,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
  allow ptrace peer=golem-exec*,
  audit deny capability,

  include if exists <local/golem-exec-command>
}
`
}

func appArmorParser() string {
	for _, p := range appArmorParsers {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func changeAppArmor(install bool, self string) error {
	if os.Geteuid() != 0 {
		return errors.New("run it as root (sudo)")
	}
	parser := appArmorParser()
	if !install {
		if _, err := os.Stat(appArmorProfile); err == nil && parser != "" {
			_ = exec.Command(parser, "-R", appArmorProfile).Run()
		}
		for _, p := range []string{appArmorProfile, appArmorStage, filepath.Dir(appArmorStage)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	if !shield.UserNSRestrictable() {
		return errAppArmorNotNeeded
	}
	if parser == "" {
		return errors.New("apparmor_parser isn't installed")
	}
	dir := filepath.Dir(appArmorStage)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	if err := copyExecutable(self, appArmorStage); err != nil {
		return err
	}
	if err := writeFileAtomic(appArmorProfile, []byte(appArmorProfileText(appArmorStage)), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command(parser, "-r", appArmorProfile).CombinedOutput(); err != nil {
		return fmt.Errorf("apparmor_parser: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func copyExecutable(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := to + ".new"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	if err == nil {
		err = dst.Chmod(0o755)
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, to)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// profiledLauncher is the copy to start the namespaced stage from, or "" to
// make the namespace from the shim itself.
func profiledLauncher() string {
	if !shield.UserNSRestricted() {
		return ""
	}
	if _, current := shield.AppArmorCopy("/proc/self/exe"); !current {
		return ""
	}
	return appArmorStage
}

// runJailLauncher is the profiled copy's one job: start the jail stage in a
// new user, network and mount namespace, which AppArmor lets only this file
// make, and wait for it. If it can't, nothing ran, and it tells the shim so.
func runJailLauncher(args []string) int {
	spec, ctl := os.NewFile(jailSpecFD, "jail-spec"), os.NewFile(stageCtlFD, "stage-ctl")
	if len(args) == 0 || (args[0] != launcherNet && args[0] != launcherNoNet) {
		_, _ = ctl.Write([]byte{ctlRetry})
		return stageRetryExit
	}
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = append([]string{jailStage}, args[1:]...)
	cmd.ExtraFiles = []*os.File{spec, ctl}
	cmd.SysProcAttr = namespaceAttr(args[0] == launcherNet)
	l := &shim{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	code, err := l.tryStart(cmd, os.Environ(), func() {
		spec.Close()
		ctl.Close()
		_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	})
	if err != nil {
		_, _ = ctl.Write([]byte{ctlRetry})
		return stageRetryExit
	}
	return code
}
