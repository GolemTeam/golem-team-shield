package main

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// The jail's privileged half: what takes capabilities in the command's own
// namespace. Where the kernel lets anyone make one, the stage does this
// itself. On Ubuntu the root-owned copy that golem-exec's AppArmor profile
// names does it, then execs the user's own golem-exec as the stage, holding
// nothing, so an update of golem-exec leaves the copy working. The copy is
// replaced only when root installs the profile again: change what this file
// does, or fix it, and bump shield.NamespaceSetupProtocol, so an older copy
// refuses and the doctor asks for that (TestSetupProtocolFollowsTheSetup).

// stageBinFD is the user's golem-exec, which the copy execs as the stage.
const stageBinFD = 5

// setupSpec is the part of the stage's spec the setup reads; it hands the
// stage the whole spec, unread, so an older copy drops nothing.
type setupSpec struct {
	Net    bool      `json:"net,omitempty"`
	Mounts mountPlan `json:"mounts,omitempty"`
}

type mountPlan struct {
	Binds []planBind `json:"binds,omitempty"`
}

type planBind struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"ro,omitempty"`
}

// prepareNamespace makes the namespace's mounts its own, binds the project
// files, enters the working directory again, and for an allowed-hosts network
// brings up loopback and hides the resolvers.
func prepareNamespace(spec setupSpec) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := applyMountPlan(spec.Mounts); err != nil {
		return err
	}
	// The working directory still points into the mounts as they were before
	// the binds, where a folder bound onto itself on the way down keeps the
	// original, writable copies of what is bound beneath it. Entering it
	// again by its path lands on the new ones.
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := unix.Chdir(wd); err != nil {
		return err
	}
	if !spec.Net {
		return nil
	}
	if err := loopbackUp(); err != nil {
		return err
	}
	hideResolvers()
	return nil
}

// runJailSetup is the copy in the namespace the launcher made: it sets the
// namespace up, drops what it held, and execs the user's golem-exec as the
// stage with the spec as it came. If it can't, nothing has run, and the shim
// runs the stage again without a namespace.
func runJailSetup(argv []string) int {
	runtime.LockOSThread()
	ctl := os.NewFile(stageCtlFD, "stage-ctl")
	retry := func() int {
		_, _ = ctl.Write([]byte{ctlRetry})
		return stageRetryExit
	}
	f := os.NewFile(jailSpecFD, "jail-spec")
	if f == nil || ctl == nil {
		return retry()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16<<20))
	f.Close()
	var spec setupSpec
	if err != nil || json.Unmarshal(raw, &spec) != nil || prepareNamespace(spec) != nil {
		return retry()
	}
	mfd, err := unix.MemfdCreate("jail-spec", 0)
	if err != nil {
		return retry()
	}
	if _, err := unix.Write(mfd, raw); err != nil {
		return retry()
	}
	if _, err := unix.Seek(mfd, 0, io.SeekStart); err != nil {
		return retry()
	}
	if mfd != jailSpecFD {
		if unix.Dup3(mfd, jailSpecFD, 0) != nil {
			return retry()
		}
		unix.Close(mfd)
	}
	if allThreads(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != nil {
		return retry()
	}
	unix.CloseOnExec(stageBinFD)
	_ = syscall.Exec("/proc/self/fd/5", append([]string{jailStagePrepared}, argv...), os.Environ())
	return retry()
}

func loopbackUp() error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr)
}

// resolverDirs hold the sockets through which a name is resolved outside the
// namespace: systemd-resolved's varlink socket, nscd, and the system bus,
// which resolved answers on too. An empty tmpfs over each keeps a command
// from sending what it read out as a DNS query.
var resolverDirs = []string{"/run/systemd/resolve", "/run/nscd", "/var/run/nscd", "/run/dbus"}

func hideResolvers() {
	for _, d := range resolverDirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			_ = unix.Mount("tmpfs", d, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0755")
		}
	}
}

// applyMountPlan binds each path onto itself, deepest first so a folder's
// recursive bind carries what was bound inside it, then makes the read-only
// ones read-only. A remount must keep the flags the original mount was
// locked with, or the kernel refuses it in a user namespace.
func applyMountPlan(plan mountPlan) error {
	for _, b := range plan.Binds {
		if err := unix.Mount(b.Path, b.Path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
	}
	for _, b := range plan.Binds {
		if !b.ReadOnly {
			continue
		}
		var st unix.Statfs_t
		if err := unix.Statfs(b.Path, &st); err != nil {
			return err
		}
		flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
		for _, f := range []struct{ st, ms uintptr }{
			{unix.ST_NOSUID, unix.MS_NOSUID}, {unix.ST_NODEV, unix.MS_NODEV}, {unix.ST_NOEXEC, unix.MS_NOEXEC},
			{unix.ST_NOATIME, unix.MS_NOATIME}, {unix.ST_NODIRATIME, unix.MS_NODIRATIME}, {unix.ST_RELATIME, unix.MS_RELATIME},
		} {
			if uintptr(st.Flags)&f.st != 0 {
				flags |= f.ms
			}
		}
		if err := unix.Mount("", b.Path, "", flags, ""); err != nil {
			return err
		}
	}
	return nil
}
