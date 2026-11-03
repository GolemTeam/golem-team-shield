package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/GolemTeam/golem-team-shield/shield"
)

const jailSpecFD = 3

func landlockABI() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(v)
}

func canJail() bool { return landlockABI() >= shield.LandlockMinABI }

// jailed runs the shim again as its jail stage, which applies the rules to
// itself and execs the shell. Landlock and seccomp are inherited across exec
// and fork and can't be lifted, so everything the command starts is held. The
// shim stays outside, the shell's parent, to report the run.
//
// An allowlisted network first tries a stage in its own user and network
// namespace, where loopback is the only address and only the proxy listens on
// it; where the kernel won't make one, the stage runs again without and holds
// the network with Landlock's port rule (shield.LinuxJail.NetFallback).
func (s *shim) jailed(rec *shield.RunRecord, p shield.Policy, tmp string, argv, env []string) bool {
	abi := landlockABI()
	if abi < shield.LandlockMinABI {
		rec.Jail = shield.JailNone
		if p.Proxied() {
			rec.Net = shield.NetAdvisory
		}
		rec.ExitCode = s.child(argv, env)
		return true
	}
	c := s.context(tmp, rec.RunTag)
	if p.Tainted() || p.ConfinedWrites() {
		c.HarnessFiles = harnessFiles(c.HarnessTmp, argv[1:])
	}
	j, err := shield.CompileLandlock(p, c, abi)
	if err != nil {
		j, err = shield.CompileLandlock(p, withoutWorkspace(c), abi)
	}
	if err != nil {
		return false
	}
	rec.Jail = shield.JailLandlock
	rec.PolicyHash = j.Hash()
	if p.ConfinedWrites() {
		rec.Writes = string(shield.WritesWorkspace)
	}
	if j.Proxy == 0 {
		code, _, err := s.stage(stageSpec{Jail: j}, argv, env)
		rec.ExitCode = code
		return err == nil
	}
	code, mode, err := 0, shield.NetMode(""), errNoNamespace
	if !s.noNamespace {
		code, mode, err = s.stage(stageSpec{Jail: j, Namespace: true}, argv, env)
	}
	if errors.Is(err, errNoNamespace) {
		code, mode, err = s.stage(stageSpec{Jail: j}, argv, env)
	}
	rec.ExitCode, rec.Net = code, mode
	return err == nil
}

// stageSpec is what the shim tells its jail stage on fd 3.
type stageSpec struct {
	Jail      shield.LinuxJail `json:"jail"`
	Namespace bool             `json:"namespace,omitempty"`
}

const (
	stageCtlFD = 4
	// The stage's one word on fd 4 for an allowlisted network.
	ctlNamespace    = 'n' // in a namespace; the proxy's listener comes with it
	ctlLandlockPort = 'p'
	ctlNoNetwork    = 'x'
	ctlRetry        = 'r' // no namespace after all; nothing ran
)

var errNoNamespace = errors.New("no network namespace")

// stage runs the jail stage once and reports how it held the network.
func (s *shim) stage(spec stageSpec, argv, env []string) (int, shield.NetMode, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return 0, "", err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return 0, "", err
	}
	defer r.Close()
	defer w.Close()
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = append([]string{jailStage}, argv...)
	cmd.ExtraFiles = []*os.File{r}
	var ctl *os.File
	if spec.Jail.Proxy > 0 {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return 0, "", err
		}
		ctl = os.NewFile(uintptr(fds[0]), "stage-ctl")
		child := os.NewFile(uintptr(fds[1]), "stage-ctl-child")
		defer ctl.Close()
		defer child.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, child)
	}
	if spec.Namespace {
		uid, gid := os.Getuid(), os.Getgid()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
			// The stage runs as the user, not root, in its namespace, so it
			// keeps only what it needs to bring up loopback and hide the
			// resolvers across its exec, and clears them before the shell's.
			AmbientCaps: []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN},
		}
	}
	modes := make(chan byte, 1)
	code, err := s.tryStart(cmd, env, func() {
		for _, f := range cmd.ExtraFiles {
			f.Close()
		}
		go func() {
			_, _ = w.Write(raw)
			w.Close()
		}()
		if ctl != nil {
			go func() { modes <- s.readStageCtl(ctl) }()
		}
	})
	if err != nil {
		if spec.Namespace {
			return 0, "", errNoNamespace
		}
		fmt.Fprintln(s.stderr, "golem-exec: can't start the shell")
		return 127, "", nil
	}
	if ctl == nil {
		return code, "", nil
	}
	var mode byte
	select {
	case mode = <-modes:
	case <-time.After(time.Second):
	}
	switch mode {
	case ctlNamespace:
		return code, shield.NetNamespace, nil
	case ctlLandlockPort:
		return code, shield.NetLandlockPort, nil
	case ctlNoNetwork:
		return code, shield.NetNone, nil
	case ctlRetry:
		if spec.Namespace {
			return 0, "", errNoNamespace
		}
	}
	return code, "", nil
}

// readStageCtl reads the stage's one message, and serves the proxy on the
// listener a namespaced stage sends with it.
func (s *shim) readStageCtl(ctl *os.File) byte {
	buf, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(ctl.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil || n != 1 {
		return 0
	}
	if buf[0] != ctlNamespace {
		return buf[0]
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return 0
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return 0
	}
	f := os.NewFile(uintptr(fds[0]), "namespace-proxy")
	l, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return 0
	}
	s.proxy.Serve(l)
	return ctlNamespace
}

var harnessFileRE = regexp.MustCompile(`[^\s'"<>|;&]*/claude-[A-Za-z0-9-]+-cwd`)

// harnessFiles creates the files the harness has the shell write its cwd to,
// so a tainted jail, which can only grant paths that exist, can let the shell
// write them. Only names in the harness's own temp directory count.
func harnessFiles(dir string, args []string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	for _, a := range args {
		for _, m := range harnessFileRE.FindAllString(a, 8) {
			if realPath(filepath.Dir(m)) != dir {
				continue
			}
			p := filepath.Join(dir, filepath.Base(m))
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
			if err != nil {
				continue
			}
			f.Close()
			out = append(out, p)
		}
	}
	return out
}

// runJailStage is the shim's second process: it reads the compiled rules,
// applies them to itself and execs argv. It returns only when that failed,
// and then the command doesn't run: never unjailed.
func runJailStage(argv []string) int {
	runtime.LockOSThread()
	err := applyJailStage(argv)
	fmt.Fprintf(os.Stderr, "golem-exec: can't apply the Golem shield (%T); not running the command\n", err)
	return 126
}

func applyJailStage(argv []string) error {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return errors.New("no shell")
	}
	f := os.NewFile(jailSpecFD, "jail-spec")
	if f == nil {
		return errors.New("no spec")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16<<20))
	f.Close()
	if err != nil {
		return err
	}
	var spec stageSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return err
	}
	j := spec.Jail
	inet, netPort := shield.InetOpen, 0
	if j.Proxy > 0 {
		if inet, netPort, err = holdNetwork(spec); err != nil {
			return err
		}
	}
	if err := allThreads(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := applyLandlock(j, netPort); err != nil {
		return err
	}
	if j.Sockets != shield.SocketsOpen || inet != shield.InetOpen {
		if err := applySeccomp(j.Sockets, inet); err != nil {
			return err
		}
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}

// holdNetwork confines an allowlisted command to the proxy and tells the shim
// how: in a namespace, the proxy's listener goes to the shim; outside one,
// Landlock allows TCP to the proxy's port and nothing else. Only plain TCP
// sockets open either way, so no other family (vsock reaches a VM's host
// from any namespace) is a way out.
func holdNetwork(spec stageSpec) (shield.InetDeny, int, error) {
	ctl := os.NewFile(stageCtlFD, "stage-ctl")
	if ctl == nil {
		return "", 0, errors.New("no control socket")
	}
	defer ctl.Close()
	if spec.Namespace {
		lfd, err := namespaceProxyListener(spec.Jail.Proxy)
		if err != nil {
			_, _ = ctl.Write([]byte{ctlRetry})
			os.Exit(stageRetryExit)
		}
		hideResolvers()
		err = unix.Sendmsg(int(ctl.Fd()), []byte{ctlNamespace}, unix.UnixRights(lfd), nil, 0)
		unix.Close(lfd)
		if err != nil {
			return "", 0, err
		}
		return shield.InetTCPOnly, 0, allThreads(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	}
	mode, inet := spec.Jail.NetFallback()
	word, port := byte(ctlNoNetwork), 0
	if mode == shield.NetLandlockPort {
		word, port = ctlLandlockPort, spec.Jail.Proxy
	}
	_, err := ctl.Write([]byte{word})
	return inet, port, err
}

// stageRetryExit is the stage's exit when the namespace it was put in can't
// hold a proxy; it ran nothing, and the shim runs it again without one.
const stageRetryExit = 125

// namespaceProxyListener brings up the namespace's loopback and listens on
// port there, for the shim outside to serve the proxy on.
func namespaceProxyListener(port int) (int, error) {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(sock)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return -1, err
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
		return -1, err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr); err != nil {
		return -1, err
	}
	lfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(lfd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		unix.Close(lfd)
		return -1, err
	}
	if err := unix.Listen(lfd, 128); err != nil {
		unix.Close(lfd)
		return -1, err
	}
	return lfd, nil
}

// resolverDirs hold the sockets through which a name is resolved outside the
// namespace: systemd-resolved's varlink socket, nscd, and the system bus,
// which resolved answers on too. An empty tmpfs over each keeps a command
// from sending what it read out as a DNS query.
var resolverDirs = []string{"/run/systemd/resolve", "/run/nscd", "/var/run/nscd", "/run/dbus"}

func hideResolvers() {
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return
	}
	for _, d := range resolverDirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			_ = unix.Mount("tmpfs", d, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0755")
		}
	}
}

// landlockNetPortAttr is struct landlock_net_port_attr, which x/sys lacks.
type landlockNetPortAttr struct {
	allowedAccess uint64
	port          uint64
}

const landlockRuleNetPort = 2

func applyLandlock(j shield.LinuxJail, netPort int) error {
	if j.ABI < shield.LandlockMinABI || j.Handled == 0 {
		return errors.New("empty ruleset")
	}
	attr := unix.LandlockRulesetAttr{Handled_access_fs: j.Handled}
	size := unsafe.Sizeof(attr.Handled_access_fs)
	if netPort > 0 {
		attr.Handled_access_net = shield.LandlockNetConnectTCP
		size = unsafe.Offsetof(attr.Scoped)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))
	for _, r := range j.Rules {
		addLandlockRule(int(fd), r.Path, r.Access&j.Handled)
	}
	if netPort > 0 {
		rule := landlockNetPortAttr{allowedAccess: shield.LandlockNetConnectTCP, port: uint64(netPort)}
		if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, landlockRuleNetPort, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
			return errno
		}
	}
	return allThreads(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0, 0, 0)
}

// addLandlockRule skips a path that has gone or changed kind since the shim
// compiled the rules: a missing rule only takes access away.
func addLandlockRule(rulesetFD int, path string, access uint64) {
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer unix.Close(pfd)
	attr := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(pfd)}
	_, _, _ = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD),
		unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
}

func applySeccomp(deny shield.SocketDeny, inet shield.InetDeny) error {
	prog, err := shield.SeccompProgram(runtime.GOARCH, deny, inet)
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filters[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(filters)
	if errno != 0 {
		return errno
	}
	return nil
}

// allThreads makes a per-thread syscall on every thread of the process: Go
// can exec from any of them, and the jail must hold whichever it is. With cgo
// that isn't possible, so it falls back to this locked thread, which then
// execs.
func allThreads(trap, a1, a2, a3, a4, a5 uintptr) error {
	_, _, errno := syscall.AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, 0)
	if errno == syscall.ENOTSUP {
		_, _, errno = unix.Syscall6(trap, a1, a2, a3, a4, a5, 0)
	}
	if errno != 0 {
		return errno
	}
	return nil
}
