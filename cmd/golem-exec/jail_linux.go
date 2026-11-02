package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
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
func (s *shim) jailed(rec *shield.RunRecord, p shield.Policy, tmp string, argv, env []string) bool {
	abi := landlockABI()
	if abi < shield.LandlockMinABI {
		rec.Jail = shield.JailNone
		rec.ExitCode = s.child(argv, env)
		return true
	}
	c := s.context(tmp, rec.RunTag)
	if p.Tainted() {
		c.HarnessFiles = harnessFiles(c.HarnessTmp, argv[1:])
	}
	j, err := shield.CompileLandlock(p, c, abi)
	if err != nil {
		j, err = shield.CompileLandlock(p, withoutWorkspace(c), abi)
	}
	if err != nil {
		return false
	}
	spec, err := json.Marshal(j)
	if err != nil {
		return false
	}
	r, w, err := os.Pipe()
	if err != nil {
		return false
	}
	cmd := exec.Command("/proc/self/exe")
	cmd.Args = append([]string{jailStage}, argv...)
	cmd.ExtraFiles = []*os.File{r}
	rec.Jail = shield.JailLandlock
	rec.PolicyHash = j.Hash()
	rec.ExitCode = s.start(cmd, env, func() {
		r.Close()
		go func() {
			_, _ = w.Write(spec)
			w.Close()
		}()
	})
	r.Close()
	w.Close()
	return true
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
	var j shield.LinuxJail
	if err := json.Unmarshal(raw, &j); err != nil {
		return err
	}
	if err := allThreads(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := applyLandlock(j); err != nil {
		return err
	}
	if j.Sockets != shield.SocketsOpen {
		if err := applySeccomp(j.Sockets); err != nil {
			return err
		}
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}

func applyLandlock(j shield.LinuxJail) error {
	if j.ABI < shield.LandlockMinABI || j.Handled == 0 {
		return errors.New("empty ruleset")
	}
	attr := unix.LandlockRulesetAttr{Handled_access_fs: j.Handled}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr.Handled_access_fs), 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))
	for _, r := range j.Rules {
		addLandlockRule(int(fd), r.Path, r.Access&j.Handled)
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

func applySeccomp(deny shield.SocketDeny) error {
	prog, err := shield.SeccompProgram(runtime.GOARCH, deny)
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
