//go:build darwin

package agentposture

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/unix"
)

type osProcesses struct{}

func (osProcesses) Alive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || err == unix.EPERM
}

func (osProcesses) Environ(pid int) ([]string, bool) { return ProcessEnviron(pid) }

// ProcessEnviron reads a process's environment from kern.procargs2, as
// `ps eww` does. macOS answers only for the caller's own processes.
func ProcessEnviron(pid int) ([]string, bool) {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, false
	}
	return parseProcArgs2(b)
}

// parseProcArgs2 reads argc, the executable path, then argc arguments and the
// environment, each NUL-terminated, with NUL padding after the path.
func parseProcArgs2(b []byte) ([]string, bool) {
	if len(b) < 4 {
		return nil, false
	}
	argc := int(binary.LittleEndian.Uint32(b[:4]))
	rest := b[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil, false
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	var env []string
	for n := 0; len(rest) > 0; n++ {
		i := bytes.IndexByte(rest, 0)
		if i <= 0 {
			break
		}
		if n >= argc {
			env = append(env, string(rest[:i]))
		}
		rest = rest[i+1:]
	}
	return env, true
}
