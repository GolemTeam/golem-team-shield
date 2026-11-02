package shield

import "fmt"

// SockFilter is struct sock_filter.
type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

const (
	bpfLdWAbs = 0x00 | 0x00 | 0x20
	bpfJeqK   = 0x05 | 0x10 | 0x00
	bpfJgeK   = 0x05 | 0x30 | 0x00
	bpfRetK   = 0x06 | 0x00

	seccompRetAllow = 0x7fff0000
	seccompRetErrno = 0x00050000
	errEPERM        = 1
	errEACCES       = 13

	afUnix = 1

	// struct seccomp_data: nr at 0, arch at 4, args from 16. Both supported
	// architectures are little-endian, so an argument's low word is first.
	offNr   = 0
	offArch = 4
	offArg0 = 16
)

type seccompArch struct {
	audit         uint32
	socket        uint32
	ioUringSetup  uint32
	x32SyscallBit bool
}

var seccompArches = map[string]seccompArch{
	"amd64": {audit: 0xc000003e, socket: 41, ioUringSetup: 425, x32SyscallBit: true},
	"arm64": {audit: 0xc00000b7, socket: 198, ioUringSetup: 425},
}

// SeccompProgram is the filter that refuses the sockets deny names with
// EACCES. io_uring is refused whenever a socket is, because its operations
// open and connect sockets without passing through the filter. A syscall from
// another architecture's ABI (x32, or 32-bit compat) is refused outright, so
// the filter can't be stepped around by syscall number. socketpair stays
// open: it reaches nothing outside the jail.
func SeccompProgram(goarch string, deny SocketDeny) ([]SockFilter, error) {
	a, ok := seccompArches[goarch]
	if !ok {
		return nil, fmt.Errorf("no seccomp filter for %s", goarch)
	}
	if deny != SocketsUnix && deny != SocketsAll {
		return nil, fmt.Errorf("no sockets to deny")
	}
	var p bpfProgram
	p.ld(offArch)
	p.jeq(a.audit, "", "foreign")
	p.ld(offNr)
	if a.x32SyscallBit {
		p.jge(0x40000000, "foreign", "")
	}
	p.jeq(a.ioUringSetup, "deny", "")
	if deny == SocketsAll {
		p.jeq(a.socket, "deny", "allow")
	} else {
		p.jeq(a.socket, "", "allow")
		p.ld(offArg0)
		p.jeq(afUnix, "deny", "allow")
	}
	p.label("allow")
	p.ret(seccompRetAllow)
	p.label("deny")
	p.ret(seccompRetErrno | errEACCES)
	p.label("foreign")
	p.ret(seccompRetErrno | errEPERM)
	return p.assemble()
}

type bpfInsn struct {
	SockFilter
	jt, jf string
}

type bpfProgram struct {
	insns  []bpfInsn
	labels map[string]int
}

func (p *bpfProgram) ld(off uint32) {
	p.insns = append(p.insns, bpfInsn{SockFilter: SockFilter{Code: bpfLdWAbs, K: off}})
}

func (p *bpfProgram) jeq(k uint32, jt, jf string) {
	p.insns = append(p.insns, bpfInsn{SockFilter: SockFilter{Code: bpfJeqK, K: k}, jt: jt, jf: jf})
}

func (p *bpfProgram) jge(k uint32, jt, jf string) {
	p.insns = append(p.insns, bpfInsn{SockFilter: SockFilter{Code: bpfJgeK, K: k}, jt: jt, jf: jf})
}

func (p *bpfProgram) ret(k uint32) {
	p.insns = append(p.insns, bpfInsn{SockFilter: SockFilter{Code: bpfRetK, K: k}})
}

func (p *bpfProgram) label(name string) {
	if p.labels == nil {
		p.labels = map[string]int{}
	}
	p.labels[name] = len(p.insns)
}

// assemble turns each label into a forward offset; an empty label falls
// through.
func (p *bpfProgram) assemble() ([]SockFilter, error) {
	out := make([]SockFilter, len(p.insns))
	for i, in := range p.insns {
		f := in.SockFilter
		for _, j := range []struct {
			label string
			off   *uint8
		}{{in.jt, &f.Jt}, {in.jf, &f.Jf}} {
			if j.label == "" {
				continue
			}
			target, ok := p.labels[j.label]
			if !ok || target <= i || target-i-1 > 255 {
				return nil, fmt.Errorf("bad jump to %q", j.label)
			}
			*j.off = uint8(target - i - 1)
		}
		out[i] = f
	}
	return out, nil
}
