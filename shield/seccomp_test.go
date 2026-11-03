package shield

import (
	"encoding/binary"
	"testing"
)

// runBPF interprets the subset of classic BPF SeccompProgram emits.
func runBPF(t *testing.T, prog []SockFilter, arch, nr uint32, args ...uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[offNr:], nr)
	binary.LittleEndian.PutUint32(data[offArch:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[offArg0+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLdWAbs:
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case bpfJeqK, bpfJgeK:
			hit := acc == in.K
			if in.Code == bpfJgeK {
				hit = acc >= in.K
			}
			if hit {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfAndK:
			acc &= in.K
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("unexpected opcode %#x", in.Code)
		}
	}
	t.Fatal("ran off the end of the program")
	return 0
}

func TestSeccompRefusesEverySocketWhenTainted(t *testing.T) {
	for goarch, a := range seccompArches {
		prog, err := SeccompProgram(goarch, SocketsAll, InetOpen)
		if err != nil {
			t.Fatal(err)
		}
		deny := uint32(seccompRetErrno | errEACCES)
		for _, domain := range []uint64{1, 2, 10, 16, 17} {
			if got := runBPF(t, prog, a.audit, a.socket, domain); got != deny {
				t.Errorf("%s socket(%d) → %#x", goarch, domain, got)
			}
		}
		if got := runBPF(t, prog, a.audit, a.ioUringSetup, 0); got != deny {
			t.Errorf("%s io_uring_setup → %#x", goarch, got)
		}
		if got := runBPF(t, prog, a.audit, 63, 0); got != seccompRetAllow {
			t.Errorf("%s read → %#x", goarch, got)
		}
		if got := runBPF(t, prog, 0x40000003, a.socket, 2); got != seccompRetErrno|errEPERM {
			t.Errorf("%s 32-bit syscall → %#x", goarch, got)
		}
	}
}

func TestSeccompUnixModeLeavesTheNetworkOpen(t *testing.T) {
	a := seccompArches["amd64"]
	prog, err := SeccompProgram("amd64", SocketsUnix, InetOpen)
	if err != nil {
		t.Fatal(err)
	}
	if got := runBPF(t, prog, a.audit, a.socket, afUnix); got != seccompRetErrno|errEACCES {
		t.Errorf("AF_UNIX → %#x", got)
	}
	if got := runBPF(t, prog, a.audit, a.socket, 2|1<<32); got != seccompRetAllow {
		t.Errorf("AF_INET → %#x", got)
	}
	if got := runBPF(t, prog, a.audit, 0x40000000|a.socket, 2); got != seccompRetErrno|errEPERM {
		t.Errorf("x32 socket → %#x", got)
	}
}

func TestSeccompNeedsSomethingToDeny(t *testing.T) {
	if _, err := SeccompProgram("amd64", SocketsOpen, InetOpen); err == nil {
		t.Error("built a filter that denies nothing")
	}
	if _, err := SeccompProgram("riscv64", SocketsAll, InetOpen); err == nil {
		t.Error("built a filter for an architecture without syscall numbers here")
	}
}

func TestSeccompTCPOnlyLeavesLandlockEveryConnection(t *testing.T) {
	const (
		dgram    = 2
		nonblock = 0x800
		udp      = 17
		mptcp    = 262
		vsock    = 40
		packet   = 17
	)
	deny, allow := uint32(seccompRetErrno|errEACCES), uint32(seccompRetAllow)
	for goarch, a := range seccompArches {
		for _, sockets := range []SocketDeny{SocketsOpen, SocketsUnix} {
			prog, err := SeccompProgram(goarch, sockets, InetTCPOnly)
			if err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name             string
				domain, typ, pro uint64
				want             uint32
			}{
				{"tcp", afInet, sockStream, 0, allow},
				{"tcp6 nonblocking", afInet6, sockStream | nonblock, ipprotoTCP, allow},
				{"udp", afInet, dgram, 0, deny},
				{"udp6", afInet6, dgram, udp, deny},
				{"mptcp", afInet, sockStream, mptcp, deny},
				{"vsock", vsock, sockStream, 0, deny},
				{"packet", packet, 3, 0, deny},
				{"netlink", afNetlink, 3, 0, allow},
			}
			for _, c := range cases {
				if got := runBPF(t, prog, a.audit, a.socket, c.domain, c.typ, c.pro); got != c.want {
					t.Errorf("%s %s: socket(%s) → %#x", goarch, sockets, c.name, got)
				}
			}
			unix := runBPF(t, prog, a.audit, a.socket, afUnix, sockStream, 0)
			if (sockets == SocketsUnix) != (unix == deny) {
				t.Errorf("%s %s: unix → %#x", goarch, sockets, unix)
			}
			if got := runBPF(t, prog, a.audit, a.ioUringSetup, 0); got != deny {
				t.Errorf("%s io_uring_setup → %#x", goarch, got)
			}
		}
	}
}

func TestSeccompInetAllKeepsUnixAsTheGrantsSay(t *testing.T) {
	a := seccompArches["arm64"]
	deny := uint32(seccompRetErrno | errEACCES)
	for _, sockets := range []SocketDeny{SocketsOpen, SocketsUnix} {
		prog, err := SeccompProgram("arm64", sockets, InetAll)
		if err != nil {
			t.Fatal(err)
		}
		if got := runBPF(t, prog, a.audit, a.socket, afInet, sockStream, 0); got != deny {
			t.Errorf("%s: tcp → %#x", sockets, got)
		}
		if got := runBPF(t, prog, a.audit, a.socket, afUnix, sockStream, 0); (got == deny) != (sockets == SocketsUnix) {
			t.Errorf("%s: unix → %#x", sockets, got)
		}
	}
}
