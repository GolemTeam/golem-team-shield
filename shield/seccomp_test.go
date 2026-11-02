package shield

import (
	"encoding/binary"
	"testing"
)

// runBPF interprets the subset of classic BPF SeccompProgram emits.
func runBPF(t *testing.T, prog []SockFilter, arch, nr uint32, arg0 uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[offNr:], nr)
	binary.LittleEndian.PutUint32(data[offArch:], arch)
	binary.LittleEndian.PutUint64(data[offArg0:], arg0)
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
		prog, err := SeccompProgram(goarch, SocketsAll)
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
	prog, err := SeccompProgram("amd64", SocketsUnix)
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
	if _, err := SeccompProgram("amd64", SocketsOpen); err == nil {
		t.Error("built a filter that denies nothing")
	}
	if _, err := SeccompProgram("riscv64", SocketsAll); err == nil {
		t.Error("built a filter for an architecture without syscall numbers here")
	}
}
