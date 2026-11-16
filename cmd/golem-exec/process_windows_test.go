package main

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/GolemTeam/golem-team-shield/shield"
)

func TestHelperOpenParent(t *testing.T) {
	var pid int
	for _, a := range os.Args {
		if v, ok := strings.CutPrefix(a, "open-pid="); ok {
			pid, _ = strconv.Atoi(v)
		}
	}
	if pid == 0 {
		t.Skip("run by TestAJailedCommandCantReadTheShimsMemory")
	}
	for name, access := range map[string]uint32{"read": windows.PROCESS_VM_READ, "inject": windows.PROCESS_CREATE_THREAD | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_OPERATION} {
		h, err := windows.OpenProcess(access, false, uint32(pid))
		if err == nil {
			windows.CloseHandle(h)
			os.Stdout.WriteString("OPENED-" + name + "\n")
		} else {
			os.Stdout.WriteString("DENIED-" + name + "\n")
		}
	}
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
		windows.CloseHandle(h)
		os.Stdout.WriteString("QUERY-OK\n")
	}
}

func TestAJailedCommandCantReadTheShimsMemory(t *testing.T) {
	w := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean, Grants: shield.AllGrants()})
	s, stdout, _ := testShim(t, w.URL)
	s.env = append(s.env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
	s.run(os.Args[0], []string{"-test.run=^TestHelperOpenParent$", "-test.v", "open-pid=" + strconv.Itoa(os.Getpid())})
	out := stdout.String()
	if strings.Contains(out, "OPENED-") || !strings.Contains(out, "DENIED-read") || !strings.Contains(out, "DENIED-inject") {
		t.Fatalf("a jailed command could open the shim: %s", out)
	}
	if !strings.Contains(out, "QUERY-OK") {
		t.Errorf("a jailed command can no longer even ask about its parent: %s", out)
	}
}
