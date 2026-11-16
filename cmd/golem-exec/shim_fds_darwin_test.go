package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// Cursor's agent runtime, which Grok Bot runs local commands through, sends
// the command on fd 5 and the shell's state on fds 3 and 4. A shim that closed
// or wrapped them would break every one of its commands.
func TestShimLeavesTheAgentsPipesToTheShell(t *testing.T) {
	const fd = 41
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := unix.Dup2(int(w.Fd()), fd); err != nil {
		t.Fatal(err)
	}
	w.Close()

	wit := newFakeWitness(t, shield.Policy{Enforce: true, State: shield.Clean})
	s, _, stderr := testShim(t, wit.URL)
	s.env = append(s.env, "SAND_AGENT=1", "CURSOR_AGENT=1")
	code := s.run("/bin/zsh", []string{"-c", "echo through >&41"})
	unix.Close(fd)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "through" {
		t.Fatalf("the shell's write on fd %d came back as %q", fd, got)
	}
	if len(wit.runs) != 1 || wit.runs[0].AgentID != "grok-bot" {
		t.Fatalf("runs %+v", wit.runs)
	}
}
