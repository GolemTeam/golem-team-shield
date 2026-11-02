//go:build !windows

package shield

import (
	"strings"
	"testing"
)

func TestParseDenialReadsATaggedKernelMessage(t *testing.T) {
	d, ok := ParseDenial("Sandbox: cat(97170) deny(1) file-read-data /Users/dev/.ssh/config\ngolem-run 01ABC")
	if !ok {
		t.Fatal("not parsed")
	}
	want := Denial{Process: "cat", PID: 97170, Operation: "file-read-data", Target: "/Users/dev/.ssh/config", RunTag: "01ABC"}
	if d != want {
		t.Fatalf("got %+v", d)
	}
	d, ok = ParseDenial("Sandbox: curl(97171) deny(1) network-outbound remote:*:80\ngolem-run 01ABC")
	if !ok || d.Operation != "network-outbound" || d.Target != "remote:*:80" {
		t.Fatalf("network denial: %+v %v", d, ok)
	}
}

func TestParseDenialIgnoresUntaggedAndMalformed(t *testing.T) {
	for _, msg := range []string{
		"Sandbox: callservicesd(39723) deny(1) user-preference-read com.apple.tty",
		"Sandbox: cat(1) deny(1) file-read-data /x\nsomething else",
		"Sandbox: cat(1) deny(1) file-read-data /x\ngolem-run bad tag!",
		"not a denial\ngolem-run 01ABC",
	} {
		if _, ok := ParseDenial(msg); ok {
			t.Errorf("parsed %q", msg)
		}
	}
}

func TestRunTagMarksEveryDenyRule(t *testing.T) {
	c := testContext()
	c.RunTag = "01ABC"
	out := mustCompile(t, Policy{Enforce: true, State: Tainted}, c)
	if n, m := strings.Count(out, "(deny"), strings.Count(out, `(with message "golem-run 01ABC")`); n == 0 || n != m {
		t.Fatalf("%d deny rules, %d tagged:\n%s", n, m, out)
	}
	c.RunTag = "bad tag"
	if _, err := CompileSeatbelt(Baseline(), c); err == nil {
		t.Fatal("a tag with a space compiled")
	}
}
