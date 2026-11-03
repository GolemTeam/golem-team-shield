package shield

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var awkwardCommands = []string{
	`echo hi`,
	`echo 'single' "double" $HOME`,
	`printf '%s\n' "it's" 'a'\''b'`,
	"cat <<'EOF'\nline $x\nEOF",
	`a=1; b=$(echo "$a"); echo "${b}" | tr 1 2 && false || true`,
	`echo \\ \' \"`,
	"echo é ✓ `date`",
	`/elsewhere/bash -c 'echo nested'`,
}

func TestWrapHandsTheShimTheCommandUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "got")
	shim := filepath.Join(dir, "golem-bash")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" > " + Quote(out) + "\nprintf '%s' \"$2\" >> " + Quote(out) + "\n"
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sh := range []string{"sh", "bash", "zsh", "fish"} {
		path, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		for _, cmd := range awkwardCommands {
			wrapped, err := Wrap(shim, cmd)
			if err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(out)
			if b, err := exec.Command(path, "-c", wrapped).CombinedOutput(); err != nil {
				t.Fatalf("%s -c %q: %v\n%s", sh, wrapped, err, b)
			}
			got, _ := os.ReadFile(out)
			want := "-c\n" + cmd
			if string(got) != want {
				t.Errorf("%s: the shim got\n%q\nwant\n%q", sh, got, want)
			}
		}
	}
}

// Gemini CLI matches its allow and deny rules, and stores "always allow",
// against the command inside a "<path>/bash -c '…'" wrapper
// (stripShellWrapper in its bundle, 0.46.0); this is its pattern.
var geminiShellWrapper = regexp.MustCompile(`^\s*(?:(?:\S+\/)?(?:sh|bash|zsh))\s+-c\s+`)

func TestClientsSeeTheCommandInsideTheWrap(t *testing.T) {
	got, _ := Wrap("/Users/dev/.golem/bin/hook/bash", "git push origin main")
	m := geminiShellWrapper.FindString(got)
	if m == "" {
		t.Fatalf("Gemini CLI would not see inside %q", got)
	}
	if inner := strings.Trim(got[len(m):], "'"); inner != "git push origin main" {
		t.Fatalf("Gemini CLI would match its rules against %q", inner)
	}
}

func TestWrapRefusesWhatItCannotRunInTheJail(t *testing.T) {
	for _, tc := range []struct{ shim, cmd string }{
		{"/h/.golem/bin/golem-bash", ""},
		{"/h/.golem/bin/golem-bash", "  \n"},
		{"/h/.golem/bin/golem-bash", "echo a\x00b"},
		{"golem-bash", "true"},
		{"", "true"},
		{"/Users/a b/.golem/bin/hook/bash", "true"},
		{"/h/.golem/bin/hook/bash; rm", "true"},
	} {
		if _, err := Wrap(tc.shim, tc.cmd); err == nil {
			t.Errorf("Wrap(%q, %q) wrapped it", tc.shim, tc.cmd)
		}
	}
}

func TestWrapIsIdempotent(t *testing.T) {
	shim := "/h/.golem/bin/hook/bash"
	once, _ := Wrap(shim, "ls -la")
	twice, err := Wrap(shim, once)
	if err != nil || twice != once {
		t.Fatalf("wrapped twice: %q", twice)
	}
	other, _ := Wrap("/elsewhere/bash", "ls")
	if Wrapped(shim, other) {
		t.Fatal("a wrap for another shim counted as ours")
	}
}
