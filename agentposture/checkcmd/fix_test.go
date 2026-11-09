package checkcmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

type fixHome struct {
	env    agentposture.Env
	claude string
	cursor string
}

func newFixHome(t *testing.T) fixHome {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := t.TempDir()
	h := fixHome{
		env: agentposture.Env{
			Home: home, GOOS: "linux",
			ManagedDir:   filepath.Join(root, "claude-code"),
			GeminiSystem: filepath.Join(root, "gemini-cli", "settings.json"),
			CodexHomes:   []string{filepath.Join(home, ".codex")},
		},
		claude: filepath.Join(home, ".claude", "settings.json"),
		cursor: filepath.Join(home, ".cursor", "cli-config.json"),
	}
	put(t, h.claude, "{\n  \"permissions\": {\n    \"defaultMode\": \"bypassPermissions\",\n    \"allow\": [\"Read\", \"Bash(*)\"]\n  }\n}\n")
	put(t, h.cursor, `{"permissions":{"allow":["Read(**)"]}}`)
	return h
}

func put(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h fixHome) options() Options {
	o := options(agentposture.Result{})
	o.Machine = func() agentposture.Result { return agentposture.ScanAll(h.env) }
	o.Env = func() agentposture.Env { return h.env }
	return o
}

func snapshot(t *testing.T, paths ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(p)
		out[p] = info.Mode().Perm().String() + "\n" + string(b)
	}
	return out
}

func same(t *testing.T, want map[string]string) {
	t.Helper()
	for p, w := range want {
		if got := snapshot(t, p)[p]; got != w {
			t.Errorf("%s changed:\n%s\nwas:\n%s", p, got, w)
		}
	}
}

func TestFixIsADryRunWithoutYes(t *testing.T) {
	h := newFixHome(t)
	before := snapshot(t, h.claude, h.cursor)
	code, out, errs := run(t, h.options(), "-fix")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"~/.claude/settings.json", `-    "defaultMode": "bypassPermissions",`, "Dry run: nothing was changed", "golem-check -fix -yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	same(t, before)
	if _, err := os.Stat(filepath.Join(h.env.Home, ".golem")); !os.IsNotExist(err) {
		t.Error("a dry run made the backup folder")
	}
}

func TestFixYesBacksUpWritesAndRescans(t *testing.T) {
	h := newFixHome(t)
	original, _ := os.ReadFile(h.claude)
	code, out, errs := run(t, h.options(), "-fix", "-yes")
	if code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, errs, out)
	}
	got, _ := os.ReadFile(h.claude)
	if strings.Contains(string(got), "bypassPermissions") || strings.Contains(string(got), "Bash(*)") || !strings.Contains(string(got), `"Read"`) {
		t.Errorf("settings after -fix -yes:\n%s", got)
	}
	if !strings.Contains(out, "Grade: ") || !strings.Contains(out, "~/.golem/check-backups/") {
		t.Errorf("output:\n%s", out)
	}
	dirs, _ := filepath.Glob(filepath.Join(h.env.Home, ".golem", "check-backups", "*"))
	if len(dirs) != 1 {
		t.Fatalf("backup folders %v", dirs)
	}
	backup := filepath.Join(dirs[0], ".claude", "settings.json")
	if b, err := os.ReadFile(backup); err != nil || !bytes.Equal(b, original) {
		t.Errorf("backup %q (%v), want the original", b, err)
	}
	var manifest []manifestEntry
	if b, err := os.ReadFile(filepath.Join(dirs[0], "manifest.json")); err != nil || json.Unmarshal(b, &manifest) != nil || len(manifest) != 1 || manifest[0].Path != h.claude {
		t.Errorf("manifest %+v (%v)", manifest, err)
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{dirs[0]: 0o700, backup: 0o600} {
			if info, _ := os.Stat(path); info.Mode().Perm() != want {
				t.Errorf("%s mode %o", path, info.Mode().Perm())
			}
		}
	}
	if code, out, _ := run(t, h.options(), "-fix"); code != 0 || !strings.Contains(out, "Nothing in your own agent settings") {
		t.Errorf("second pass: exit %d\n%s", code, out)
	}
}

func TestFixRollsBackEveryFileWhenTheScoreDrops(t *testing.T) {
	h := newFixHome(t)
	before := snapshot(t, h.claude, h.cursor)
	plan := agentposture.PlanFixes(h.env)
	if len(plan.Files) != 1 {
		t.Fatalf("plan %+v", plan.Files)
	}
	old, _ := os.ReadFile(h.cursor)
	plan.Files = append(plan.Files, agentposture.FileFix{
		Path: h.cursor, Location: "~/.cursor/cli-config.json", Format: "json",
		Old: old, New: []byte(`{"approvalMode":"unrestricted","permissions":{"allow":["Read(**)"]}}`),
		OldMode: 0o600, NewMode: 0o600, Changes: []string{"makes it worse"},
	})
	var out, errs bytes.Buffer
	code := fixWith(&out, &errs, h.options(), h.env, plan, true, time.Now())
	if code != ExitRolledBack {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, ExitRolledBack, out.String(), errs.String())
	}
	if !strings.Contains(out.String(), "Rolled back: ") {
		t.Errorf("output:\n%s", out.String())
	}
	same(t, before)
}

func TestFixRollsBackWhenAFileNoLongerParses(t *testing.T) {
	h := newFixHome(t)
	before := snapshot(t, h.claude, h.cursor)
	plan := agentposture.PlanFixes(h.env)
	old, _ := os.ReadFile(h.cursor)
	plan.Files = append(plan.Files, agentposture.FileFix{
		Path: h.cursor, Location: "~/.cursor/cli-config.json", Format: "json",
		Old: old, New: []byte(`{"permissions":`), OldMode: 0o600, NewMode: 0o600,
	})
	var out, errs bytes.Buffer
	if code := fixWith(&out, &errs, h.options(), h.env, plan, true, time.Now()); code != ExitRolledBack || !strings.Contains(out.String(), "no longer parses") {
		t.Errorf("exit %d\n%s", code, out.String())
	}
	same(t, before)
}

func TestFixChangesNothingWhenAFileMovedSinceThePlan(t *testing.T) {
	h := newFixHome(t)
	plan := agentposture.PlanFixes(h.env)
	put(t, h.claude, `{"permissions":{"defaultMode":"bypassPermissions","allow":["Edit"]}}`)
	before := snapshot(t, h.claude, h.cursor)
	var out, errs bytes.Buffer
	if code := fixWith(&out, &errs, h.options(), h.env, plan, true, time.Now()); code != 1 || !strings.Contains(errs.String(), "nothing was changed") {
		t.Errorf("exit %d\n%s", code, errs.String())
	}
	same(t, before)
}

func TestFixLeavesAFileItCannotParseAlone(t *testing.T) {
	h := newFixHome(t)
	put(t, h.claude, "{\n  // set by hand\n  \"permissions\": {\"defaultMode\": \"bypassPermissions\"},\n}\n")
	before := snapshot(t, h.claude, h.cursor)
	code, out, _ := run(t, h.options(), "-fix", "-yes")
	if code != 0 || !strings.Contains(out, "Left alone:") || !strings.Contains(out, "not plain JSON") {
		t.Errorf("exit %d\n%s", code, out)
	}
	same(t, before)
}

func TestFixTakesOnlyYesAndO(t *testing.T) {
	h := newFixHome(t)
	for _, args := range [][]string{{"-yes"}, {"-fix", "-json"}, {"-fix", "-sarif"}, {"-fix", "-repo", "."}, {"-fix", "-fail-on", "dangerous"}} {
		if code, _, _ := run(t, h.options(), args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	plan := filepath.Join(t.TempDir(), "plan.txt")
	if code, _, _ := run(t, h.options(), "-fix", "-o", plan); code != 0 {
		t.Errorf("-fix -o: exit %d", code)
	}
	if b, _ := os.ReadFile(plan); !strings.Contains(string(b), "Dry run") {
		t.Errorf("plan file: %s", b)
	}
}
