package checkcmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/agentposture"
	"github.com/GolemTeam/golem-team-shield/shield"
)

const footerLine = "the footer of a machine scan"

func options(res agentposture.Result) Options {
	return Options{
		Name: "golem-check", Version: "1.2.3",
		Machine: func() agentposture.Result { return res },
		Footer: func(out io.Writer) error {
			_, err := io.WriteString(out, footerLine+"\n")
			return err
		},
	}
}

func riskyRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(filepath.Join(repo, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".claude", "settings.json"), []byte(`{"permissions":{"defaultMode":"bypassPermissions"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return repo
}

func run(t *testing.T, o Options, args ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := Run(args, &out, &errs, o)
	return code, out.String(), errs.String()
}

func TestEveryFormatComesFromOneCommandLine(t *testing.T) {
	machine := agentposture.Result{Items: []agentposture.Item{{Client: "claude-code", Check: "bypass_default", Severity: agentposture.Dangerous, Area: agentposture.AreaRunModes, Detail: "prompts off"}}}
	o := options(machine)

	if code, out, _ := run(t, o); code != 0 || !strings.Contains(out, "DANGEROUS") || !strings.Contains(out, footerLine) {
		t.Errorf("text: exit %d\n%s", code, out)
	}
	if code, out, _ := run(t, o, "-json"); code != 0 || !strings.HasPrefix(out, "[") {
		t.Errorf("-json: exit %d\n%s", code, out)
	}
	var scored struct {
		Score agentposture.Report `json:"score"`
		Items []agentposture.Item `json:"items"`
	}
	if code, out, _ := run(t, o, "-json", "-with-score"); code != 0 || json.Unmarshal([]byte(out), &scored) != nil || scored.Score.Grade == "" || len(scored.Items) != 1 {
		t.Errorf("-json -with-score: exit %d\n%s", code, out)
	}
	if code, out, _ := run(t, o, "-sarif"); code != 0 || !strings.Contains(out, `"version": "2.1.0"`) || !strings.Contains(out, `"version": "1.2.3"`) {
		t.Errorf("-sarif: exit %d\n%s", code, out)
	}
	if code, out, _ := run(t, o, "-html"); code != 0 || !strings.Contains(out, "<html") {
		t.Errorf("-html: exit %d", code)
	}
	if code, out, _ := run(t, o, "-version"); code != 0 || out != "golem-check 1.2.3\n" {
		t.Errorf("-version: exit %d %q", code, out)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if code, out, _ := run(t, o, "-json", "-o", path); code != 0 || out != "" {
		t.Errorf("-o: exit %d, stdout %q", code, out)
	} else if b, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(b), "[") {
		t.Errorf("-o wrote %q, %v", b, err)
	}
}

func TestFailOnSetsTheExitCode(t *testing.T) {
	suspicious := options(agentposture.Result{Items: []agentposture.Item{
		{Client: "x", Check: "y", Severity: agentposture.Suspicious, Area: agentposture.AreaPermissions},
		{Client: "x", Check: "shell_jail", Severity: agentposture.Suspicious, Area: agentposture.AreaProtections},
	}})
	for _, c := range []struct {
		failOn string
		want   int
	}{{"none", 0}, {"dangerous", 0}, {"suspicious", 3}} {
		if code, _, _ := run(t, suspicious, "-fail-on", c.failOn); code != c.want {
			t.Errorf("-fail-on %s: exit %d, want %d", c.failOn, code, c.want)
		}
	}
	protectionsOnly := options(agentposture.Result{Items: []agentposture.Item{{Client: "x", Check: "shell_jail", Severity: agentposture.Suspicious, Area: agentposture.AreaProtections}}})
	if code, _, _ := run(t, protectionsOnly, "-fail-on", "suspicious"); code != 0 {
		t.Errorf("a missing protection failed the build: exit %d", code)
	}
}

func TestUsageErrorsNameTheCommand(t *testing.T) {
	o := options(agentposture.Result{})
	o.Name = "golem check"
	for _, args := range [][]string{{"-fail-on", "loud"}, {"-repo", filepath.Join(t.TempDir(), "missing")}, {"-nope"}} {
		code, _, errs := run(t, o, args...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if args[0] != "-nope" && !strings.HasPrefix(errs, "golem check: ") {
			t.Errorf("%v: %q", args, errs)
		}
	}
}

func TestRepoChecksTheRepositoryNotTheMachine(t *testing.T) {
	o := options(agentposture.Result{Items: []agentposture.Item{{Client: "machine", Check: "only_on_the_machine", Severity: agentposture.Dangerous}}})
	code, out, _ := run(t, o, "-repo", riskyRepo(t), "-fail-on", "suspicious")
	if code != 3 || !strings.Contains(out, "permission prompts off") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "only_on_the_machine") || strings.Contains(out, footerLine) {
		t.Errorf("-repo printed the machine scan or its footer:\n%s", out)
	}
}

func TestShellJailCoverageIsCreditWhenJailed(t *testing.T) {
	items := ShellJailItems([]shield.AgentCoverage{
		{Client: "claude-code", Coverage: shield.Jailed, Detail: "jailed"},
		{Client: "cursor", Coverage: shield.NotJailed, Detail: "not jailed"},
	})
	if len(items) != 2 || items[0].Severity != agentposture.Info || items[1].Severity != agentposture.Suspicious || items[0].Area != agentposture.AreaProtections {
		t.Errorf("%+v", items)
	}
}
