package agentposture

import (
	"bytes"
	"strings"
	"testing"
)

func TestReportListsWhatIsRiskyAndCountsTheRest(t *testing.T) {
	var out bytes.Buffer
	WriteReport(&out, []Item{
		{Client: "claude-code", Check: "bypass_default", Severity: Dangerous, Location: "~/.claude/settings.json",
			Detail: "every Claude Code session starts with permission prompts off"},
		{Client: "codex", Check: "no_sandbox", Severity: Suspicious, Scope: "user", Setting: "sandbox_mode", Value: "danger-full-access"},
		{Client: "cursor", Check: "auto_review", Severity: Info},
	})
	got := out.String()
	for _, want := range []string{
		"DANGEROUS   claude-code  every Claude Code session starts with permission prompts off",
		"in ~/.claude/settings.json",
		"suspicious  codex        sandbox_mode = danger-full-access",
		"in user",
		"1 more for information only",
		"1 dangerous, 1 suspicious. Nothing was sent anywhere.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "auto_review") {
		t.Errorf("an info item is counted, not listed:\n%s", got)
	}
}

func TestReportOnACleanMachineSaysSo(t *testing.T) {
	var out bytes.Buffer
	WriteReport(&out, nil)
	if got := out.String(); !strings.Contains(got, "Nothing risky found") || !strings.Contains(got, "0 dangerous, 0 suspicious") {
		t.Errorf("clean report:\n%s", got)
	}
}
