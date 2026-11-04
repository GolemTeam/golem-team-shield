package agentposture

import (
	"bytes"
	"strings"
	"testing"
)

func TestReportListsWhatIsRiskyAndCountsTheRest(t *testing.T) {
	var out bytes.Buffer
	res := Result{Agents: []string{"claude-code", "codex"}, Read: []string{AreaRunModes, AreaPermissions, AreaProtections}}
	res.Add(
		Item{Client: "claude-code", Check: "bypass_default", Severity: Dangerous, Location: "~/.claude/settings.json",
			Detail: "every Claude Code session starts with permission prompts off"},
		Item{Client: "codex", Check: "full_access", Severity: Suspicious, Scope: "user", Setting: "sandbox_mode", Value: "danger-full-access"},
		Item{Client: "cursor", Check: "auto_review", Severity: Info},
		Item{Client: "codex", Check: "agent_sandbox", Severity: Info, Detail: "Codex runs commands in its sandbox by default"},
	)
	WriteReport(&out, res)
	got := out.String()
	for _, want := range []string{
		"grade D (64 of 100)",
		"Run modes",
		"1 dangerous, 1 suspicious, 1 to note",
		"0.75 of 2 agents jailed or sandboxed",
		"DANGEROUS   claude-code  every Claude Code session starts with permission prompts off",
		"in ~/.claude/settings.json",
		"suspicious  codex        sandbox_mode = danger-full-access",
		"in user",
		"1 more for information only",
		"Protections\n  claude-code  no sandbox found; this check cannot see a shell jail yet\n  codex        Codex runs commands in its sandbox by default",
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

func TestReportWithNoAgentsHasNoGrade(t *testing.T) {
	var out bytes.Buffer
	WriteReport(&out, Result{})
	got := out.String()
	for _, want := range []string{"No AI coding agents found", "Nothing risky found", "0 dangerous, 0 suspicious"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "grade") || strings.Contains(got, "Protections") {
		t.Errorf("a machine with no agents is graded:\n%s", got)
	}
}

func TestAFindingWithALineSaysWhichLine(t *testing.T) {
	var out bytes.Buffer
	res := Result{Agents: []string{"claude-code"}, Read: []string{AreaInstructions}}
	res.Add(Item{Client: "claude-code", Check: "gd-conceal", Area: AreaInstructions, Severity: Suspicious, Location: "~/.claude/skills/notes/SKILL.md", Line: 12})
	WriteReport(&out, res)
	if !strings.Contains(out.String(), "in ~/.claude/skills/notes/SKILL.md:12") {
		t.Errorf("no line in:\n%s", out.String())
	}
}

func TestAnAgentWhoseJailWasLookedForSaysWhatWasFound(t *testing.T) {
	var out bytes.Buffer
	res := Result{Agents: []string{"codex"}, Read: []string{AreaProtections}}
	res.Add(Item{Client: "codex", Check: "shell_jail", Value: "not_jailed", Area: AreaProtections, Severity: Suspicious,
		Detail: "Codex's shell commands run outside the jail"})
	WriteReport(&out, res)
	if got := out.String(); !strings.Contains(got, "codex        Codex's shell commands run outside the jail\n") {
		t.Errorf("got:\n%s", got)
	}
}

func TestAnAgentWithNeitherSandboxNorJailSaysBoth(t *testing.T) {
	var out bytes.Buffer
	res := Result{Agents: []string{"claude-code"}, Read: []string{AreaProtections}}
	res.Add(Item{Client: "claude-code", Check: "shell_jail", Value: "not_jailed", Area: AreaProtections, Severity: Suspicious,
		Detail: "Claude Code's shell commands run without the Golem jail: CLAUDE_CODE_SHELL is not set"})
	res.Add(Item{Client: "claude-code", Check: "no_sandbox", Area: AreaProtections, Severity: Suspicious,
		Detail: "shell commands run without Claude Code's sandbox"})
	WriteReport(&out, res)
	want := "claude-code  shell commands run without Claude Code's sandbox; Claude Code's shell commands run without the Golem jail: CLAUDE_CODE_SHELL is not set\n"
	if got := out.String(); !strings.Contains(got, want) || strings.Contains(got, "cannot see a shell jail") {
		t.Errorf("got:\n%s", got)
	}
}
