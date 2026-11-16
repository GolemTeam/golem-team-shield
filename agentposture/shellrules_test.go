package agentposture

import (
	"path/filepath"
	"testing"
)

func TestShellRuleKinds(t *testing.T) {
	for _, c := range []struct {
		rule string
		want shellRuleKind
		cmd  string
	}{
		{"Bash", shellAny, ""},
		{"Bash(*)", shellAny, ""},
		{"Bash( : * )", shellAny, ""},
		{"Bash(python3:*)", shellAnyCode, "python3"},
		{"Bash(python3.12 *)", shellAnyCode, "python3.12"},
		{"Bash(/usr/bin/node:*)", shellAnyCode, "/usr/bin/node"},
		{"Bash(bash -c:*)", shellAnyCode, "bash -c"},
		{"Bash(sh:*)", shellAnyCode, "sh"},
		{"Bash(npx:*)", shellAnyCode, "npx"},
		{"Bash(eval:*)", shellAnyCode, "eval"},
		{"Bash(uv run:*)", shellAnyCode, "uv run"},
		{"Bash(curl:*)", shellUpload, "curl"},
		{"Bash(wget *)", shellUpload, "wget"},
		{"Bash(scp:*)", shellUpload, "scp"},

		{"Bash(python3)", shellNone, ""},
		{"Bash(python3 -m pytest:*)", shellNone, ""},
		{"Bash(python3 scripts/build.py)", shellNone, ""},
		{"Bash(npm test:*)", shellNone, ""},
		{"Bash(npm run build:*)", shellNone, ""},
		{"Bash(git status)", shellNone, ""},
		{"Bash(git:*)", shellNone, ""},
		{"Bash(uv sync:*)", shellNone, ""},
		{"Read(./src/**)", shellNone, ""},
		{"WebFetch", shellNone, ""},
	} {
		if k, cmd := claudeShellRule(c.rule); k != c.want || cmd != c.cmd {
			t.Errorf("%s: %v %q, want %v %q", c.rule, k, cmd, c.want, c.cmd)
		}
	}
	for _, c := range []struct {
		rule string
		want shellRuleKind
	}{
		{"Shell(*)", shellAny},
		{"Shell(python3)", shellAnyCode},
		{"Shell(bash)", shellAnyCode},
		{"Shell(curl)", shellUpload},
		{"Shell(git)", shellNone},
		{"Shell(ls)", shellNone},
		{"Write(**)", shellNone},
	} {
		if k, _ := cursorShellRule(c.rule); k != c.want {
			t.Errorf("%s: %v, want %v", c.rule, k, c.want)
		}
	}
}

func TestInterpreterAndUploadAllowRules(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"permissions":{"allow":["Bash(npm test:*)","Bash(python3 -m pytest:*)","Bash(node:*)","Bash(curl:*)","Bash(wget:*)"]}}`)
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"),
		`{"permissions":{"allow":["Shell(git)","Shell(*)","Shell(curl)"]}}`)

	got := map[string]Item{}
	for _, it := range ScanAll(env).Items {
		got[it.Client+"/"+it.Check] = it
	}
	if it := got["claude-code/shell_allowed"]; it.Value != "Bash(node:*)" || it.Severity != Suspicious ||
		it.Detail != "any code runs without asking, through node" {
		t.Errorf("claude shell = %+v", it)
	}
	if it := got["claude-code/upload_allowed"]; it.Value != "Bash(curl:*)" || it.Severity != Suspicious || it.Area != AreaPermissions {
		t.Errorf("claude upload = %+v", it)
	}
	if it := got["cursor/shell_allowed"]; it.Value != "Shell(*)" || it.Severity != Suspicious {
		t.Errorf("cursor shell = %+v", it)
	}
	if it := got["cursor/upload_allowed"]; it.Value != "Shell(curl)" {
		t.Errorf("cursor upload = %+v", it)
	}
	for _, it := range Scan(env) {
		if it.Check == "upload_allowed" {
			t.Error("a report-only check reached the posture items")
		}
	}
}

func TestOneToolAllowRulesAreNotShell(t *testing.T) {
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"permissions":{"allow":["Bash(npm test:*)","Bash(python3 -m pytest:*)","Bash(git status)","Bash(python3)"]}}`)
	writePostureFile(t, filepath.Join(env.Home, ".cursor", "cli-config.json"), `{"permissions":{"allow":["Shell(git)","Shell(ls)"]}}`)
	for _, it := range ScanAll(env).Items {
		if it.Check == "shell_allowed" || it.Check == "upload_allowed" {
			t.Errorf("one tool reported as any: %+v", it)
		}
	}
}
