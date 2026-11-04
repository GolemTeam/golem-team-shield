package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func withSettings(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("PATH", t.TempDir())
	t.Setenv("GOLEM_INSTALL_DIR", "")
	saved := systemBinDirs
	systemBinDirs = nil
	t.Cleanup(func() { systemBinDirs = saved })
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReportsPromptsOffAndSaysNothingWasSent(t *testing.T) {
	withSettings(t, `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	var out, errs bytes.Buffer
	if code := run(nil, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	for _, want := range []string{"grade D", "DANGEROUS", "claude-code", "Nothing was sent anywhere", "Not read: MCP tool descriptions", installCommand(runtime.GOOS)} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestJSONListsEveryFinding(t *testing.T) {
	withSettings(t, `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	var out, errs bytes.Buffer
	if code := run([]string{"-json"}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var items []struct {
		Client, Check, Severity string
	}
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	found := false
	for _, it := range items {
		found = found || (it.Client == "claude-code" && it.Check == "bypass_default" && it.Severity == "dangerous")
	}
	if !found {
		t.Errorf("no bypass_default finding in %s", out.String())
	}
}

func TestJSONWithScoreWrapsTheSameItems(t *testing.T) {
	withSettings(t, `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	var out, errs bytes.Buffer
	if code := run([]string{"-json", "-with-score"}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var doc struct {
		Score struct {
			Version, Grade string
			Score          int
		}
		Items []struct{ Check, Area string }
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if doc.Score.Grade != "D" || doc.Score.Version == "" || len(doc.Items) == 0 || doc.Items[0].Check != "bypass_default" || doc.Items[0].Area != "run_modes" {
		t.Errorf("got %+v", doc)
	}
}

func TestVersion(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"--version"}, &out, &errs); code != 0 || !strings.HasPrefix(out.String(), "golem-check ") {
		t.Errorf("exit %d: %q %q", code, out.String(), errs.String())
	}
}

func TestAnUnknownFlagIsAUsageError(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"-nope"}, &out, &errs); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

func TestTheShellJailCountsAsAProtection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows shim is bash.exe, set through CLAUDE_CODE_GIT_BASH_PATH")
	}
	withSettings(t, `{}`)
	home := os.Getenv("HOME")
	shim := filepath.Join(home, ".golem", "bin", "golem-zsh")
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"env":{"CLAUDE_CODE_SHELL":"`+shim+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{"-json"}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var items []struct{ Client, Area, Check, Value string }
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Check == "shell_jail" && it.Client == "claude-code" && it.Value == "jailed" && it.Area == "protections" {
			return
		}
	}
	t.Fatalf("no jailed shell_jail item for Claude Code in %s", out.String())
}

func TestARepoReportInSARIFFailsOnWhatItFinds(t *testing.T) {
	withSettings(t, `{}`)
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".claude", "settings.json"), []byte(`{"permissions":{"allow":["Bash(*)"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "out.sarif")
	var out, errs bytes.Buffer
	if code := run([]string{"-repo", repo, "-sarif", "-o", report, "-fail-on", "suspicious"}, &out, &errs); code != 3 {
		t.Fatalf("exit %d, want 3: %s", code, errs.String())
	}
	b, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(b), `"ruleId": "shell_allowed"`) || !strings.Contains(string(b), `"uri": ".claude/settings.json"`) {
		t.Fatalf("%v\n%s", err, b)
	}
	if out.Len() != 0 {
		t.Errorf("wrote to stdout with -o: %s", out.String())
	}
	if code := run([]string{"-repo", repo, "-fail-on", "dangerous"}, &out, &errs); code != 0 {
		t.Errorf("a suspicious finding failed -fail-on dangerous: exit %d", code)
	}
}

func TestBadFlagValuesAreUsageErrors(t *testing.T) {
	var out, errs bytes.Buffer
	for _, args := range [][]string{{"-fail-on", "high"}, {"-repo", filepath.Join(t.TempDir(), "missing")}} {
		if code := run(args, &out, &errs); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestTheInstallLineIsLeftOutWhereTheAgentIsInstalled(t *testing.T) {
	withSettings(t, `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	var out, errs bytes.Buffer
	if code := run(nil, &out, &errs); code != 0 || !strings.Contains(out.String(), installCommand(runtime.GOOS)) {
		t.Fatalf("no agent, no install line (exit %d):\n%s", code, out.String())
	}

	name := "golem"
	if runtime.GOOS == "windows" {
		name = "golem.exe"
	}
	bin := filepath.Join(os.Getenv("HOME"), ".local", "bin", name)
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Setenv("PATH", filepath.Dir(bin))
	}
	out.Reset()
	if code := run(nil, &out, &errs); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := out.String(); strings.Contains(got, installCommand(runtime.GOOS)) || !strings.Contains(got, "The Golem agent is installed here") {
		t.Errorf("an installed agent is offered again:\n%s", got)
	}
}
