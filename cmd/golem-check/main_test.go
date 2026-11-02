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
	for _, want := range []string{"DANGEROUS", "claude-code", "Nothing was sent anywhere", installCommand(runtime.GOOS)} {
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

func TestAnUnknownFlagIsAUsageError(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"-nope"}, &out, &errs); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}
