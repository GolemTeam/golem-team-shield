package agentposture

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParsePlistBinaryAndXMLAgree(t *testing.T) {
	want := map[string]any{
		"permissions": map[string]any{
			"defaultMode":                  "bypassPermissions",
			"disableBypassPermissionsMode": "disable",
			"allow":                        []any{"Bash(*)", "Read"},
		},
		"sandbox":           map[string]any{"enabled": true, "failIfUnavailable": false},
		"cleanupPeriodDays": float64(30),
		"ratio":             0.5,
		"note":              "café ✓",
	}
	for _, name := range []string{"claude-managed.bplist", "claude-managed.xml"} {
		b, err := os.ReadFile(filepath.Join("testdata", "plist", name))
		if err != nil {
			t.Fatal(err)
		}
		v, err := parsePlist(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := v.(map[string]any)
		for k, w := range want {
			if !reflect.DeepEqual(got[k], w) {
				t.Errorf("%s: %s = %#v, want %#v", name, k, got[k], w)
			}
		}
		list, _ := got["longList"].([]any)
		if len(list) != 17 || list[16] != float64(-1) {
			t.Errorf("%s: longList = %v", name, list)
		}
	}
}

func TestParsePlistNeverPanicsOnDamage(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "plist", "claude-managed.bplist"))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(b); n++ {
		_, _ = parsePlist(b[:n])
	}
	for i := range b {
		for _, x := range []byte{0x00, 0xFF, 0x0F, 0xDF} {
			bad := append([]byte(nil), b...)
			bad[i] = x
			_, _ = parsePlist(bad)
		}
	}
	if _, err := parsePlist([]byte("<plist><dict><string>orphan</string></dict></plist>")); err == nil {
		t.Error("a dict value with no key is malformed")
	}
}

func managedEnv(t *testing.T) Env {
	t.Helper()
	env := postureTestEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "settings.json"),
		`{"permissions": {"defaultMode": "bypassPermissions"}}`)
	return env
}

func bypassFinding(items []Item) Item {
	return postureByKey(items)[postureKey{"claude-code", "bypass_default", "user"}]
}

func TestAnMDMProfileThatRefusesBypassIsSeen(t *testing.T) {
	env := managedEnv(t)
	prefs := filepath.Join(t.TempDir(), "com.anthropic.claudecode.plist")
	b, _ := os.ReadFile(filepath.Join("testdata", "plist", "claude-managed.bplist"))
	writePostureFile(t, prefs, string(b))
	env.ManagedPrefs = []string{prefs}

	items := Scan(env)
	if it := bypassFinding(items); it.Severity != Info {
		t.Errorf("the MDM profile refuses bypass: %v", it)
	}
	got := postureByKey(items)
	if it := got[postureKey{"claude-code", "bypass_default", "managed"}]; it.Location != prefs {
		t.Errorf("the profile's own defaultMode is reported where it is: %v", it)
	}
	if !has(got, postureKey{"claude-code", "shell_allowed", "managed"}) {
		t.Error("the profile's Bash(*) rule is reported")
	}
	for k := range got {
		if k.check == "no_sandbox" {
			t.Error("the profile turns the sandbox on")
		}
	}
}

func TestOnlyTheSelectedAdminSourceApplies(t *testing.T) {
	env := managedEnv(t)
	writePostureFile(t, filepath.Join(env.Home, ".claude", "remote-settings.json"),
		`{"permissions": {"defaultMode": "acceptEdits"}}`)
	writePostureFile(t, filepath.Join(env.ManagedDir, "managed-settings.json"),
		`{"permissions": {"disableBypassPermissionsMode": "disable"}}`)

	if it := bypassFinding(Scan(env)); it.Severity != Dangerous {
		t.Errorf("server-managed settings win, and they do not refuse bypass: %v", it)
	}

	writePostureFile(t, filepath.Join(env.Home, ".claude", "remote-settings.json"),
		`{"managedSourcesBehavior": "merge", "permissions": {"defaultMode": "acceptEdits"}}`)
	if it := bypassFinding(Scan(env)); it.Severity != Info {
		t.Errorf("merged, the file's refusal applies: %v", it)
	}

	writePostureFile(t, filepath.Join(env.Home, ".claude", "remote-settings.json"),
		`{"managedSourcesBehavior": "first-wins"}`)
	if it := bypassFinding(Scan(env)); it.Severity != Info {
		t.Errorf("a source with no policy key is passed over: %v", it)
	}
}

func TestTheRegistryIsAnAdminSourceAndHKCUAFallback(t *testing.T) {
	env := managedEnv(t)
	policies := map[string]map[string]any{}
	env.Registry = func(hive string) map[string]any { return policies[hive] }

	policies["HKCU"] = parseRegistrySettings(`{"permissions": {"disableBypassPermissionsMode": "disable"}}`)
	if it := bypassFinding(Scan(env)); it.Severity != Info {
		t.Errorf("with no admin source, HKCU applies: %v", it)
	}

	policies["HKLM"] = parseRegistrySettings(`{"sandbox": {"enabled": true}}`)
	items := Scan(env)
	if it := bypassFinding(items); it.Severity != Dangerous {
		t.Errorf("HKCU never applies beneath an admin source: %v", it)
	}
	for _, it := range items {
		if it.Check == "no_sandbox" {
			t.Errorf("HKLM turns the sandbox on: %v", it)
		}
	}
}

func TestParseRegistrySettingsRejectsNonObjects(t *testing.T) {
	for _, raw := range []string{"", "[]", "not json", `"string"`} {
		if parseRegistrySettings(raw) != nil {
			t.Errorf("%q parsed", raw)
		}
	}
	if m := parseRegistrySettings(`{"a": 1, }`); m == nil || !strings.Contains(strings.Join(sortedMapKeys(m), ","), "a") {
		t.Errorf("trailing comma rejected: %v", m)
	}
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
