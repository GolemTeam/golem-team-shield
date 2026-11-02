package agentposture

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

const vscdbFixture = "testdata/vscdb/state.vscdb"

func TestReadItemTableFollowsInteriorPagesAndOverflow(t *testing.T) {
	got, err := readItemTable(vscdbFixture, map[string]bool{
		cursorStateKey: true, antigravityPrefsKey: true, "filler.0123": true, "missing": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ComposerState map[string]any `json:"composerState"`
	}
	if err := json.Unmarshal(got[cursorStateKey], &doc); err != nil {
		t.Fatalf("the overflowed Cursor state does not decode: %v", err)
	}
	if pad, _ := doc.ComposerState["padding"].(string); len(pad) != 6000 {
		t.Errorf("padding = %d bytes, want 6000", len(pad))
	}
	if string(got["filler.0123"]) != "xxx" {
		t.Errorf("filler.0123 = %q", got["filler.0123"])
	}
	if _, ok := got["missing"]; ok {
		t.Error("a missing key was found")
	}
	if v, ok := antigravityPreference(got[antigravityPrefsKey], antigravityExecKey); !ok || v != 3 {
		t.Errorf("Antigravity auto-execution = %d, %v; want 3 (eager)", v, ok)
	}
}

func TestReadItemTableNeverPanicsOnDamage(t *testing.T) {
	b, err := os.ReadFile(vscdbFixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.vscdb")
	try := func(data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = readItemTable(path, map[string]bool{cursorStateKey: true})
	}
	for n := 0; n < len(b); n += 97 {
		try(b[:n])
	}
	for i := 0; i < len(b); i += 37 {
		bad := append([]byte(nil), b...)
		bad[i] ^= 0xFF
		try(bad)
	}
}

func TestEditorStateReportsCursorAndAntigravityRunModes(t *testing.T) {
	env := postureTestEnv(t)
	env.XDG = filepath.Join(env.Home, "xdg")
	b, err := os.ReadFile(vscdbFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"Cursor", "Antigravity"} {
		writePostureFile(t, filepath.Join(env.XDG, app, "User", "globalStorage", "state.vscdb"), string(b))
	}
	got := postureByKey(Scan(env))
	if it := got[postureKey{"cursor", "run_everything", "user"}]; it.Severity != Dangerous || it.Value != "run-everything" {
		t.Errorf("Cursor IDE run everything = %v", it)
	}
	if it := got[postureKey{"antigravity", "auto_execution", "user"}]; it.Severity != Dangerous || it.Value != "eager" {
		t.Errorf("Antigravity eager = %v", it)
	}
}

func agPrefs(key string, policy uint64) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 2, protowire.VarintType)
	inner = protowire.AppendVarint(inner, policy)
	var val []byte
	val = protowire.AppendTag(val, 1, protowire.BytesType)
	val = protowire.AppendString(val, base64.StdEncoding.EncodeToString(inner))
	var entry []byte
	entry = protowire.AppendTag(entry, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, key)
	entry = protowire.AppendTag(entry, 2, protowire.BytesType)
	entry = protowire.AppendBytes(entry, val)
	var outer []byte
	outer = protowire.AppendTag(outer, 1, protowire.BytesType)
	outer = protowire.AppendBytes(outer, entry)
	return []byte(base64.StdEncoding.EncodeToString(outer))
}

func TestAntigravityExecutionLevels(t *testing.T) {
	for _, c := range []struct {
		policy  uint64
		sev     string
		reports bool
	}{
		{1, "", false}, {2, Info, true}, {3, Dangerous, true}, {4, Info, true}, {9, "", false},
	} {
		s := &scan{}
		s.antigravityExecution("state.vscdb", agPrefs(antigravityExecKey, c.policy))
		if (len(s.items) == 1) != c.reports || (c.reports && s.items[0].Severity != c.sev) {
			t.Errorf("policy %d: %v", c.policy, s.items)
		}
	}
	for _, raw := range [][]byte{nil, []byte("not base64!"), agPrefs("otherKey", 3), []byte(base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF}))} {
		if _, ok := antigravityPreference(raw, antigravityExecKey); ok {
			t.Errorf("%q decoded", raw)
		}
	}
}

func TestCursorRunModeNeedsTheAppsOwnKeys(t *testing.T) {
	for raw, want := range map[string]int{
		`{"composerState":{"yoloEnableRunEverything":true,"enableSmartAuto":false}}`:  1,
		`{"composerState":{"yoloEnableRunEverything":false,"enableSmartAuto":true}}`:  1,
		`{"composerState":{"yoloEnableRunEverything":false,"enableSmartAuto":false}}`: 0,
		`{"composerState":{"yoloEnableRunEverything":"yes"}}`:                         0,
		`not json`: 0,
	} {
		s := &scan{}
		s.cursorRunMode("state.vscdb", []byte(raw))
		if len(s.items) != want {
			t.Errorf("%s: %v", raw, s.items)
		}
	}
}
