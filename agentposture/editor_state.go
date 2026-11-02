package agentposture

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protowire"
)

// Cursor and Antigravity keep the run mode their settings screens show in the
// editor's own state database, not in settings.json. The keys and encodings are
// undocumented: they were read off the apps (Cursor's as cursor-hook.sh reads
// it; Antigravity's enum from the descriptor in its language server, where
// CASCADE_COMMANDS_AUTO_EXECUTION_ OFF=1, AUTO=2, EAGER=3,
// PROCEED_IN_SANDBOX=4). Anything that does not decode as expected reports
// nothing rather than a guess.

const (
	cursorStateKey      = "src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl.persistentStorage.applicationUser"
	antigravityPrefsKey = "antigravityUnifiedStateSync.agentPreferences"
	antigravityExecKey  = "terminalAutoExecutionPolicySentinelKey"
)

func (s *scan) editorStatePath(app string) string {
	base := s.editorBase()
	if base == "" {
		return ""
	}
	return filepath.Join(base, app, "User", "globalStorage", "state.vscdb")
}

func (s *scan) editorState() {
	if path := s.editorStatePath("Cursor"); path != "" {
		if v, err := readItemTable(path, map[string]bool{cursorStateKey: true}); err == nil {
			s.cursorRunMode(path, v[cursorStateKey])
		}
	}
	if path := s.editorStatePath("Antigravity"); path != "" {
		if v, err := readItemTable(path, map[string]bool{antigravityPrefsKey: true}); err == nil {
			s.antigravityExecution(path, v[antigravityPrefsKey])
		}
	}
}

func (s *scan) cursorRunMode(path string, raw []byte) {
	var doc struct {
		ComposerState map[string]any `json:"composerState"`
	}
	if raw == nil || json.Unmarshal(raw, &doc) != nil {
		return
	}
	everything, ok1 := doc.ComposerState["yoloEnableRunEverything"].(bool)
	smart, ok2 := doc.ComposerState["enableSmartAuto"].(bool)
	if !ok1 || !ok2 {
		return
	}
	switch {
	case everything:
		s.add("cursor", "run_everything", Dangerous, "user", path, "run mode", "run-everything",
			"Cursor runs every command without asking")
	case smart:
		s.add("cursor", "auto_review", Info, "user", path, "run mode", "auto-review",
			"Cursor lets a model approve commands instead of asking")
	}
}

func (s *scan) antigravityExecution(path string, raw []byte) {
	policy, ok := antigravityPreference(raw, antigravityExecKey)
	if !ok {
		return
	}
	switch policy {
	case 3:
		s.add("antigravity", "auto_execution", Dangerous, "user", path, "terminal auto-execution", "eager",
			"Antigravity runs every terminal command without asking")
	case 2:
		s.add("antigravity", "auto_execution", Info, "user", path, "terminal auto-execution", "auto",
			"Antigravity's agent decides which terminal commands run without asking")
	case 4:
		s.add("antigravity", "auto_execution", Info, "user", path, "terminal auto-execution", "proceed-in-sandbox",
			"Antigravity runs terminal commands without asking, inside its sandbox")
	}
}

// antigravityPreference reads one enum out of the preferences blob: base64 of
// a message of entries {1: key, 2: {1: base64 of a message whose field 2 is the
// value}}.
func antigravityPreference(raw []byte, key string) (uint64, bool) {
	blob, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return 0, false
	}
	for _, entry := range protoBytesFields(blob, 1) {
		if string(firstProtoBytes(entry, 1)) != key {
			continue
		}
		inner, err := base64.StdEncoding.DecodeString(string(firstProtoBytes(firstProtoBytes(entry, 2), 1)))
		if err != nil {
			return 0, false
		}
		return firstProtoVarint(inner, 2)
	}
	return 0, false
}

func protoBytesFields(b []byte, field protowire.Number) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out
		}
		b = b[n:]
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return out
		}
		if num == field && typ == protowire.BytesType {
			if v, k := protowire.ConsumeBytes(b); k >= 0 {
				out = append(out, v)
			}
		}
		b = b[m:]
	}
	return out
}

func firstProtoBytes(b []byte, field protowire.Number) []byte {
	if v := protoBytesFields(b, field); len(v) > 0 {
		return v[0]
	}
	return nil
}

func firstProtoVarint(b []byte, field protowire.Number) (uint64, bool) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return 0, false
		}
		b = b[n:]
		if num == field && typ == protowire.VarintType {
			v, k := protowire.ConsumeVarint(b)
			return v, k >= 0
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return 0, false
		}
		b = b[m:]
	}
	return 0, false
}
