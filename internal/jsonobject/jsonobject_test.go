package jsonobject

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnEditKeepsKeyOrderAndUntouchedValues(t *testing.T) {
	doc, err := Parse([]byte(`{"z": 1, "lastSeen": 1786000000000, "a": {"keep": [1, 2]}}`))
	if err != nil {
		t.Fatal(err)
	}
	doc.Set("m", json.RawMessage(`"new"`))
	doc.Set("z", json.RawMessage(`2`))
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"z":2,"lastSeen":1786000000000,"a":{"keep":[1,2]},"m":"new"}`; string(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

func TestRemoveAndEmpty(t *testing.T) {
	doc := New()
	doc.Set("a", json.RawMessage(`1`))
	doc.Remove("missing")
	doc.Remove("a")
	if !doc.Empty() {
		t.Error("an object with its only key removed is empty")
	}
	if _, ok := doc.Get("a"); ok {
		t.Error("a removed key is still there")
	}
}

func TestADuplicateKeyKeepsItsPlaceAndTakesTheLastValue(t *testing.T) {
	doc, err := Parse([]byte(`{"a": 1, "b": 2, "a": 3}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(doc)
	if string(out) != `{"a":3,"b":2}` {
		t.Errorf("got %s", out)
	}
}

func TestParseRefusesWhatIsNotAnObject(t *testing.T) {
	for _, in := range []string{`[1]`, `"x"`, `{"a": 1`, `{1: 2}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%s) accepted", in)
		}
	}
}

func TestFilesRoundTripPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dir", "settings.json")
	doc, existed, err := ReadFile(path)
	if err != nil || existed || !doc.Empty() {
		t.Fatalf("a missing file: %v, existed=%v", err, existed)
	}
	doc.Set("env", json.RawMessage(`{"A":"1"}`))
	if err := WriteFile(path, doc); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "\n  \"env\": {\n    \"A\": \"1\"\n  }\n") {
		t.Errorf("not indented: %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	back, existed, err := ReadFile(path)
	if err != nil || !existed {
		t.Fatalf("read back: %v", err)
	}
	if v, _ := back.Get("env"); string(v) == "" {
		t.Error("the value did not survive")
	}
}
