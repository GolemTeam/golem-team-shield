package checkcmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

func TestPinMergesAndKeepsTheFileOwnerOnly(t *testing.T) {
	home := t.TempDir()
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if err := writePins(home, map[string]agentposture.LivePin{"a": {Pinned: day, Tools: map[string]string{}}}); err != nil {
		t.Fatal(err)
	}
	if err := writePins(home, map[string]agentposture.LivePin{"b": {Pinned: day, Tools: map[string]string{}}}); err != nil {
		t.Fatal(err)
	}
	got, ok := agentposture.ReadLivePins(home)
	if _, a := got.Servers["a"]; !ok || !a || len(got.Servers) != 2 {
		t.Errorf("a later pin must keep the servers it did not read: %+v", got)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(agentposture.LivePinsPath(home))
		dir, _ := os.Stat(filepath.Dir(agentposture.LivePinsPath(home)))
		if fi.Mode().Perm() != 0o600 || dir.Mode().Perm() != 0o700 {
			t.Errorf("modes %v %v", fi.Mode().Perm(), dir.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(agentposture.LivePinsPath(home)))
	if len(entries) != 1 {
		t.Errorf("a temp file was left behind: %v", entries)
	}
}

func TestPinNeverReplacesAFileItCannotRead(t *testing.T) {
	home := t.TempDir()
	path := agentposture.LivePinsPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePins(home, map[string]agentposture.LivePin{"a": {}}); err == nil {
		t.Error("an unreadable pin file was replaced")
	}
	if b, _ := os.ReadFile(path); string(b) != "{broken" {
		t.Errorf("file now %q", b)
	}
	if runtime.GOOS == "windows" {
		return
	}
	other := filepath.Join(home, "elsewhere.json")
	if err := os.WriteFile(other, []byte(`{"version":1,"servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if err := writePins(home, map[string]agentposture.LivePin{"a": {}}); err == nil {
		t.Error("the pin file was written through a symbolic link")
	}
}

func TestPinGoesWithLiveTools(t *testing.T) {
	var errs bytes.Buffer
	code := Run([]string{"-pin"}, io.Discard, &errs, Options{Name: "golem-check", Machine: func(agentposture.LiveReader) agentposture.Result { return agentposture.Result{} }})
	if code != 2 || !strings.Contains(errs.String(), "goes with -live-tools") {
		t.Errorf("exit %d: %s", code, errs.String())
	}
}
