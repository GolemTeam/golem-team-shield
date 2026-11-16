// Package jailshell tells whether a shell is the Golem jail's, and reads the
// shell Grok Bot's local-exec daemon runs on. It is apart from pkg/shield so
// golem-check's settings scan can use it without importing pkg/shield's
// network and exec code.
package jailshell

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ShimDir(home string) string { return filepath.Join(home, ".golem", "bin") }

// IsShim reports whether path is one of the shim's names under home.
func IsShim(home, goos, path string) bool {
	dir := ShimDir(home)
	if goos == "windows" {
		slash := func(p string) string { return strings.ReplaceAll(filepath.Clean(p), `\`, "/") }
		return strings.EqualFold(slash(path), slash(filepath.Join(dir, "bash.exe")))
	}
	return strings.HasPrefix(path, dir+string(filepath.Separator)+"golem-")
}

type GrokBotDaemon struct {
	PID int
	// Inflight is the daemon's inflightCount, or -1 when its file doesn't say.
	Inflight int
	Shell    string
}

// The app sets this on the daemon and the daemon never clears it, so a pid
// the daemon file names but another program now holds is told apart.
const grokBotDaemonMarker = "SAND_LOCAL_EXEC_GENERATION"

func GrokBotDaemonFile(home string) string {
	return filepath.Join(home, ".grokbot", "local-exec-daemon.json")
}

// ReadGrokBotDaemon reads the daemon running for the user at home. ok is
// false when none runs, or its environment can't be read.
func ReadGrokBotDaemon(home string, environ func(pid int) ([]string, bool)) (d GrokBotDaemon, ok bool) {
	if environ == nil || home == "" {
		return d, false
	}
	f, err := os.Open(GrokBotDaemonFile(home))
	if err != nil {
		return d, false
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	f.Close()
	if err != nil {
		return d, false
	}
	var st struct {
		PID      int  `json:"pid"`
		Inflight *int `json:"inflightCount"`
	}
	if json.Unmarshal(b, &st) != nil || st.PID <= 1 {
		return d, false
	}
	env, read := environ(st.PID)
	if !read {
		return d, false
	}
	d.PID, d.Inflight = st.PID, -1
	if st.Inflight != nil {
		d.Inflight = *st.Inflight
	}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "SHELL":
			d.Shell = v
		case grokBotDaemonMarker:
			ok = true
		}
	}
	return d, ok
}
