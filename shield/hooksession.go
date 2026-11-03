package shield

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Some clients put nothing in a command's env that names its session (Gemini
// CLI, OpenClaw), while their hook is told it. So the hook leaves the session
// where the shim will look for it a moment later: keyed by agent and working
// directory, under ~/.golem, which a jailed command can't write.

const hookSessionMaxAge = time.Hour

var hookSessionRE = regexp.MustCompile(`^[\w\-.:]{1,255}$`)

func hookSessionPath(home, agent, cwd string) string {
	sum := sha256.Sum256([]byte(agent + "\x00" + filepath.Clean(cwd)))
	return filepath.Join(home, ".golem", "shield", "hook-sessions", hex.EncodeToString(sum[:12]))
}

// NoteHookSession records that agent's next command in cwd belongs to session,
// under the path as the client gave it and as the shim's getwd will see it.
func NoteHookSession(home, agent, cwd, session string) error {
	if !hookSessionRE.MatchString(session) || !hookSessionRE.MatchString(agent) || cwd == "" {
		return nil
	}
	dirs := []string{cwd}
	if real, err := filepath.EvalSymlinks(cwd); err == nil && real != filepath.Clean(cwd) {
		dirs = append(dirs, real)
	}
	for _, d := range dirs {
		p := hookSessionPath(home, agent, d)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, []byte(session), 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, p); err != nil {
			return err
		}
	}
	return nil
}

// HookSession is the session NoteHookSession left for agent in cwd, or "".
func HookSession(home, agent, cwd string, now time.Time) string {
	p := hookSessionPath(home, agent, cwd)
	fi, err := os.Stat(p)
	if err != nil || now.Sub(fi.ModTime()) > hookSessionMaxAge {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if s := strings.TrimSpace(string(b)); hookSessionRE.MatchString(s) {
		return s
	}
	return ""
}
