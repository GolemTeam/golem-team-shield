package main

import (
	"testing"
	"time"

	"github.com/GolemTeam/golem-team-shield/shield"
)

func TestSessionFromEnv(t *testing.T) {
	home, cwd, now := t.TempDir(), "/work/repo", time.Now()
	if err := shield.NoteHookSession(home, "gemini-cli", cwd, "gem-1"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		env           map[string]string
		session, agnt string
	}{
		{"Claude Code's shell", map[string]string{"CLAUDE_CODE_SESSION_ID": "c1", "CLAUDECODE": "1"}, "c1", "claude-code"},
		{"Codex", map[string]string{"CODEX_THREAD_ID": "019a-t"}, "019a-t", "codex"},
		{"Cursor", map[string]string{"CURSOR_CONVERSATION_ID": "cv", "CURSOR_AGENT": "1"}, "cv", "cursor"},
		{"Copilot CLI", map[string]string{"COPILOT_AGENT_SESSION_ID": "cp", "COPILOT_CLI": "1"}, "cp", "copilot"},
		{"Hermes", map[string]string{"HERMES_SESSION_ID": "h1"}, "h1", "hermes"},
		{"Gemini CLI, from its hook's note", map[string]string{"GEMINI_CLI": "1"}, "gem-1", "gemini-cli"},
		{"OpenClaw with no note", map[string]string{"OPENCLAW_SHELL": "exec"}, "", "openclaw"},
		{"Claude Code with no session", map[string]string{"CLAUDECODE": "1"}, "", "claude-code"},
		{"an invalid session is none", map[string]string{"CODEX_THREAD_ID": "a b"}, "", ""},
		{"nothing", map[string]string{}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a := sessionFromEnv(func(k string) string { return tc.env[k] }, home, cwd, now)
			if s != tc.session || a != tc.agnt {
				t.Fatalf("got (%q, %q), want (%q, %q)", s, a, tc.session, tc.agnt)
			}
		})
	}
	if s, _ := sessionFromEnv(func(k string) string { return map[string]string{"GEMINI_CLI": "1"}[k] }, home, "/elsewhere", now); s != "" {
		t.Fatalf("a note for one directory named the session in another: %q", s)
	}
	if s, _ := sessionFromEnv(func(k string) string { return map[string]string{"GEMINI_CLI": "1"}[k] }, home, cwd, now.Add(2*time.Hour)); s != "" {
		t.Fatalf("a stale note still named the session: %q", s)
	}
}
