package main

import (
	"time"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// clientSessionVars are the variables a client sets in its commands' env that
// name the session (docs/design-local-shield.md, Other clients).
var clientSessionVars = []struct{ env, agent string }{
	{"CLAUDE_CODE_SESSION_ID", "claude-code"},
	{"CODEX_THREAD_ID", "codex"},
	{"CURSOR_CONVERSATION_ID", "cursor"},
	{"COPILOT_AGENT_SESSION_ID", "copilot"},
	{"HERMES_SESSION_ID", "hermes"},
}

// clientMarkers name the agent for clients that set no session variable.
var clientMarkers = []struct{ env, value, agent string }{
	{"CLAUDECODE", "1", "claude-code"},
	{"GEMINI_CLI", "1", "gemini-cli"},
	{"OPENCLAW_SHELL", "exec", "openclaw"},
	{"CURSOR_AGENT", "1", "cursor"},
	{"COPILOT_CLI", "1", "copilot"},
	{"ANTIGRAVITY_AGENT", "1", "antigravity"},
}

// sessionFromEnv names the session and agent a command belongs to, so its
// taint follows it: the client's own session variable, or for a client that
// sets none, what its hook noted for this directory. A command it can tie to
// no session gets the machine's policy.
func sessionFromEnv(getenv func(string) string, home, cwd string, now time.Time) (sessionID, agentID string) {
	// Copilot CLI's hook names the session the Golem agent knows; whether its
	// commands' variable is the same id is not established, so the note wins.
	if getenv("COPILOT_AGENT_SESSION_ID") != "" || getenv("COPILOT_CLI") == "1" {
		if id := shield.HookSession(home, "copilot", cwd, now); id != "" {
			return id, "copilot"
		}
	}
	for _, v := range clientSessionVars {
		if id := getenv(v.env); sessionIDRE.MatchString(id) {
			return id, v.agent
		}
	}
	for _, m := range clientMarkers {
		if getenv(m.env) == m.value {
			return shield.HookSession(home, m.agent, cwd, now), m.agent
		}
	}
	return "", ""
}
