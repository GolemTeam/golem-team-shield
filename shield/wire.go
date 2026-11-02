package shield

// PolicyRequest is what the shim sends the witness before a command runs.
// RunTag goes first, so the witness can attribute the kernel's denials to the
// run even if the shim never reports back.
type PolicyRequest struct {
	SessionID string `json:"session_id"`
	AgentID   string `json:"agent_id,omitempty"`
	RunTag    string `json:"run_tag"`
	CWD       string `json:"cwd,omitempty"`
}

// Jail says what actually held the command.
type Jail string

const (
	JailSeatbelt Jail = "seatbelt"
	// JailLandlock: Landlock and a seccomp socket filter (Linux).
	JailLandlock Jail = "landlock"
	// JailToken: a restricted token and deny entries for its SID (Windows).
	JailToken Jail = "restricted-token"
	// JailHost: the agent's own sandbox already held the process (Seatbelt
	// doesn't nest), so the shield filtered the environment only.
	JailHost Jail = "host"
	// JailOff: the workspace switched the shield off.
	JailOff Jail = "off"
	// JailNone: no engine on this platform yet.
	JailNone Jail = "none"
)

// RunRecord is what the shim reports after the command exits. It never
// carries output or environment values, only names and hashes.
type RunRecord struct {
	SessionID   string   `json:"session_id"`
	AgentID     string   `json:"agent_id,omitempty"`
	RunTag      string   `json:"run_tag"`
	Jail        Jail     `json:"jail"`
	State       State    `json:"state"`
	Grants      Grants   `json:"grants"`
	PolicyHash  string   `json:"policy_hash,omitempty"`
	FromWitness bool     `json:"from_witness"`
	ExitCode    int      `json:"exit_code"`
	DurationMS  int64    `json:"duration_ms"`
	DroppedEnv  []string `json:"dropped_env,omitempty"`
}
