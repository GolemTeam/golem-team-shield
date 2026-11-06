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

// NetMode says how an allowlisted network was held.
type NetMode string

const (
	NetSeatbelt NetMode = "seatbelt"
	// NetNamespace: a network namespace where only the proxy answers (Linux).
	NetNamespace NetMode = "namespace"
	// NetLandlockPort: Landlock allowed TCP to the proxy's port and nothing
	// else, so a program ignoring the proxy can reach any host on that port.
	NetLandlockPort NetMode = "landlock-port"
	// NetNone: no way to confine it to the proxy, so no network at all.
	NetNone NetMode = "none"
	// NetAdvisory: the proxy variables only; nothing refuses a program that
	// ignores them (Windows without the shield's firewall).
	NetAdvisory NetMode = "advisory"
	// NetFirewall: the shield's Windows Filtering Platform filters.
	NetFirewall NetMode = "firewall"
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
	// Writes is "workspace" when the jail kept a clean session's writes to
	// its roots (on Windows, through a low-integrity shell). "deny-list" is
	// what an older Windows shim, which couldn't, reported.
	Writes string `json:"writes,omitempty"`
	// Net is how an allowlisted network was held; Egress what the proxy saw,
	// and EgressOverflow how many more distinct requests it only counted.
	Net            NetMode        `json:"net,omitempty"`
	Egress         []EgressRecord `json:"egress,omitempty"`
	EgressOverflow int            `json:"egress_overflow,omitempty"`
	// Files is "held" when the agents' project files were bound read-only in
	// the command's mount namespace (Linux).
	Files string `json:"files,omitempty"`
}

const FilesHeld = "held"
