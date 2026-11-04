package shield

// Attachments says how golem-exec, the free tool, and the Golem agent each put
// an agent's shell commands in the jail. Tests in golem-exec and the witness
// hold each product to its column, so the two can only differ where a row says
// why. The agent covers every client golem-exec does.
var Attachments = []Attachment{
	{Client: "claude-code", FreeTool: AttachShell, Agent: AttachShell},
	{Client: "codex", FreeTool: AttachHook, Agent: AttachHook},
	{Client: "gemini-cli", FreeTool: AttachHook, Agent: AttachHook},
	{Client: "cursor", FreeTool: AttachHook, Agent: AttachHook},
	{Client: "copilot", FreeTool: AttachHook, Agent: AttachHook},
	{Client: "devin", FreeTool: AttachHook, Agent: AttachHook, PastApproval: true},
	{Client: "antigravity", Agent: AttachHook, Why: "Antigravity's hook must answer a decision, and any golem-exec gave would change whether it asks; the agent's hook already answers one"},
	{Client: "hermes", Agent: AttachPlugin, Why: "the jail reaches Hermes through the Golem plugin, which only the agent installs"},
	{Client: "openclaw", Agent: AttachPlugin, Why: "the jail reaches OpenClaw through the Golem plugin, which only the agent installs"},
	{Client: "vscode", Agent: AttachProfile, PastApproval: true, Why: "the profile is a setting in VS Code's settings.json, which holds the person's comments, and only the agent's editor keeps them"},
}

type Attachment struct {
	Client   string
	FreeTool string
	Agent    string
	Why      string
	// PastApproval: attached only with jail_past_approval, as the client's
	// own approval would see only the jail (JailsPastApproval).
	PastApproval bool
}

const (
	AttachShell  = "shell setting"
	AttachHook   = "pre-tool hook"
	AttachPlugin = "Golem plugin"
	// AttachProfile names the shim as the shell of the terminals the agent
	// runs its commands in.
	AttachProfile = "terminal profile"
)

// FreeHookClients are the clients golem-exec answers `golem-exec hook` for.
func FreeHookClients() []string {
	var out []string
	for _, a := range Attachments {
		if a.FreeTool == AttachHook {
			out = append(out, a.Client)
		}
	}
	return out
}
