// Package attacktech is the technique vocabulary shared by the deterministic
// floor, the analyst, and anything that exports a finding.
//
// It exists because the mapping was already written — db/033 cites "MITRE ATLAS
// v5.1", T1098, T1053, T1546 — but only inside description prose, where nothing
// can query it, aggregate it, or hand it to a customer's SIEM. A taxonomy that
// cannot be queried is not a taxonomy.
//
// The catalogue is DELIBERATELY PARTIAL. ATLAS carries roughly 84 techniques and
// this holds the handful sourced against published pages, because an ID invented to
// fill a gap is worse than no ID at all: free text reads as a guess, whereas an
// AML.T identifier in a SIEM dashboard reads as a fact. Adding an entry means citing
// where the ID came from.
package attacktech

import (
	"fmt"
	"sort"
)

// Framework separates the two matrices, which cover different layers and must not
// be conflated: ATT&CK describes what happens to a host, ATLAS what happens to an
// AI system. A credential-file read is ATT&CK; an indirect prompt injection has no
// ATT&CK technique at all.
type Framework string

const (
	ATLAS  Framework = "atlas"
	ATTACK Framework = "attack"
)

// Technique is one entry in the vocabulary.
type Technique struct {
	ID        string
	Name      string
	Framework Framework
	// Tactic is the matrix column, kept as free text because ATT&CK and ATLAS name
	// their tactics differently and forcing one enum over both would invent a
	// mapping neither publishes.
	Tactic string
	// Source is where the ID and name were read from. Required: an entry nobody can
	// check is how a fabricated ID enters a customer's dashboard.
	Source string
}

var catalogue = []Technique{
	{
		ID: "AML.T0051", Name: "LLM Prompt Injection", Framework: ATLAS,
		Tactic: "Initial Access",
		Source: "atlas.mitre.org/techniques/AML.T0051",
	},
	{
		ID: "AML.T0051.000", Name: "Direct Prompt Injection", Framework: ATLAS,
		Tactic: "Initial Access",
		Source: "atlas.mitre.org/techniques/AML.T0051.000",
	},
	{
		ID: "AML.T0051.001", Name: "Indirect Prompt Injection via Retrieved Content",
		Framework: ATLAS, Tactic: "Initial Access",
		Source: "atlas.mitre.org/techniques/AML.T0051.001",
	},
	{
		ID: "AML.T0053", Name: "LLM Plugin Compromise", Framework: ATLAS,
		Tactic: "Execution",
		Source: "atlas.mitre.org/techniques/AML.T0053",
	},
	{
		ID: "AML.T0024", Name: "Exfiltration via AI Inference API", Framework: ATLAS,
		Tactic: "Exfiltration",
		Source: "atlas.mitre.org/techniques/AML.T0024",
	},
	{
		ID: "T1053", Name: "Scheduled Task/Job", Framework: ATTACK,
		Tactic: "Persistence",
		Source: "attack.mitre.org/techniques/T1053 — cited by db/033 cron rule",
	},
	{
		ID: "T1098", Name: "Account Manipulation", Framework: ATTACK,
		Tactic: "Persistence",
		Source: "attack.mitre.org/techniques/T1098 — cited by db/033 authorized_keys rule",
	},
	{
		ID: "T1546", Name: "Event Triggered Execution", Framework: ATTACK,
		Tactic: "Persistence",
		Source: "attack.mitre.org/techniques/T1546 — cited by db/033 authorized_keys rule",
	},
	{
		ID: "T1552", Name: "Unsecured Credentials", Framework: ATTACK,
		Tactic: "Credential Access",
		Source: "attack.mitre.org/techniques/T1552 — the credential-file read, the most common signature finding, and it was missing",
	},
	{
		ID: "T1552.001", Name: "Credentials In Files", Framework: ATTACK,
		Tactic: "Credential Access",
		Source: "attack.mitre.org/techniques/T1552/001",
	},
	{
		ID: "T1552.004", Name: "Private Keys", Framework: ATTACK,
		Tactic: "Credential Access",
		Source: "attack.mitre.org/techniques/T1552/004",
	},
	{
		ID: "T1083", Name: "File and Directory Discovery", Framework: ATTACK,
		Tactic: "Discovery",
		Source: "attack.mitre.org/techniques/T1083 — the recon an agent does before it reads",
	},
	{
		ID: "T1005", Name: "Data from Local System", Framework: ATTACK,
		Tactic: "Collection",
		Source: "attack.mitre.org/techniques/T1005",
	},
	{
		ID: "T1119", Name: "Automated Collection", Framework: ATTACK,
		Tactic: "Collection",
		Source: "attack.mitre.org/techniques/T1119",
	},
	{
		ID: "T1059", Name: "Command and Scripting Interpreter", Framework: ATTACK,
		Tactic: "Execution",
		Source: "attack.mitre.org/techniques/T1059",
	},
	{
		ID: "T1059.004", Name: "Unix Shell", Framework: ATTACK,
		Tactic: "Execution",
		Source: "attack.mitre.org/techniques/T1059/004",
	},
	{
		ID: "T1567", Name: "Exfiltration Over Web Service", Framework: ATTACK,
		Tactic: "Exfiltration",
		Source: "attack.mitre.org/techniques/T1567 — the curl POST half of read-then-send",
	},
	{
		ID: "T1567.002", Name: "Exfiltration to Cloud Storage", Framework: ATTACK,
		Tactic: "Exfiltration",
		Source: "attack.mitre.org/techniques/T1567/002",
	},
	{
		ID: "T1105", Name: "Ingress Tool Transfer", Framework: ATTACK,
		Tactic: "Command and Control",
		Source: "attack.mitre.org/techniques/T1105 — curl piped to a shell",
	},
	{
		ID: "T1027", Name: "Obfuscated Files or Information", Framework: ATTACK,
		Tactic: "Defense Evasion",
		Source: "attack.mitre.org/techniques/T1027 — encoding a payload before sending it",
	},
	{
		ID: "T1070", Name: "Indicator Removal", Framework: ATTACK,
		Tactic: "Defense Evasion",
		Source: "attack.mitre.org/techniques/T1070",
	},
	{
		ID: "T1070.003", Name: "Clear Command History", Framework: ATTACK,
		Tactic: "Defense Evasion",
		Source: "attack.mitre.org/techniques/T1070/003",
	},
	{
		ID: "T1562", Name: "Impair Defenses", Framework: ATTACK,
		Tactic: "Defense Evasion",
		Source: "attack.mitre.org/techniques/T1562 — an agent disabling the hooks that observe it",
	},
	{
		ID: "T1562.001", Name: "Disable or Modify Tools", Framework: ATTACK,
		Tactic: "Defense Evasion",
		Source: "attack.mitre.org/techniques/T1562/001",
	},
	{
		ID: "T1195", Name: "Supply Chain Compromise", Framework: ATTACK,
		Tactic: "Initial Access",
		Source: "attack.mitre.org/techniques/T1195",
	},
	{
		ID: "T1195.001", Name: "Compromise Software Dependencies and Development Tools", Framework: ATTACK,
		Tactic: "Initial Access",
		Source: "attack.mitre.org/techniques/T1195/001 — installing a dependency nobody asked for",
	},
	{
		ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Framework: ATTACK,
		Tactic: "Exfiltration",
		Source: "attack.mitre.org/techniques/T1048 — a command that sends data out over the network",
	},
	{
		ID: "T1485", Name: "Data Destruction", Framework: ATTACK,
		Tactic: "Impact",
		Source: "attack.mitre.org/techniques/T1485 — rm -rf and its relatives",
	},
	{
		ID: "T1548.003", Name: "Sudo and Sudo Caching", Framework: ATTACK,
		Tactic: "Privilege Escalation",
		Source: "attack.mitre.org/techniques/T1548/003",
	},
	{
		ID: "T1053.003", Name: "Cron", Framework: ATTACK,
		Tactic: "Persistence",
		Source: "attack.mitre.org/techniques/T1053/003",
	},
	{
		ID: "T1546.004", Name: "Unix Shell Configuration Modification", Framework: ATTACK,
		Tactic: "Persistence",
		Source: "attack.mitre.org/techniques/T1546/004 — writing to ~/.bashrc, ~/.zshrc and similar",
	},
	{
		ID: "T1543.001", Name: "Launch Agent", Framework: ATTACK,
		Tactic: "Persistence",
		Source: "attack.mitre.org/techniques/T1543/001",
	},
	{
		ID: "T1598.003", Name: "Phishing for Information: Spearphishing Link", Framework: ATTACK,
		Tactic: "Reconnaissance",
		Source: "attack.mitre.org/techniques/T1598/003 — a link to a page that asks for credentials",
	},
	{
		ID: "T1566.002", Name: "Phishing: Spearphishing Link", Framework: ATTACK,
		Tactic: "Initial Access",
		Source: "attack.mitre.org/techniques/T1566/002 — a link that delivers a payload",
	},
	{
		ID: "T1608.005", Name: "Stage Capabilities: Link Target", Framework: ATTACK,
		Tactic: "Resource Development",
		Source: "attack.mitre.org/techniques/T1608/005 — the lure page a phishing link points to",
	},
	{
		ID: "T1584.004", Name: "Compromise Infrastructure: Server", Framework: ATTACK,
		Tactic: "Resource Development",
		Source: "attack.mitre.org/techniques/T1584/004 — a lure hosted on someone else's hacked site",
	},
	{
		ID: "T1583.001", Name: "Acquire Infrastructure: Domains", Framework: ATTACK,
		Tactic: "Resource Development",
		Source: "attack.mitre.org/techniques/T1583/001",
	},
	{
		ID: "T1557", Name: "Adversary-in-the-Middle", Framework: ATTACK,
		Tactic: "Credential Access",
		Source: "attack.mitre.org/techniques/T1557 — a phishing site relaying the real sign-in to take the session",
	},
	{
		ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", Framework: ATTACK,
		Tactic: "Initial Access",
		Source: "attack.mitre.org/techniques/T1078/004 — a phished sign-in being used",
	},
	{
		ID: "T1114.003", Name: "Email Collection: Email Forwarding Rule", Framework: ATTACK,
		Tactic: "Collection",
		Source: "attack.mitre.org/techniques/T1114/003",
	},
	{
		ID: "T1555.006", Name: "Credentials from Password Stores: Cloud Secrets Management Stores", Framework: ATTACK,
		Tactic: "Credential Access",
		Source: "attack.mitre.org/techniques/T1555/006 — a value read out of a cloud or Vault secret store",
	},
	{
		ID: "T1611", Name: "Escape to Host", Framework: ATTACK,
		Tactic: "Privilege Escalation",
		Source: "attack.mitre.org/techniques/T1611",
	},
	{
		ID: "T1609", Name: "Container Administration Command", Framework: ATTACK,
		Tactic: "Execution",
		Source: "attack.mitre.org/techniques/T1609 — running a command inside another workload",
	},
	{
		ID: "T1572", Name: "Protocol Tunneling", Framework: ATTACK,
		Tactic: "Command and Control",
		Source: "attack.mitre.org/techniques/T1572",
	},
	{
		ID: "T1548", Name: "Abuse Elevation Control Mechanism", Framework: ATTACK,
		Tactic: "Privilege Escalation",
		Source: "attack.mitre.org/techniques/T1548",
	},
	{
		ID: "T1496", Name: "Resource Hijacking", Framework: ATTACK,
		Tactic: "Impact",
		Source: "attack.mitre.org/techniques/T1496",
	},
	{
		ID: "T1489", Name: "Service Stop", Framework: ATTACK,
		Tactic: "Impact",
		Source: "attack.mitre.org/techniques/T1489",
	},
}

var byID = func() map[string]Technique {
	m := make(map[string]Technique, len(catalogue))
	for _, t := range catalogue {
		m[t.ID] = t
	}
	return m
}()

// Lookup returns the technique for an ID.
func Lookup(id string) (Technique, bool) {
	t, ok := byID[id]
	return t, ok
}

// Valid reports whether an ID is in the catalogue. The EMPTY string is valid:
// "no technique named" is an honest answer, and requiring one would push a
// classifier toward the nearest-looking label rather than none.
func Valid(id string) bool {
	if id == "" {
		return true
	}
	_, ok := byID[id]
	return ok
}

// Validate returns an error naming the offending ID, so a caller that guessed
// learns which guess was wrong rather than that something was.
func Validate(id string) error {
	if Valid(id) {
		return nil
	}
	return fmt.Errorf("unknown technique %q: add it to pkg/attacktech with a source, or leave it empty", id)
}

// All returns the catalogue sorted by ID, so a seed file and a report list it in
// the same order every time.
func All() []Technique {
	out := make([]Technique, len(catalogue))
	copy(out, catalogue)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
