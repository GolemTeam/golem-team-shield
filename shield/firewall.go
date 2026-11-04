package shield

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
)

// The Windows firewall half of an allowlisted network
// (docs/design-shield-workspace-and-egress.md, "Windows").
//
// A restricted token can't take the network away, so the shim puts one more
// SID, ShieldNetSIDString, in the restricting SIDs of a shell whose network
// is allowlisted, and a persistent Windows Filtering Platform sublayer
// refuses outbound connections to any process whose token fails
// FirewallSDDL: it denies that SID and allows every principal a process
// normally carries. A token only fails it in its restricted pass, where only
// the shim puts the SID, so the block holds the jailed shell and nothing else
// the user runs. Loopback to WindowsProxyPorts stays open, for the proxy.

func ShieldSIDString() string { return derivedSID("golem-shield") }

func ShieldNetSIDString() string { return derivedSID("golem-shield-net") }

// derivedSID names no account or group, under the resource manager
// authority: CreateRestrictedToken refuses a capability SID.
func derivedSID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	s := "S-1-9-1"
	for i := 0; i < 4; i++ {
		s += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[i*4:])), 10)
	}
	return s
}

// WindowsProxyPorts are the loopback ports the shim's proxy listens on under
// Windows, the ones the firewall lets a jailed shell reach.
var WindowsProxyPorts = [2]uint16{47300, 47399}

// FirewallSDDL is what a process's token must pass to keep its network. The
// allows cover the principals ordinary processes, services, packaged apps
// and other vendors' sandboxes carry, so only a token whose restricted pass
// holds ShieldNetSIDString fails. WFP refuses a descriptor with a label, so
// it has none; a low-integrity token still matches (measured).
func FirewallSDDL() string {
	sd := "O:SYG:SYD:(D;;0x1;;;" + ShieldNetSIDString() + ")"
	for _, s := range []string{"WD", "AU", "BU", "BA", "SY", "LS", "NS", "RC", "AC", "S-1-15-2-2", "IU", "SU", "S-1-5-6"} {
		sd += "(A;;0x1;;;" + s + ")"
	}
	return sd
}
