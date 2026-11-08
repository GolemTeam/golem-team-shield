package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"testing"

	"github.com/GolemTeam/golem-team-shield/shield"
)

// setupHashes pins setup_linux.go to the protocol it speaks. A root-owned
// copy installed once runs that file for every later build of golem-exec, so
// a change to it that the protocol doesn't name would leave copies already
// out there doing the old thing, a fixed bug included, with nothing asking
// for them to be replaced.
var setupHashes = map[string]string{
	"1": "6a7b1e83da1b3dbf0673a52dc2563e35fd0615b3d54274539ba93331f6a2819b",
}

//go:embed setup_linux.go
var setupSource []byte

func TestSetupProtocolFollowsTheSetup(t *testing.T) {
	sum := sha256.Sum256(setupSource)
	got := hex.EncodeToString(sum[:])
	if setupHashes[shield.NamespaceSetupProtocol] != got {
		t.Fatalf("setup_linux.go changed (sha256 %s). If the change alters what the setup does, or fixes it, "+
			"bump shield.NamespaceSetupProtocol and pin the new hash to it; if it can't (a comment), pin the "+
			"new hash to the current protocol", got)
	}
}
