//go:build darwin

package agentposture

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestParseProcArgs2(t *testing.T) {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	b = append(b, "/usr/local/bin/ollama\x00\x00\x00\x00ollama\x00serve\x00OLLAMA_HOST=0.0.0.0\x00HOME=/Users/x\x00\x00\x00"...)
	env, ok := parseProcArgs2(b)
	if !ok || !slices.Equal(env, []string{"OLLAMA_HOST=0.0.0.0", "HOME=/Users/x"}) {
		t.Fatalf("env %q ok %v", env, ok)
	}
	if _, ok := parseProcArgs2([]byte{1, 0}); ok {
		t.Error("a short buffer was read")
	}
}
