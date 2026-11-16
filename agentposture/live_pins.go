package agentposture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// Pins let -live-tools catch a change between two of its own runs, for the
// servers no agent stores a copy of. They live in ~/.golem, which a jailed
// agent can neither read nor write, so an agent cannot rewrite a pin to hide
// the change it made. The file holds hashes only: a server's URL can carry a
// key, and its tool names and descriptions are its own text.

const livePinsVersion = 1

type LivePins struct {
	Version int                `json:"version"`
	Servers map[string]LivePin `json:"servers"`
}

type LivePin struct {
	Pinned time.Time `json:"pinned"`
	// Instructions is "none" when the server sent none, and "" when what it
	// sent could not be read whole, which compares with nothing.
	Instructions string `json:"instructions,omitempty"`
	// Tools maps each tool's hashed name to its hashed description, "" when
	// the description could not be read whole.
	Tools map[string]string `json:"tools"`
}

const maxPinsBytes = 8 << 20

func LivePinsPath(home string) string { return filepath.Join(home, ".golem", "check-pins.json") }

func pinKey(rawURL string) string { return hashOf(rawURL) }

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ReadLivePins returns false when the file exists but cannot be read or does
// not decode, so the report can say the comparison was not made.
func ReadLivePins(home string) (LivePins, bool) {
	pins := LivePins{Version: livePinsVersion, Servers: map[string]LivePin{}}
	if home == "" {
		return pins, true
	}
	f, err := os.Open(LivePinsPath(home))
	if errors.Is(err, fs.ErrNotExist) {
		return pins, true
	}
	if err != nil {
		return pins, false
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return pins, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPinsBytes+1))
	if err != nil || len(b) > maxPinsBytes {
		return pins, false
	}
	var got LivePins
	if json.Unmarshal(b, &got) != nil || got.Version != livePinsVersion {
		return pins, false
	}
	for k, v := range got.Servers {
		pins.Servers[k] = v
	}
	return pins, true
}

func pinOf(parts []definition.Part, now time.Time) LivePin {
	p := LivePin{Pinned: now.UTC(), Tools: map[string]string{}, Instructions: "none"}
	if in := instructionsOf(parts); in.known {
		p.Instructions = hashOf(in.text)
	} else if hasKind(parts, definition.KindInstructions) {
		p.Instructions = ""
	}
	for name, d := range describedTools(parts) {
		p.Tools[hashOf(name)] = ""
		if d.known {
			p.Tools[hashOf(name)] = hashOf(d.text)
		}
	}
	return p
}

func hasKind(parts []definition.Part, kind string) bool {
	for _, p := range parts {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

func pinChanged(pin LivePin, live []definition.Part, r RemoteServer) (Item, bool) {
	now := pinOf(live, time.Time{})
	var changed []string
	added, removed := 0, 0
	for name, d := range describedTools(live) {
		old, ok := pin.Tools[hashOf(name)]
		switch {
		case !ok:
			added++
		case old != "" && d.known && old != hashOf(d.text):
			changed = append(changed, name)
		}
	}
	for h := range pin.Tools {
		if _, ok := now.Tools[h]; !ok {
			removed++
		}
	}
	instr := pin.Instructions != "" && now.Instructions != "" && pin.Instructions != now.Instructions
	return changeItem(r, "golem-check pinned it on "+pin.Pinned.UTC().Format("2006-01-02"), changed, added, removed, instr)
}

func (p LivePins) Merge(fresh map[string]LivePin) LivePins {
	out := LivePins{Version: livePinsVersion, Servers: map[string]LivePin{}}
	for k, v := range p.Servers {
		out.Servers[k] = v
	}
	for k, v := range fresh {
		out.Servers[k] = v
	}
	return out
}

func pinLine(cov ToolCoverage) string {
	switch {
	case cov.PinsUnreadable:
		return "  The pins in ~/.golem/check-pins.json could not be read, so nothing was compared with them."
	case cov.PinsCompared > 0:
		return "  Compared with what golem-check pinned for " + countOf(cov.PinsCompared, "server") + "."
	}
	return "  With -pin, a later -live-tools run flags any change from what they said now."
}
