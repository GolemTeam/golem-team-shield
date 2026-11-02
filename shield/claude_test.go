package shield

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GolemTeam/golem-team-shield/internal/jsonobject"
)

func testShell(windows bool) ClaudeShell {
	return ClaudeShell{
		Windows: windows,
		Shim:    "/home/dev/.golem/bin/golem-zsh",
		Ours:    func(p string) bool { return strings.HasPrefix(p, "/home/dev/.golem/bin/golem-") },
		Ready:   func(string) bool { return true },
	}
}

func settingsOf(t *testing.T, s string) *jsonobject.Object {
	t.Helper()
	doc, err := jsonobject.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func marshal(t *testing.T, doc *jsonobject.Object) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWireSetsTheShimAndKeepsTheRest(t *testing.T) {
	doc := settingsOf(t, `{"model": "x", "env": {"FOO": "1"}}`)
	changes, err := testShell(false).Wire(doc)
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes %v, err %v", changes, err)
	}
	if got, want := marshal(t, doc), `{"model":"x","env":{"FOO":"1","CLAUDE_CODE_SHELL":"/home/dev/.golem/bin/golem-zsh"}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if changes, _ := testShell(false).Wire(doc); len(changes) != 0 {
		t.Errorf("a second wire changed %v", changes)
	}
}

func TestWireLeavesTheUsersOwnShellAlone(t *testing.T) {
	doc := settingsOf(t, `{"env": {"CLAUDE_CODE_SHELL": "/usr/local/bin/fish"}}`)
	if changes, err := testShell(false).Wire(doc); err != nil || len(changes) != 0 {
		t.Fatalf("changed the user's shell: %v %v", changes, err)
	}
	if changes, _ := testShell(false).Unwire(doc); len(changes) != 0 {
		t.Errorf("unwire removed the user's shell: %v", changes)
	}
}

func TestWireNeverSetsAShimThatCannotRun(t *testing.T) {
	c := testShell(false)
	c.Ready = func(string) bool { return false }
	doc := settingsOf(t, `{}`)
	if changes, _ := c.Wire(doc); len(changes) != 0 || marshal(t, doc) != `{}` {
		t.Errorf("set a shim that cannot run: %v %s", changes, marshal(t, doc))
	}
}

func TestWindowsWiresGitBashAndTurnsPowerShellOff(t *testing.T) {
	doc := settingsOf(t, `{}`)
	changes, err := testShell(true).Wire(doc)
	if err != nil || len(changes) != 2 {
		t.Fatalf("changes %v, err %v", changes, err)
	}
	if got := marshal(t, doc); !strings.Contains(got, `"CLAUDE_CODE_GIT_BASH_PATH"`) || !strings.Contains(got, `"CLAUDE_CODE_USE_POWERSHELL_TOOL":"0"`) {
		t.Errorf("got %s", got)
	}
	if changes, _ := testShell(true).Unwire(doc); len(changes) != 1 || marshal(t, doc) != `{}` {
		t.Errorf("unwire left %s (%v)", marshal(t, doc), changes)
	}
}

func TestUnwireDropsAnEnvBlockItEmptied(t *testing.T) {
	doc := settingsOf(t, `{"a": 1, "env": {"CLAUDE_CODE_SHELL": "/home/dev/.golem/bin/golem-bash"}}`)
	if changes, err := testShell(false).Unwire(doc); err != nil || len(changes) != 1 {
		t.Fatalf("changes %v, err %v", changes, err)
	}
	if got := marshal(t, doc); got != `{"a":1}` {
		t.Errorf("got %s", got)
	}
}

func TestAnEnvThatIsNotAnObjectIsAnError(t *testing.T) {
	if _, err := testShell(false).Wire(settingsOf(t, `{"env": "x"}`)); err == nil {
		t.Error("wired into an env that is a string")
	}
}
