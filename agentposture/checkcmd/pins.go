package checkcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

var errPinsUnreadable = errors.New("checkcmd: the pin file exists and cannot be read")

// writePins never replaces a pin file it could not read: that would drop
// every pin it holds for the servers not read this time.
func writePins(home string, fresh map[string]agentposture.LivePin) error {
	old, ok := agentposture.ReadLivePins(home)
	if !ok {
		return errPinsUnreadable
	}
	path := agentposture.LivePinsPath(home)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return errPinsUnreadable
	}
	b, err := json.MarshalIndent(old.Merge(fresh), "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".check-pins-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func pin(stderr io.Writer, name string, o Options, res agentposture.Result) int {
	env := agentposture.DefaultEnv()
	if o.Env != nil {
		env = o.Env()
	}
	n := len(res.Tools.NewPins)
	if n == 0 {
		fmt.Fprintln(stderr, name+": no remote server was read, so nothing was pinned")
		return 0
	}
	if err := writePins(env.Home, res.Tools.NewPins); err != nil {
		fmt.Fprintln(stderr, name+": could not write the pins to ~/.golem/check-pins.json")
		return 1
	}
	plural := "s"
	if n == 1 {
		plural = ""
	}
	fmt.Fprintf(stderr, "%s: pinned the tools of %d server%s in ~/.golem/check-pins.json\n", name, n, plural)
	return 0
}
