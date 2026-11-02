// golem-check prints the settings that let the AI coding agents on this
// machine act without asking: permission prompts off, every command allowed,
// no sandbox. It reads their settings files and sends nothing anywhere.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("golem-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print every finding, informational ones included, as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	items := agentposture.Scan(agentposture.DefaultEnv())
	if *asJSON {
		if items == nil {
			items = []agentposture.Item{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(items); err != nil {
			fmt.Fprintln(stderr, "golem-check: could not write the report")
			return 1
		}
		return 0
	}
	agentposture.WriteReport(stdout, items)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "golem-exec puts every shell command your agents run in a kernel jail. Golem adds")
	fmt.Fprintln(stdout, "a sandbox for untrusted repos, pages and files, free and with no account:")
	fmt.Fprintln(stdout, "  https://golem.team")
	return 0
}
