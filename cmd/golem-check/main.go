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
	"runtime"

	"github.com/GolemTeam/golem-team-shield/agentposture"
)

// version is set at release (-X main.version=...).
var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("golem-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print every finding, informational ones included, as JSON")
	showVersion := fs.Bool("version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "golem-check "+version)
		return 0
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
	fmt.Fprintln(stdout, "Put every shell command your agents run in a kernel jail, and run untrusted repos,")
	fmt.Fprintln(stdout, "pages and files in a sandbox, free and with no account:")
	fmt.Fprintln(stdout, "  "+installCommand(runtime.GOOS))
	return 0
}

// installCommand installs the Golem agent, which with no key runs on this
// machine only. On Windows it needs PowerShell run as administrator.
func installCommand(goos string) string {
	if goos == "windows" {
		return "iwr -useb https://app.golem.team/install.ps1 | iex   (PowerShell, as administrator)"
	}
	return "curl -fsSL https://app.golem.team/install.sh | sh"
}
