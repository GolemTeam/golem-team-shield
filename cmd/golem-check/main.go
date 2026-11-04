// golem-check grades how the AI coding agents on this machine are set up: the
// settings that let them act without asking, what protects their shells, and
// the rest of docs/design-golem-check-report.md as it lands. It reads their
// files and sends nothing anywhere.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/GolemTeam/golem-team-shield/agentposture"
	"github.com/GolemTeam/golem-team-shield/shield"
)

// version is set at release (-X main.version=...).
var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("golem-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print every finding, informational ones included, as JSON")
	withScore := fs.Bool("with-score", false, "with -json, print the grade and area scores beside the findings")
	showVersion := fs.Bool("version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "golem-check "+version)
		return 0
	}
	env := agentposture.DefaultEnv()
	res := agentposture.ScanAll(env)
	res.Add(shellJailItems(shield.CoverageOf(shield.CoverageEnv{Home: env.Home, GOOS: env.GOOS}))...)
	if *asJSON {
		items := res.Items
		if items == nil {
			items = []agentposture.Item{}
		}
		var doc any = items
		if *withScore {
			doc = struct {
				Score agentposture.Report `json:"score"`
				Items []agentposture.Item `json:"items"`
			}{agentposture.Score(res), items}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintln(stderr, "golem-check: could not write the report")
			return 1
		}
		return 0
	}
	agentposture.WriteReport(stdout, res)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, agentposture.NotRead)
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

// shellJailItems are the shell jail's coverage as the report's protections:
// credit for each agent whose commands it jails. The Golem agent's `golem
// check` has the same.
func shellJailItems(cov []shield.AgentCoverage) []agentposture.Item {
	items := make([]agentposture.Item, 0, len(cov))
	for _, c := range cov {
		sev := agentposture.Suspicious
		if c.Coverage == shield.Jailed {
			sev = agentposture.Info
		}
		items = append(items, agentposture.Item{
			Client: c.Client, Area: agentposture.AreaProtections, Check: "shell_jail", Severity: sev,
			Location: c.Location, Setting: "shell", Value: string(c.Coverage), Detail: c.Detail,
		})
	}
	return items
}
