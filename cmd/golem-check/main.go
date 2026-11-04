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
	"time"

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
	asSARIF := fs.Bool("sarif", false, "print the findings as SARIF 2.1.0, for GitHub code scanning")
	asHTML := fs.Bool("html", false, "print the report as one self-contained HTML page, to hand a security team")
	repo := fs.String("repo", "", "check only the agent files in this repository, not this machine")
	outPath := fs.String("o", "", "write the report to this file instead of standard output")
	failOn := fs.String("fail-on", "none", "exit 3 if a finding is at least this severe: suspicious, dangerous or none")
	showVersion := fs.Bool("version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "golem-check "+version)
		return 0
	}
	threshold, ok := map[string]int{"none": -1, agentposture.Suspicious: 1, agentposture.Dangerous: 0}[*failOn]
	if !ok {
		fmt.Fprintln(stderr, "golem-check: -fail-on takes suspicious, dangerous or none")
		return 2
	}
	var res agentposture.Result
	if *repo != "" {
		if info, err := os.Stat(*repo); err != nil || !info.IsDir() {
			fmt.Fprintln(stderr, "golem-check: -repo needs a directory")
			return 2
		}
		res = agentposture.ScanRepo(*repo)
	} else {
		env := agentposture.DefaultEnv()
		res = agentposture.ScanAll(env)
		res.Add(shellJailItems(shield.CoverageOf(shield.CoverageEnv{Home: env.Home, GOOS: env.GOOS, LoginShell: os.Getenv("SHELL"), CodexHomes: env.CodexHomes, OpenClawDir: os.Getenv("OPENCLAW_STATE_DIR")}))...)
	}
	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(stderr, "golem-check: could not create the report file")
			return 1
		}
		defer f.Close()
		out = f
	}
	if err := write(out, res, format{*asJSON, *withScore, *asSARIF, *asHTML}, *repo != ""); err != nil {
		fmt.Fprintln(stderr, "golem-check: could not write the report")
		return 1
	}
	if threshold >= 0 && failing(res, threshold) {
		return 3
	}
	return 0
}

type format struct{ json, withScore, sarif, html bool }

func write(out io.Writer, res agentposture.Result, f format, repo bool) error {
	switch {
	case f.sarif:
		return agentposture.WriteSARIF(out, res, version)
	case f.html:
		return agentposture.WriteHTML(out, res, agentposture.HTMLMeta{Version: version, GOOS: runtime.GOOS, When: time.Now()})
	case f.json:
		items := res.Items
		if items == nil {
			items = []agentposture.Item{}
		}
		var doc any = items
		if f.withScore {
			doc = struct {
				Score agentposture.Report `json:"score"`
				Items []agentposture.Item `json:"items"`
			}{agentposture.Score(res), items}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	}
	agentposture.WriteReport(out, res)
	if repo {
		return nil
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, agentposture.NotRead)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Put every shell command your agents run in a kernel jail, and run untrusted repos,")
	fmt.Fprintln(out, "pages and files in a sandbox, free and with no account:")
	_, err := fmt.Fprintln(out, "  "+installCommand(runtime.GOOS))
	return err
}

// failing reports a finding at or above threshold, by agentposture.Rank.
// Protections are credit, not findings.
func failing(res agentposture.Result, threshold int) bool {
	for _, it := range res.Items {
		if it.Area != agentposture.AreaProtections && agentposture.Rank(it.Severity) <= threshold {
			return true
		}
	}
	return false
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
