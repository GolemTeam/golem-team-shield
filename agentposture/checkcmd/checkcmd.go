// Package checkcmd is the command line of golem-check and of the Golem agent's
// `golem check`, so the free tool and the agent take the same options, write
// the same formats and exit the same way. Each passes in only what differs: how
// it scans this machine and what the text report ends with.
package checkcmd

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

type Options struct {
	Name    string
	Version string
	// Machine scans this machine, the shell jail's protections included.
	Machine func() agentposture.Result
	// Footer ends the text report of a machine scan.
	Footer func(out io.Writer) error
}

// Run runs the check with args and returns its exit code: 0 when the report
// was written, 1 when it could not be, 2 for a usage error, 3 when -fail-on
// found something at least that severe.
func Run(args []string, stdout, stderr io.Writer, o Options) int {
	fs := flag.NewFlagSet(o.Name, flag.ContinueOnError)
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
		fmt.Fprintln(stdout, o.Name+" "+o.Version)
		return 0
	}
	threshold, ok := map[string]int{"none": -1, agentposture.Suspicious: 1, agentposture.Dangerous: 0}[*failOn]
	if !ok {
		fmt.Fprintln(stderr, o.Name+": -fail-on takes suspicious, dangerous or none")
		return 2
	}
	var res agentposture.Result
	if *repo != "" {
		if info, err := os.Stat(*repo); err != nil || !info.IsDir() {
			fmt.Fprintln(stderr, o.Name+": -repo needs a directory")
			return 2
		}
		res = agentposture.ScanRepo(*repo)
	} else {
		res = o.Machine()
	}
	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(stderr, o.Name+": could not create the report file")
			return 1
		}
		defer f.Close()
		out = f
	}
	if err := write(out, res, format{*asJSON, *withScore, *asSARIF, *asHTML}, *repo != "", o); err != nil {
		fmt.Fprintln(stderr, o.Name+": could not write the report")
		return 1
	}
	if threshold >= 0 && failing(res, threshold) {
		return 3
	}
	return 0
}

type format struct{ json, withScore, sarif, html bool }

func write(out io.Writer, res agentposture.Result, f format, repo bool, o Options) error {
	switch {
	case f.sarif:
		return agentposture.WriteSARIF(out, res, o.Version)
	case f.html:
		return agentposture.WriteHTML(out, res, agentposture.HTMLMeta{Version: o.Version, GOOS: runtime.GOOS, When: time.Now()})
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
	if repo || o.Footer == nil {
		return nil
	}
	fmt.Fprintln(out)
	return o.Footer(out)
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

// ShellJailItems are the shell jail's coverage as the report's protections:
// credit for each agent whose commands it jails.
func ShellJailItems(cov []shield.AgentCoverage) []agentposture.Item {
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
