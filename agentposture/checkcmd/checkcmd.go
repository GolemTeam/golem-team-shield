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
	// Env is the machine Machine scans, for -fix; DefaultEnv when nil.
	Env func() agentposture.Env
}

// Run runs the check with args and returns its exit code: 0 when the report
// was written, 1 when it could not be, 2 for a usage error, 3 when -fail-on
// found something at least that severe, 4 when -fix -yes put every file back.
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
	fix := fs.Bool("fix", false, "print the changes to your own agent settings that undo their risky findings, file by file, and change nothing")
	yes := fs.Bool("yes", false, "with -fix, make the changes: each file is backed up first, and every one is put back if the grade drops")
	var up uploadTarget
	doUpload := fs.Bool("upload", false, "with -repo, also send the findings to Golem with the CI token in $"+TokenEnv+"; a failure prints one line and leaves the exit code alone")
	fs.StringVar(&up.url, "golem-url", "", "where -upload sends them: $"+URLEnv+", or "+DefaultURL)
	fs.StringVar(&up.repo, "upload-repo", "", "with -upload, the repository as owner/name: $GITHUB_REPOSITORY or $CI_PROJECT_PATH by default")
	fs.StringVar(&up.commit, "upload-commit", "", "with -upload, the commit checked: $GITHUB_SHA or $CI_COMMIT_SHA by default")
	fs.StringVar(&up.ref, "upload-ref", "", "with -upload, the ref checked: $GITHUB_REF, or the GitLab CI branch or tag, by default")
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
	if *yes && !*fix {
		fmt.Fprintln(stderr, o.Name+": -yes goes with -fix")
		return 2
	}
	if *doUpload && *repo == "" {
		fmt.Fprintln(stderr, o.Name+": -upload sends a repository's findings: it goes with -repo")
		return 2
	}
	if *fix && (*repo != "" || *asJSON || *withScore || *asSARIF || *asHTML || threshold >= 0) {
		fmt.Fprintln(stderr, o.Name+": -fix changes only this machine's own settings and prints its own plan: it takes -yes and -o")
		return 2
	}
	var res agentposture.Result
	if *repo != "" {
		if info, err := os.Stat(*repo); err != nil || !info.IsDir() {
			fmt.Fprintln(stderr, o.Name+": -repo needs a directory")
			return 2
		}
		res = agentposture.ScanRepo(*repo)
	} else if !*fix {
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
	if *fix {
		return runFix(out, stderr, o, *yes)
	}
	if err := write(out, res, format{*asJSON, *withScore, *asSARIF, *asHTML}, *repo != "", o); err != nil {
		fmt.Fprintln(stderr, o.Name+": could not write the report")
		return 1
	}
	if *doUpload {
		upload(stderr, o.Name, up, res)
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
// Protections are credit, not findings, except one the machine requires and
// lacks, which ShellJailItems makes dangerous.
func failing(res agentposture.Result, threshold int) bool {
	for _, it := range res.Items {
		if (it.Area != agentposture.AreaProtections || it.Severity == agentposture.Dangerous) && agentposture.Rank(it.Severity) <= threshold {
			return true
		}
	}
	return false
}

// ShellJailItems are the shell jail's coverage as the report's protections:
// credit for each agent whose commands it jails. Where the machine requires
// the jail (requiredBy says who does), an agent whose commands can run
// outside it is dangerous.
func ShellJailItems(cov []shield.AgentCoverage, requiredBy string) []agentposture.Item {
	items := make([]agentposture.Item, 0, len(cov))
	for _, c := range cov {
		sev, detail := agentposture.Suspicious, c.Detail
		switch {
		case c.Coverage == shield.Jailed:
			sev = agentposture.Info
		case requiredBy != "":
			sev = agentposture.Dangerous
			detail += "; this machine requires the jail (" + requiredBy + ")"
		}
		items = append(items, agentposture.Item{
			Client: c.Client, Area: agentposture.AreaProtections, Check: "shell_jail", Severity: sev,
			Location: c.Location, Setting: "shell", Value: string(c.Coverage), Detail: detail,
		})
	}
	return items
}

// JailRequiredBy says who requires this machine's agents to be jailed, or ""
// when nothing does: the administrator's managed settings, the Golem agent's
// workspace, or shield.json.
func JailRequiredBy(home, goos string) string {
	on, by := shield.JailRequired(home, shield.LoadManaged(shield.ManagedConfigPath(goos), shield.AdminOwned))
	if !on {
		return ""
	}
	return by
}
