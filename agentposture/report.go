package agentposture

import (
	"fmt"
	"io"
	"strings"
)

// NotRead is what no report from this package can say, for the caller to end
// with when nothing else on the machine reads it.
const NotRead = "Not read: MCP tool descriptions. This check never starts an MCP server; the Golem agent\nreads each server's tools as your agents receive them, and checks them with the same rules."

// WriteReport prints a scan for a person: the grade, a line per area, each
// dangerous and suspicious finding, a count of the rest, and what protects
// each agent. What to do next is the caller's to say.
func WriteReport(w io.Writer, res Result) {
	rep := Score(res)
	if rep.Grade == "" {
		fmt.Fprintln(w, "No AI coding agents found on this machine.")
	} else {
		fmt.Fprintf(w, "Your AI agents on this machine: grade %s (%d of 100)\n", rep.Grade, rep.Score)
	}
	fmt.Fprintln(w)
	for _, a := range rep.Areas {
		if a.Applies {
			fmt.Fprintln(w, strings.TrimRight(fmt.Sprintf("  %-24s %3d  %s", a.Title, a.Score, areaSummary(a)), " "))
		}
	}
	fmt.Fprintln(w)

	counts := map[string]int{}
	var protections []Item
	for _, it := range res.Items {
		if it.Area == AreaProtections {
			protections = append(protections, it)
			continue
		}
		counts[it.Severity]++
	}
	if counts[Dangerous]+counts[Suspicious] == 0 {
		fmt.Fprintln(w, "  Nothing risky found in the settings this check reads.")
	}
	for _, it := range res.Items {
		if it.Area != AreaProtections && (it.Severity == Dangerous || it.Severity == Suspicious) {
			writeItem(w, it)
		}
	}
	if n := counts[Info]; n > 0 {
		fmt.Fprintf(w, "  (%d more for information only: --json lists them)\n", n)
	}
	if len(res.Agents) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Protections")
		writeProtections(w, res.Agents, protections)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d dangerous, %d suspicious. Nothing was sent anywhere.\n", counts[Dangerous], counts[Suspicious])
}

func areaSummary(a AreaScore) string {
	if a.Area == AreaProtections {
		noun := "agents"
		if a.Agents == 1 {
			noun = "agent"
		}
		return fmt.Sprintf("%s of %d %s jailed or sandboxed", trimFloat(a.Covered), a.Agents, noun)
	}
	var parts []string
	for _, c := range []struct {
		n    int
		what string
	}{{a.Dangerous, "dangerous"}, {a.Suspicious, "suspicious"}, {a.Info, "to note"}} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.what))
		}
	}
	return strings.Join(parts, ", ")
}

func trimFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", f), "0"), ".")
}

func writeProtections(w io.Writer, agents []string, items []Item) {
	for _, client := range agents {
		var best *Item
		jailSeen := false
		for i := range items {
			it := &items[i]
			if it.Client != client {
				continue
			}
			jailSeen = jailSeen || it.Check == "shell_jail"
			if best == nil || protectionCover(*it) > protectionCover(*best) {
				best = it
			}
		}
		detail := "no sandbox found"
		if best != nil && strings.TrimSpace(best.Detail) != "" {
			detail = best.Detail
		}
		// Without a shell_jail item the jail was not looked for, which is not
		// the same as its being absent.
		if !jailSeen && (best == nil || protectionCover(*best) == 0) {
			detail += "; this check cannot see a shell jail yet"
		}
		fmt.Fprintf(w, "  %-12s %s\n", client, detail)
	}
}

func writeItem(w io.Writer, it Item) {
	label := "suspicious"
	if it.Severity == Dangerous {
		label = "DANGEROUS "
	}
	where := it.Location
	if where == "" {
		where = it.Scope
	} else if it.Line > 0 {
		where = fmt.Sprintf("%s:%d", where, it.Line)
	}
	fmt.Fprintf(w, "  %s  %-12s %s\n", label, it.Client, summary(it))
	if where != "" {
		fmt.Fprintf(w, "              %-12s in %s\n", "", where)
	}
}

func summary(it Item) string {
	if d := strings.TrimSpace(it.Detail); d != "" {
		return d
	}
	if it.Setting != "" {
		return it.Setting + " = " + it.Value
	}
	return it.Check
}
