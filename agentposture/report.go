package agentposture

import (
	"fmt"
	"io"
	"strings"
)

// WriteReport prints items for a person: each dangerous and suspicious one,
// a count of the rest, and the totals. What to do next is the caller's to say.
func WriteReport(w io.Writer, items []Item) {
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	fmt.Fprintln(w, "Your AI agents' settings on this machine")
	fmt.Fprintln(w)
	if counts[Dangerous]+counts[Suspicious] == 0 {
		fmt.Fprintln(w, "  Nothing risky found in the settings this check reads.")
	}
	for _, it := range items {
		if it.Severity == Dangerous || it.Severity == Suspicious {
			writeItem(w, it)
		}
	}
	if n := counts[Info]; n > 0 {
		fmt.Fprintf(w, "  (%d more for information only: --json lists them)\n", n)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d dangerous, %d suspicious. Nothing was sent anywhere.\n", counts[Dangerous], counts[Suspicious])
}

func writeItem(w io.Writer, it Item) {
	label := "suspicious"
	if it.Severity == Dangerous {
		label = "DANGEROUS "
	}
	where := it.Location
	if where == "" {
		where = it.Scope
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
