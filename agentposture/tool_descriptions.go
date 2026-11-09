package agentposture

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
	"github.com/GolemTeam/golem-team-shield/internal/defscan"
)

type ServerRef struct {
	Client string `json:"client"`
	Name   string `json:"name"`
}

// ToolCoverage is what a report could read of MCP servers' tool descriptions:
// the servers an agent stored a copy of, and the configured servers none did.
type ToolCoverage struct {
	Read   []ServerRef `json:"read,omitempty"`
	Unread []ServerRef `json:"unread,omitempty"`
}

func golemServer(name string) bool {
	return name == "golem" || strings.HasPrefix(name, "golem-") || strings.HasPrefix(name, "mcp-golem-")
}

var printableNameRE = regexp.MustCompile(`^[\w.@:/+-]+( [\w.@:/+-]+)*$`)

// printable keeps a name out of the report unless it is plainly a name: a
// server or a cloned repository's config chose it.
func printable(name, otherwise string) string {
	if len(name) <= 64 && printableNameRE.MatchString(name) {
		return name
	}
	return otherwise
}

// toolDescriptionItems runs defscan over the copies the agents stored, as the
// inventory does over what the gateway sees. A finding names the server, the
// tool and the rule, never the text: it is the server's own, possibly an
// attacker's, and the report is made to be handed on.
func (s *scan) toolDescriptionItems(configured []ServerRef) ([]Item, ToolCoverage) {
	var items []Item
	var cov ToolCoverage
	stored := map[ServerRef]bool{}
	for _, st := range StoredServers(s.env) {
		if golemServer(st.Name) {
			continue
		}
		ref := ServerRef{st.Client, st.Name}
		if !stored[ref] {
			stored[ref] = true
			cov.Read = append(cov.Read, ref)
		}
		s.read[AreaMCPServers] = true
		server := printable(st.Name, "a server")
		loc := DisplayHome(s.env.Home, st.Path)
		type found struct {
			item        Item
			where, what string
			parts       map[string]bool
		}
		var byRule []*found
		rule := map[string]*found{}
		for _, f := range defscan.Scan(definition.Build("mcp_server", "mcp-"+st.Name, definition.SourceConfigScan, st.Parts)) {
			part := f.PartKind + "\x00" + f.PartName
			if fd := rule[f.Rule]; fd != nil {
				fd.parts[part] = true
				continue
			}
			title := ruleTitles[f.Rule]
			if title == "" {
				title = f.Rule
			}
			where := "instructions"
			if f.PartKind == definition.KindTool {
				where = "tool " + printable(f.PartName, "with an unprintable name")
			}
			fd := &found{
				item: Item{Client: st.Client, Check: f.Rule, Severity: ruleSeverity(f.Severity, f.Confidence), Area: AreaMCPServers,
					Scope: st.Scope, Location: loc, Subject: st.Name},
				where: where, what: strings.ToLower(title[:1]) + title[1:], parts: map[string]bool{part: true},
			}
			rule[f.Rule] = fd
			byRule = append(byRule, fd)
		}
		for _, fd := range byRule {
			if n := len(fd.parts) - 1; n > 0 {
				fd.where += fmt.Sprintf(" and %d more", n)
			}
			fd.item.Detail = server + " " + fd.where + ": " + fd.what
			items = append(items, fd.item)
		}
	}
	seen := map[ServerRef]bool{}
	for _, c := range configured {
		if stored[c] || seen[c] || golemServer(c.Name) {
			continue
		}
		seen[c] = true
		cov.Unread = append(cov.Unread, c)
	}
	sortRefs(cov.Read)
	sortRefs(cov.Unread)
	return items, cov
}

func sortRefs(refs []ServerRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Client != refs[j].Client {
			return refs[i].Client < refs[j].Client
		}
		return refs[i].Name < refs[j].Name
	})
}

const maxServersPerLine = 6

func writeServers(w io.Writer, refs []ServerRef) {
	for i := 0; i < len(refs); {
		client := refs[i].Client
		var names []string
		n := 0
		for ; i < len(refs) && refs[i].Client == client; i++ {
			if n++; n <= maxServersPerLine {
				names = append(names, printable(refs[i].Name, "(unprintable)"))
			}
		}
		line := strings.Join(names, ", ")
		if n > maxServersPerLine {
			line += fmt.Sprintf(" and %d more", n-maxServersPerLine)
		}
		fmt.Fprintf(w, "    %-12s %s\n", client, line)
	}
}

func serverLines(refs []ServerRef) []htmlProtection {
	var out []htmlProtection
	for i := 0; i < len(refs); {
		client := refs[i].Client
		var names []string
		for ; i < len(refs) && refs[i].Client == client; i++ {
			names = append(names, printable(refs[i].Name, "(unprintable)"))
		}
		out = append(out, htmlProtection{client, strings.Join(names, ", ")})
	}
	return out
}

func servers(n int) string {
	if n == 1 {
		return "1 server"
	}
	return fmt.Sprintf("%d servers", n)
}

func writeToolCoverage(w io.Writer, cov ToolCoverage) {
	if len(cov.Read)+len(cov.Unread) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "MCP tool descriptions")
	if len(cov.Read) > 0 {
		fmt.Fprintf(w, "  Read from the copy an agent stored (%s):\n", servers(len(cov.Read)))
		writeServers(w, cov.Read)
	}
	if len(cov.Unread) > 0 {
		fmt.Fprintf(w, "  Not read, as no agent stored a copy (%s):\n", servers(len(cov.Unread)))
		writeServers(w, cov.Unread)
	}
}
