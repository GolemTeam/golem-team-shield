package agentposture

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
	"github.com/GolemTeam/golem-team-shield/internal/defscan"
)

type ServerRef struct {
	Client string `json:"client"`
	Name   string `json:"name"`
}

// ToolCoverage is what a report could read of MCP servers' tool descriptions:
// the servers an agent stored a copy of, the ones read from the server itself,
// and the configured servers neither covered.
type ToolCoverage struct {
	Read   []ServerRef `json:"read,omitempty"`
	Live   []ServerRef `json:"live,omitempty"`
	Unread []ServerRef `json:"unread,omitempty"`
	// Remote counts the unread servers a live read could ask.
	Remote int `json:"remote,omitempty"`
	// Asked is how many servers the live read sent a request to, and Why says
	// for each unread server why not; both are empty without the live read.
	Asked int                  `json:"asked,omitempty"`
	Why   map[ServerRef]string `json:"-"`
	// PinsCompared counts the servers read whose pin was found, and NewPins
	// is what -pin writes: a pin for each server read now.
	PinsCompared   int                `json:"pins_compared,omitempty"`
	PinsUnreadable bool               `json:"pins_unreadable,omitempty"`
	NewPins        map[string]LivePin `json:"-"`
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
// inventory does over what the gateway sees, and over what the remote servers
// say now when the live read is on. A finding names the server, the tool and
// the rule, never the text: it is the server's own, possibly an attacker's,
// and the report is made to be handed on.
func (s *scan) toolDescriptionItems(configured []ServerRef, remote []RemoteServer) ([]Item, ToolCoverage) {
	var items []Item
	var cov ToolCoverage
	stored := map[ServerRef]StoredServer{}
	for _, st := range StoredServers(s.env) {
		if golemServer(st.Name) {
			continue
		}
		ref := ServerRef{st.Client, st.Name}
		if _, ok := stored[ref]; !ok {
			stored[ref] = st
			cov.Read = append(cov.Read, ref)
		}
		s.read[AreaMCPServers] = true
		items = append(items, s.definitionItems(st.Client, st.Name, st.Scope, DisplayHome(s.env.Home, st.Path), st.Parts, "")...)
	}
	isRemote := map[ServerRef]bool{}
	for _, r := range remote {
		isRemote[ServerRef{r.Client, r.Name}] = true
	}
	var live map[ServerRef]LiveResult
	compared := map[string]bool{}
	if s.env.LiveTools != nil && s.env.Repo == "" {
		var servers map[ServerRef]RemoteServer
		servers, live, cov.Why, cov.Asked = s.liveRead(remote)
		var pins LivePins
		if len(live) > 0 {
			var ok bool
			pins, ok = ReadLivePins(s.env.Home)
			cov.PinsUnreadable = !ok
			cov.NewPins = map[string]LivePin{}
		}
		now := time.Now()
		for _, ref := range sortedRefs(live) {
			r, res := servers[ref], live[ref]
			cov.Live = append(cov.Live, ref)
			s.read[AreaMCPServers] = true
			parts := res.Parts
			if st, ok := stored[ref]; ok {
				if it, changed := toolsChanged(st, res.Parts, r); changed {
					items = append(items, it)
				}
				parts = newParts(res.Parts, st.Parts)
			}
			key := pinKey(r.URL)
			if pin, ok := pins.Servers[key]; ok {
				compared[key] = true
				if it, changed := pinChanged(pin, res.Parts, r); changed {
					items = append(items, it)
				}
			}
			cov.NewPins[key] = pinOf(res.Parts, now)
			items = append(items, s.definitionItems(r.Client, r.Name, r.Scope, r.Location, parts, ", as the server describes it now")...)
		}
	}
	cov.PinsCompared = len(compared)
	seen := map[ServerRef]bool{}
	for _, c := range configured {
		if _, ok := stored[c]; ok || seen[c] || golemServer(c.Name) {
			continue
		}
		if _, ok := live[c]; ok {
			continue
		}
		seen[c] = true
		cov.Unread = append(cov.Unread, c)
		if isRemote[c] {
			cov.Remote++
		}
		if cov.Why != nil && cov.Why[c] == "" {
			cov.Why[c] = liveLocal
		}
	}
	sortRefs(cov.Read)
	sortRefs(cov.Unread)
	return items, cov
}

func (s *scan) definitionItems(client, name, scope, loc string, parts []definition.Part, suffix string) []Item {
	var items []Item
	server := printable(name, "a server")
	type found struct {
		item        Item
		where, what string
		parts       map[string]bool
	}
	var byRule []*found
	rule := map[string]*found{}
	for _, f := range defscan.Scan(definition.Build("mcp_server", "mcp-"+name, definition.SourceConfigScan, parts)) {
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
			item: Item{Client: client, Check: f.Rule, Severity: ruleSeverity(f.Severity, f.Confidence), Area: AreaMCPServers,
				Scope: scope, Location: loc, Subject: name},
			where: where, what: strings.ToLower(title[:1]) + title[1:], parts: map[string]bool{part: true},
		}
		rule[f.Rule] = fd
		byRule = append(byRule, fd)
	}
	for _, fd := range byRule {
		if n := len(fd.parts) - 1; n > 0 {
			fd.where += fmt.Sprintf(" and %d more", n)
		}
		fd.item.Detail = server + " " + fd.where + ": " + fd.what + suffix
		items = append(items, fd.item)
	}
	return items
}

func sortedRefs[V any](m map[ServerRef]V) []ServerRef {
	refs := make([]ServerRef, 0, len(m))
	for r := range m {
		refs = append(refs, r)
	}
	sortRefs(refs)
	return refs
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
	if len(cov.Read)+len(cov.Live)+len(cov.Unread) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "MCP tool descriptions")
	if len(cov.Live) > 0 {
		fmt.Fprintf(w, "  Read from the server itself (%s):\n", servers(len(cov.Live)))
		writeServers(w, cov.Live)
		fmt.Fprintln(w, pinLine(cov))
	}
	if len(cov.Read) > 0 {
		fmt.Fprintf(w, "  Read from the copy an agent stored (%s):\n", servers(len(cov.Read)))
		writeServers(w, cov.Read)
	}
	if len(cov.Unread) == 0 {
		return
	}
	if cov.Why == nil {
		fmt.Fprintf(w, "  Not read, as no agent stored a copy (%s):\n", servers(len(cov.Unread)))
		writeServers(w, cov.Unread)
		switch {
		case cov.Remote == 1:
			fmt.Fprintln(w, "  One of them is remote: -live-tools asks it for its tools.")
		case cov.Remote > 1:
			fmt.Fprintf(w, "  %d of them are remote: -live-tools asks each for its tools.\n", cov.Remote)
		}
		return
	}
	for _, g := range unreadGroups(cov) {
		fmt.Fprintf(w, "  Not read, %s (%s):\n", g.text, servers(len(g.refs)))
		writeServers(w, g.refs)
	}
}

type unreadGroup struct {
	text string
	refs []ServerRef
}

func unreadGroups(cov ToolCoverage) []unreadGroup {
	var out []unreadGroup
	for _, r := range liveReasons {
		var refs []ServerRef
		for _, ref := range cov.Unread {
			if cov.Why[ref] == r.reason {
				refs = append(refs, ref)
			}
		}
		if len(refs) > 0 {
			out = append(out, unreadGroup{r.text, refs})
		}
	}
	return out
}

// SentLine is the report's last word on what left the machine: nothing, or
// with the live read only its requests for tools.
func SentLine(cov ToolCoverage) string {
	if cov.Asked == 0 {
		return "Nothing was sent anywhere."
	}
	return "Nothing was sent anywhere but a request for tools to " + countOf(cov.Asked, "remote MCP server") + "."
}
