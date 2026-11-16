package agentposture

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

// The live tool read (-live-tools, docs/design-golem-check-report.md) asks the
// remote MCP servers in the person's own configs for their tools. This half
// never touches the network, so the package keeps its offline promise without
// the flag: package livetools is the LiveReader that does the asking.

type RemoteServer struct {
	Client   string
	Name     string
	Scope    string
	Location string
	// Transport is "http", "sse", or "" when the config does not say, which
	// tries streamable HTTP and falls back to sse as the MCP spec describes.
	Transport string
	URL       string
	// Headers drop any value that names an environment variable: a config
	// line is the person's consent to send that literal value to that URL,
	// not to send whatever the environment holds.
	Headers map[string]string
}

type LiveResult struct {
	Parts   []definition.Part
	Failure string
}

// LiveReader returns one result per server, in order.
type LiveReader func([]RemoteServer) []LiveResult

const (
	LiveSignIn      = "sign_in"
	LiveUnreachable = "unreachable"
	LiveRefused     = "refused"
	LiveNotMCP      = "not_mcp"
	LiveTooLarge    = "too_large"
	LiveRedirected  = "redirected"
	liveRepository  = "repository"
	livePlainHTTP   = "plain_http"
	liveLocal       = "local"
)

const (
	LiveMaxBytes   = 1 << 20
	LiveTimeoutSec = 10
)

var liveReasons = []struct{ reason, text string }{
	{LiveSignIn, "the server asked for a sign-in this check does not have"},
	{LiveUnreachable, fmt.Sprintf("the server could not be reached, or did not answer in %d seconds", LiveTimeoutSec)},
	{LiveRefused, "the server refused the request"},
	{LiveNotMCP, "the server did not answer as an MCP server"},
	{LiveTooLarge, "the server's reply passed 1 MiB"},
	{LiveRedirected, "the server redirected elsewhere, which this check does not follow"},
	{livePlainHTTP, "plain http to another machine, so it was not asked"},
	{liveRepository, "configured in a repository's file, so it was not asked"},
	{liveLocal, "a local server, which this check never starts"},
}

var envReferenceRE = regexp.MustCompile(`\$\{[^}]*\}|\$env:|^\$[A-Za-z_][A-Za-z0-9_]*$|^%[A-Za-z_][A-Za-z0-9_]*%$`)

func remoteServer(f configFile, location, name string, d MCPServer) (RemoteServer, bool) {
	t := strings.ToLower(d.Type)
	if d.URL == "" || d.Command != "" || t == "stdio" {
		return RemoteServer{}, false
	}
	u, err := url.Parse(d.URL)
	if err != nil || u.Host == "" || (!strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http")) {
		return RemoteServer{}, false
	}
	switch t {
	case "sse":
	case "http", "streamable-http", "streamable_http", "streamablehttp":
		t = "http"
	default:
		t = ""
	}
	r := RemoteServer{Client: f.client, Name: name, Scope: f.scope, Location: location, Transport: t, URL: d.URL}
	for k, v := range d.Headers {
		if envReferenceRE.MatchString(v) {
			continue
		}
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		r.Headers[k] = v
	}
	return r, true
}

func plainHTTPElsewhere(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname())
}

// liveKey makes a server configured alike in several agents one request; the
// transport is left out, as one agent may name it where another lets it be
// found.
func liveKey(r RemoteServer) string {
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(r.URL)
	for _, k := range keys {
		b.WriteString("\x00" + strings.ToLower(k) + "\x01" + r.Headers[k])
	}
	return b.String()
}

// liveRead leaves a server in a repository's file alone: whoever wrote the
// file chose the URL, and asking it would tell them this machine cloned it.
// Plain http to another machine is left alone too, as it would send the
// config's headers in the clear.
func (s *scan) liveRead(remote []RemoteServer) (map[ServerRef]RemoteServer, map[ServerRef]LiveResult, map[ServerRef]string, int) {
	servers := map[ServerRef]RemoteServer{}
	why := map[ServerRef]string{}
	var ask []RemoteServer
	index := map[string]int{}
	asked := map[ServerRef]int{}
	for _, r := range remote {
		ref := ServerRef{r.Client, r.Name}
		if _, dup := servers[ref]; dup || golemServer(r.Name) {
			continue
		}
		servers[ref] = r
		switch {
		case r.Scope == "project":
			why[ref] = liveRepository
			continue
		case plainHTTPElsewhere(r.URL):
			why[ref] = livePlainHTTP
			continue
		}
		k := liveKey(r)
		i, ok := index[k]
		if !ok {
			i = len(ask)
			index[k] = i
			ask = append(ask, r)
		} else if ask[i].Transport == "" {
			ask[i].Transport = r.Transport
		}
		asked[ref] = i
	}
	results := map[ServerRef]LiveResult{}
	if len(ask) == 0 {
		return servers, results, why, 0
	}
	got := s.env.LiveTools(ask)
	for ref, i := range asked {
		res := LiveResult{Failure: LiveUnreachable}
		if i < len(got) {
			res = got[i]
		}
		if res.Failure != "" {
			why[ref] = res.Failure
			continue
		}
		results[ref] = res
	}
	return servers, results, why, len(ask)
}

// newParts keeps text the stored copy already holds from being scanned and
// reported a second time.
func newParts(live, stored []definition.Part) []definition.Part {
	have := map[string]bool{}
	for _, p := range stored {
		have[p.Kind+"\x00"+p.Name+"\x00"+p.Hash] = true
	}
	var out []definition.Part
	for _, p := range live {
		if !have[p.Kind+"\x00"+p.Name+"\x00"+p.Hash] {
			out = append(out, p)
		}
	}
	return out
}

// toolsChanged flags a description or the instructions changing under the
// same tool name as suspicious: that is a rug pull's shape, one text approved
// and another handed over at the next start. Schemas are not compared, since
// an agent may reshape one as it stores it, and a tool added or removed is
// only noted.
func toolsChanged(st StoredServer, live []definition.Part, r RemoteServer) (Item, bool) {
	stored, now := describedTools(st.Parts), describedTools(live)
	var changed []string
	added, removed := 0, 0
	for name, d := range now {
		old, ok := stored[name]
		switch {
		case !ok:
			added++
		case d.known && old.known && d.text != old.text:
			changed = append(changed, name)
		}
	}
	for name := range stored {
		if _, ok := now[name]; !ok {
			removed++
		}
	}
	a, b := instructionsOf(st.Parts), instructionsOf(live)
	instr := a.known && b.known && a.text != b.text
	return changeItem(r, st.Client+" stored its copy", changed, added, removed, instr)
}

func changeItem(r RemoteServer, since string, changed []string, added, removed int, instr bool) (Item, bool) {
	if len(changed)+added+removed == 0 && !instr {
		return Item{}, false
	}
	sort.Strings(changed)
	var what []string
	if instr {
		what = append(what, "its instructions")
	}
	if len(changed) > 0 {
		w := "the description of tool " + printable(changed[0], "with an unprintable name")
		if n := len(changed) - 1; n > 0 {
			w += fmt.Sprintf(" and %d more", n)
		}
		what = append(what, w)
	}
	detail := printable(r.Name, "a server") + ": "
	sev := Info
	if len(what) > 0 {
		sev = Suspicious
		detail += strings.Join(what, " and ") + " changed since " + since
	} else {
		detail += "its tools changed since " + since
	}
	if added > 0 {
		detail += "; " + countOf(added, "tool") + " added"
	}
	if removed > 0 {
		detail += "; " + countOf(removed, "tool") + " removed"
	}
	return Item{Client: r.Client, Check: "mcp_tools_changed", Severity: sev, Area: AreaMCPServers,
		Scope: r.Scope, Location: r.Location, Subject: r.Name, Detail: detail}, true
}

func countOf(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

type described struct {
	text  string
	known bool
}

func describedTools(parts []definition.Part) map[string]described {
	out := map[string]described{}
	for _, p := range parts {
		if p.Kind != definition.KindTool {
			continue
		}
		var t struct {
			Description *string `json:"description"`
		}
		d := described{}
		if len(p.JSON) > 0 && json.Unmarshal(p.JSON, &t) == nil {
			d.known = true
			if t.Description != nil {
				d.text = strings.TrimSpace(*t.Description)
			}
		}
		out[p.Name] = d
	}
	return out
}

func instructionsOf(parts []definition.Part) described {
	for _, p := range parts {
		if p.Kind == definition.KindInstructions {
			return described{strings.TrimSpace(p.Text), !p.Truncated && !p.Binary}
		}
	}
	return described{}
}
