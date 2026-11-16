// Package livetools is golem-check's -live-tools: it asks remote MCP servers
// for their tools and nothing else. It sends initialize, the initialized
// notification and tools/list, never calls a tool, follows no redirect, holds
// each server to agentposture.LiveMaxBytes and LiveTimeoutSec, and returns the
// reply as definition parts for agentposture to scan. It is its own package so
// agentposture keeps importing no network code.
package livetools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GolemTeam/golem-team-shield/agentposture"
	"github.com/GolemTeam/golem-team-shield/internal/definition"
)

const (
	protocolVersion = "2025-06-18"
	maxPages        = 20
	parallel        = 4
)

// The client names itself rather than pose as an agent: a server that answers
// a scanner differently is caught by the comparison with the copy the agent
// stored, and by the Golem agent, which reads what the agent itself receives.
var clientInfo = map[string]string{"name": "golem-check", "version": "1"}

type Reader struct {
	Timeout  time.Duration
	MaxBytes int64
	// Dial is replaced by tests; nil dials with the link-local guard.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func Read(servers []agentposture.RemoteServer) []agentposture.LiveResult {
	return Reader{}.Read(servers)
}

func (rd Reader) Read(servers []agentposture.RemoteServer) []agentposture.LiveResult {
	if rd.Timeout == 0 {
		rd.Timeout = agentposture.LiveTimeoutSec * time.Second
	}
	if rd.MaxBytes == 0 {
		rd.MaxBytes = agentposture.LiveMaxBytes
	}
	out := make([]agentposture.LiveResult, len(servers))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = rd.one(s)
		}()
	}
	wg.Wait()
	return out
}

// guardedDial refuses link-local addresses, where cloud metadata services
// answer, even when a config's host name resolves there.
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return errLinkLocal
		}
		return nil
	}}
	return d.DialContext(ctx, network, addr)
}

var errLinkLocal = errors.New("livetools: link-local address")

type failure string

func (f failure) Error() string { return string(f) }

func (rd Reader) one(s agentposture.RemoteServer) agentposture.LiveResult {
	ctx, cancel := context.WithTimeout(context.Background(), rd.Timeout)
	defer cancel()
	dial := rd.Dial
	if dial == nil {
		dial = guardedDial
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dial, ForceAttemptHTTP2: true,
		MaxResponseHeaderBytes: 64 << 10, TLSHandshakeTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	c := &conn{
		server: s, ctx: ctx, budget: rd.MaxBytes,
		http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	var parts []definition.Part
	var err error
	switch s.Transport {
	case "sse":
		parts, err = c.sse()
	case "http":
		parts, err = c.streamable()
	default:
		parts, err = c.streamable()
		if errors.Is(err, errTrySSE) {
			c.session = ""
			parts, err = c.sse()
		}
	}
	if err != nil {
		return agentposture.LiveResult{Failure: reason(ctx, err)}
	}
	return agentposture.LiveResult{Parts: parts}
}

func reason(ctx context.Context, err error) string {
	var f failure
	switch {
	case errors.As(err, &f):
		return string(f)
	case errors.Is(err, errTrySSE):
		return agentposture.LiveRefused
	case errors.Is(err, errTooLarge):
		return agentposture.LiveTooLarge
	case ctx.Err() != nil:
		return agentposture.LiveUnreachable
	}
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	if errors.As(err, &syn) || errors.As(err, &typ) {
		return agentposture.LiveNotMCP
	}
	return agentposture.LiveUnreachable
}

var (
	errTrySSE   = errors.New("livetools: no streamable HTTP here")
	errTooLarge = errors.New("livetools: reply too large")
)

type conn struct {
	server   agentposture.RemoteServer
	ctx      context.Context
	http     *http.Client
	budget   int64
	mu       sync.Mutex
	session  string
	protocol string
}

// limited charges every reply against one budget per server, so a server
// cannot pass the cap by spreading it over pages or streams.
type limited struct {
	c *conn
	r io.Reader
}

func (l limited) Read(p []byte) (int, error) {
	l.c.mu.Lock()
	left := l.c.budget
	l.c.mu.Unlock()
	if left <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := l.r.Read(p)
	l.c.mu.Lock()
	l.c.budget -= int64(n)
	l.c.mu.Unlock()
	return n, err
}

var reserved = map[string]bool{"host": true, "content-length": true, "content-type": true, "accept": true,
	"connection": true, "transfer-encoding": true, "mcp-session-id": true, "mcp-protocol-version": true}

func (c *conn) request(method, target string, body []byte) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(c.ctx, method, target, r)
	if err != nil {
		return nil, err
	}
	for k, v := range c.server.Headers {
		if !reserved[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("User-Agent", "golem-check")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", c.protocol)
	}
	return req, nil
}

func statusFailure(code int) error {
	switch {
	case code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusPaymentRequired:
		return failure(agentposture.LiveSignIn)
	case code >= 300 && code < 400:
		return failure(agentposture.LiveRedirected)
	}
	return failure(agentposture.LiveRefused)
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func call(id int, method string, params any) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return b
}

func notify(method string) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	return b
}

func initParams() map[string]any {
	return map[string]any{"protocolVersion": protocolVersion, "capabilities": map[string]any{}, "clientInfo": clientInfo}
}

func (c *conn) streamable() ([]definition.Part, error) {
	init, err := c.post(1, "initialize", initParams(), true)
	if err != nil {
		return nil, err
	}
	defer c.endSession()
	var ir initResult
	if err := json.Unmarshal(init, &ir); err != nil || ir.ProtocolVersion == "" {
		return nil, failure(agentposture.LiveNotMCP)
	}
	c.protocol = ir.ProtocolVersion
	if err := c.postNotification(); err != nil {
		return nil, err
	}
	return collect(ir, func(id int, cursor string) (json.RawMessage, error) {
		return c.post(id, "tools/list", pageParams(cursor), false)
	})
}

func (c *conn) post(id int, method string, params any, first bool) (json.RawMessage, error) {
	req, err := c.request(http.MethodPost, c.server.URL, call(id, method, params))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if first {
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed:
			if c.server.Transport == "" {
				return nil, errTrySSE
			}
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusFailure(resp.StatusCode)
	}
	if first {
		c.session = resp.Header.Get("Mcp-Session-Id")
	}
	body := limited{c, resp.Body}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") {
		ev := newEvents(body)
		for {
			_, data, err := ev.next()
			if err != nil {
				return nil, eofIsNotMCP(err)
			}
			if res, ok, err := match(data, id); ok || err != nil {
				return res, err
			}
		}
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	res, ok, err := match(b, id)
	if err == nil && !ok {
		err = failure(agentposture.LiveNotMCP)
	}
	return res, err
}

func (c *conn) postNotification() error {
	req, err := c.request(http.MethodPost, c.server.URL, notify("notifications/initialized"))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, limited{c, resp.Body})
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return statusFailure(resp.StatusCode)
	}
	return nil
}

// endSession lets the server drop the session it opened for this read, as
// the spec asks of a client that is done.
func (c *conn) endSession() {
	if c.session == "" || c.ctx.Err() != nil {
		return
	}
	req, err := c.request(http.MethodDelete, c.server.URL, nil)
	if err != nil {
		return
	}
	if resp, err := c.http.Do(req); err == nil {
		resp.Body.Close()
	}
}

// sse is the HTTP+SSE transport: a GET opens an event stream whose first
// event names where to POST, and every reply comes back on the stream. The
// POST endpoint must be on the server's own origin, or the config's headers
// would go to a host the config never named.
func (c *conn) sse() ([]definition.Part, error) {
	c.protocol = ""
	req, err := c.request(http.MethodGet, c.server.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusFailure(resp.StatusCode)
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return nil, failure(agentposture.LiveNotMCP)
	}
	ev := newEvents(limited{c, resp.Body})
	var endpoint string
	for endpoint == "" {
		name, data, err := ev.next()
		if err != nil {
			return nil, eofIsNotMCP(err)
		}
		if name == "endpoint" {
			endpoint = strings.TrimSpace(string(data))
		}
	}
	base, _ := url.Parse(c.server.URL)
	target, err := base.Parse(endpoint)
	if err != nil {
		return nil, failure(agentposture.LiveNotMCP)
	}
	if !strings.EqualFold(target.Scheme, base.Scheme) || !strings.EqualFold(target.Host, base.Host) {
		return nil, failure(agentposture.LiveRedirected)
	}
	send := func(body []byte) error {
		req, err := c.request(http.MethodPost, target.String(), body)
		if err != nil {
			return err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, limited{c, resp.Body})
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return statusFailure(resp.StatusCode)
		}
		return nil
	}
	await := func(id int) (json.RawMessage, error) {
		for {
			name, data, err := ev.next()
			if err != nil {
				return nil, eofIsNotMCP(err)
			}
			if name != "" && name != "message" {
				continue
			}
			if res, ok, err := match(data, id); ok || err != nil {
				return res, err
			}
		}
	}
	if err := send(call(1, "initialize", initParams())); err != nil {
		return nil, err
	}
	init, err := await(1)
	if err != nil {
		return nil, err
	}
	var ir initResult
	if err := json.Unmarshal(init, &ir); err != nil || ir.ProtocolVersion == "" {
		return nil, failure(agentposture.LiveNotMCP)
	}
	if err := send(notify("notifications/initialized")); err != nil {
		return nil, err
	}
	return collect(ir, func(id int, cursor string) (json.RawMessage, error) {
		if err := send(call(id, "tools/list", pageParams(cursor))); err != nil {
			return nil, err
		}
		return await(id)
	})
}

func eofIsNotMCP(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return failure(agentposture.LiveNotMCP)
	}
	return err
}

type initResult struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	Instructions    string                     `json:"instructions"`
}

func pageParams(cursor string) map[string]any {
	if cursor == "" {
		return map[string]any{}
	}
	return map[string]any{"cursor": cursor}
}

// collect builds parts the way a stored copy's are built, so the two hash
// alike and the comparison with the stored copy is like for like.
func collect(ir initResult, list func(id int, cursor string) (json.RawMessage, error)) ([]definition.Part, error) {
	var parts []definition.Part
	if ir.Instructions != "" {
		parts = append(parts, definition.Text(definition.KindInstructions, "", []byte(ir.Instructions)))
	}
	if _, ok := ir.Capabilities["tools"]; !ok {
		return parts, nil
	}
	cursor := ""
	for page := 0; page < maxPages; page++ {
		res, err := list(2+page, cursor)
		if err != nil {
			return nil, err
		}
		var tl struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(res, &tl); err != nil {
			return nil, failure(agentposture.LiveNotMCP)
		}
		for _, raw := range tl.Tools {
			if len(parts) >= definition.MaxParts {
				return parts, nil
			}
			if p, _, err := definition.Tool(raw); err == nil {
				parts = append(parts, p)
			}
		}
		if tl.NextCursor == "" || tl.NextCursor == cursor {
			break
		}
		cursor = tl.NextCursor
	}
	return parts, nil
}

// match skips a request or notification the server sends ahead of the reply:
// this client offers no capabilities, so it has nothing to answer them with.
func match(b []byte, id int) (json.RawMessage, bool, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, false, nil
	}
	var msgs []rpcMessage
	if b[0] == '[' {
		if err := json.Unmarshal(b, &msgs); err != nil {
			return nil, false, failure(agentposture.LiveNotMCP)
		}
	} else {
		var m rpcMessage
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, false, failure(agentposture.LiveNotMCP)
		}
		msgs = []rpcMessage{m}
	}
	want := fmt.Sprint(id)
	for _, m := range msgs {
		if m.Method != "" || strings.Trim(string(m.ID), `"`) != want {
			continue
		}
		if len(m.Error) > 0 && string(m.Error) != "null" {
			return nil, true, failure(agentposture.LiveRefused)
		}
		return m.Result, true, nil
	}
	return nil, false, nil
}

type events struct{ r *bufio.Reader }

func newEvents(r io.Reader) *events { return &events{bufio.NewReaderSize(r, 32<<10)} }

func (e *events) next() (string, []byte, error) {
	var name string
	var data bytes.Buffer
	seen := false
	for {
		line, err := e.r.ReadString('\n')
		if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
			return "", nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if seen {
				return name, data.Bytes(), nil
			}
			if err != nil {
				return "", nil, err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			name, seen = value, true
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
			seen = true
		}
		if err != nil {
			return name, data.Bytes(), nil
		}
	}
}
