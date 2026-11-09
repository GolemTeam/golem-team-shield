package shield

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxy is the forward proxy a command with an allowlisted network reaches
// the internet through. The shim runs one per command, on a port only that
// command's jail can reach, and reports what it saw in the run record.
//
// Names are checked after they resolve and the dial goes to the checked
// address, so a name can't re-resolve elsewhere between check and connect.
// Link-local and multicast addresses are never dialled, nor is loopback
// unless the list names localhost itself: they are the cloud metadata service
// and the local daemons. A private address is dialled only for a host the
// list names, never through *.
type Proxy struct {
	hosts []string
	// Hint ends the line a refused request gets, saying where hosts are
	// allowed.
	Hint string

	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	usable  func(a netip.Addr, named bool) bool

	mu       sync.Mutex
	seen     map[string]*EgressRecord
	overflow int
	server   *http.Server
	tunnels  map[net.Conn]struct{}
	closed   bool
}

// EgressRecord is one host and port a command asked the proxy for.
type EgressRecord struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Allowed bool   `json:"allowed"`
	Count   int    `json:"count"`
	Reason  string `json:"reason,omitempty"`
}

const (
	egressNotAllowed    = "not_allowed"
	egressLocalAddress  = "local_address"
	egressResolveFailed = "resolve_failed"
	egressBadRequest    = "bad_request"
)

// MaxEgressRecords bounds the distinct host:port pairs a run records; past it
// they are only counted.
const MaxEgressRecords = 64

func NewProxy(hosts []string) *Proxy {
	d := &net.Dialer{Timeout: 15 * time.Second}
	var clean []string
	for _, h := range ExpandHosts(hosts) {
		if CheckHost(h) == nil {
			clean = append(clean, strings.Trim(h, "[]"))
		}
	}
	return &Proxy{
		hosts: clean,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial:    d.DialContext,
		usable:  usableAddr,
		seen:    map[string]*EgressRecord{},
		tunnels: map[net.Conn]struct{}{},
	}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func usableAddr(a netip.Addr, named bool) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsMulticast(), a.IsUnspecified(), a.IsInterfaceLocalMulticast():
		return false
	case a.IsPrivate(), cgnat.Contains(a):
		return named
	}
	return a.IsGlobalUnicast()
}

// match reports whether host is allowed, and whether by name rather than *.
func (p *Proxy) match(host string) (allowed, named bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range p.hosts {
		switch {
		case h == host:
			return true, true
		case strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]):
			return true, true
		case h == "*":
			allowed = true
		}
	}
	return allowed, false
}

func (p *Proxy) target(ctx context.Context, hostport string, defaultPort int) (string, EgressRecord) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		host, portStr = hostport, strconv.Itoa(defaultPort)
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	port, err := strconv.Atoi(portStr)
	rec := EgressRecord{Host: host, Port: port}
	if host == "" || err != nil || port < 1 || port > 65535 {
		rec.Reason = egressBadRequest
		return "", rec
	}
	allowed, named := p.match(host)
	if !allowed {
		rec.Reason = egressNotAllowed
		return "", rec
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err = p.resolve(rctx, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			rec.Reason = egressResolveFailed
			return "", rec
		}
	}
	loopback := named && isLoopbackName(host)
	for _, a := range addrs {
		if loopback && a.Unmap().IsLoopback() {
			continue
		}
		if !p.usable(a, named) {
			rec.Reason = egressLocalAddress
			return "", rec
		}
	}
	rec.Allowed = true
	return net.JoinHostPort(addrs[0].Unmap().String(), strconv.Itoa(port)), rec
}

func (p *Proxy) record(r EgressRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) + "|" + r.Reason
	if cur, ok := p.seen[key]; ok {
		cur.Count++
		return
	}
	if len(p.seen) >= MaxEgressRecords {
		p.overflow++
		return
	}
	r.Count = 1
	p.seen[key] = &r
}

// Records are the distinct requests so far, refused first, and how many
// more went unrecorded past MaxEgressRecords.
func (p *Proxy) Records() ([]EgressRecord, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]EgressRecord, 0, len(p.seen))
	for _, r := range p.seen {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Allowed != out[j].Allowed {
			return !out[i].Allowed
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out, p.overflow
}

// RefusedLine is what a command is told about a refused request.
func (p *Proxy) RefusedLine(r EgressRecord) string {
	why := "not in the allowed hosts"
	switch r.Reason {
	case egressLocalAddress:
		why = "it resolves to a local address"
	case egressResolveFailed:
		why = "it doesn't resolve"
	case egressBadRequest:
		why = "the request isn't one a proxy can forward"
	}
	line := fmt.Sprintf("golem-exec: the shield refused %s: %s.", net.JoinHostPort(r.Host, strconv.Itoa(r.Port)), why)
	if r.Reason == egressNotAllowed && p.Hint != "" {
		line += " " + p.Hint
	}
	return line
}

func (p *Proxy) refuse(w http.ResponseWriter, r EgressRecord) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, p.RefusedLine(r)+"\n")
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		rec := EgressRecord{Host: r.Host, Reason: egressBadRequest}
		p.record(rec)
		p.refuse(w, rec)
		return
	}
	addr, rec := p.target(r.Context(), r.URL.Host, 80)
	p.record(rec)
	if !rec.Allowed {
		p.refuse(w, rec)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		out.Header.Del(h)
	}
	transport := &http.Transport{
		DialContext:           func(ctx context.Context, network, _ string) (net.Conn, error) { return p.dial(ctx, network, addr) },
		ResponseHeaderTimeout: 60 * time.Second,
		DisableKeepAlives:     true,
	}
	resp, err := transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	addr, rec := p.target(r.Context(), r.Host, 443)
	p.record(rec)
	if !rec.Allowed {
		p.refuse(w, rec)
		return
	}
	up, err := p.dial(r.Context(), "tcp", addr)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "tunnel unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
	if !p.track(client, up) {
		client.Close()
		up.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go p.tunnel(client, buf, up)
}

// track registers a tunnel's connections, which the HTTP server no longer
// owns once hijacked, so Close can end them.
func (p *Proxy) track(conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	for _, c := range conns {
		p.tunnels[c] = struct{}{}
	}
	return true
}

func (p *Proxy) tunnel(client net.Conn, buf *bufio.ReadWriter, up net.Conn) {
	defer func() {
		client.Close()
		up.Close()
		p.mu.Lock()
		delete(p.tunnels, client)
		delete(p.tunnels, up)
		p.mu.Unlock()
	}()
	if n := buf.Reader.Buffered(); n > 0 {
		pending, _ := buf.Reader.Peek(n)
		if _, err := up.Write(pending); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// Serve answers on l until Close. The shim calls it for its loopback
// listener and, on Linux, again for the one inside the command's network
// namespace.
func (p *Proxy) Serve(l net.Listener) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		l.Close()
		return
	}
	if p.server == nil {
		p.server = &http.Server{
			Handler:           p,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Minute,
			WriteTimeout:      30 * time.Minute,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
	}
	srv := p.server
	p.mu.Unlock()
	go func() { _ = srv.Serve(l) }()
}

// Close stops the proxy and every tunnel through it.
func (p *Proxy) Close() error {
	p.mu.Lock()
	srv := p.server
	p.closed = true
	for c := range p.tunnels {
		c.Close()
	}
	p.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Close()
}
