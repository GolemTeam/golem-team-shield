package shield

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testProxy serves hosts with names resolved from dns, and lets loopback
// stand in for the internet so a test upstream can be reached.
func testProxy(t *testing.T, hosts []string, dns map[string]string) (*Proxy, string) {
	t.Helper()
	p := NewProxy(hosts)
	p.Hint = "Allow it in ~/.golem/shield.json."
	p.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := dns[host]; ok {
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		return nil, errors.New("no such host")
	}
	p.usable = func(a netip.Addr, named bool) bool { return a.IsLoopback() || usableAddr(a, named) }
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.Serve(ln)
	t.Cleanup(func() { p.Close() })
	return p, ln.Addr().String()
}

func connect(t *testing.T, proxy, target string) (net.Conn, *http.Response) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, resp
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func TestProxyTunnelsAnAllowedHostAndRefusesTheRest(t *testing.T) {
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(echo)
	p, addr := testProxy(t, []string{"github.com"}, map[string]string{"github.com": "127.0.0.1", "evil.test": "127.0.0.1"})

	c, resp := connect(t, addr, "github.com:"+port)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed CONNECT answered %d", resp.StatusCode)
	}
	fmt.Fprint(c, "ping")
	buf := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Errorf("tunnel echoed %q, %v", buf, err)
	}
	c.Close()

	c, resp = connect(t, addr, "evil.test:443")
	body, _ := io.ReadAll(resp.Body)
	c.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted CONNECT answered %d", resp.StatusCode)
	}
	if want := "golem-exec: the shield refused evil.test:443: not in the allowed hosts. Allow it in ~/.golem/shield.json.\n"; string(body) != want {
		t.Errorf("refusal %q", body)
	}
	recs, overflow := p.Records()
	if overflow != 0 || len(recs) != 2 || recs[0].Host != "evil.test" || recs[0].Allowed || recs[0].Reason != egressNotAllowed || !recs[1].Allowed {
		t.Errorf("records %+v", recs)
	}
}

func TestProxyForwardsPlainHTTP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached the upstream")
		}
		fmt.Fprint(w, "hello")
	}))
	defer up.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	_, addr := testProxy(t, []string{"*.example.com"}, map[string]string{"pkg.example.com": "127.0.0.1", "example.com": "127.0.0.1"})
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get("http://pkg.example.com:" + port + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Errorf("got %d %q", resp.StatusCode, body)
	}
	resp, err = client.Get("http://example.com:" + port + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("*.example.com let the apex through: %d", resp.StatusCode)
	}
}

func TestProxyNeverDialsLocalAddressesAndPrivateOnlyByName(t *testing.T) {
	p := NewProxy([]string{"*", "registry.corp.example", "*.corp.example"})
	p.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		return map[string][]netip.Addr{
			"registry.corp.example": {netip.MustParseAddr("10.1.2.3")},
			"git.corp.example":      {netip.MustParseAddr("10.1.2.4")},
			"internal.other":        {netip.MustParseAddr("192.168.1.9")},
			"rebind.test":           {netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("127.0.0.1")},
			"metadata.test":         {netip.MustParseAddr("169.254.169.254")},
			"public.test":           {netip.MustParseAddr("93.184.215.14")},
		}[host], nil
	}
	cases := []struct {
		target string
		ok     bool
		reason string
	}{
		{"registry.corp.example:443", true, ""},
		{"git.corp.example:443", true, ""},
		{"internal.other:443", false, egressLocalAddress},
		{"rebind.test:443", false, egressLocalAddress},
		{"metadata.test:80", false, egressLocalAddress},
		{"169.254.169.254:80", false, egressLocalAddress},
		{"127.0.0.1:39393", false, egressLocalAddress},
		{"[::1]:39393", false, egressLocalAddress},
		{"public.test:8443", true, ""},
		{"nowhere.test:443", false, egressResolveFailed},
		{"public.test:0", false, egressBadRequest},
	}
	for _, c := range cases {
		addr, rec := p.target(context.Background(), c.target, 443)
		if rec.Allowed != c.ok || rec.Reason != c.reason || (c.ok && addr == "") {
			t.Errorf("%s: %+v %q", c.target, rec, addr)
		}
	}
}

func TestProxyRecordsAreBounded(t *testing.T) {
	p := NewProxy(nil)
	for i := 0; i < MaxEgressRecords+5; i++ {
		p.record(EgressRecord{Host: fmt.Sprintf("h%d.test", i), Port: 443, Reason: egressNotAllowed})
	}
	p.record(EgressRecord{Host: "h0.test", Port: 443, Reason: egressNotAllowed})
	recs, overflow := p.Records()
	if len(recs) != MaxEgressRecords || overflow != 5 {
		t.Errorf("%d records, %d overflow", len(recs), overflow)
	}
	for _, r := range recs {
		if r.Host == "h0.test" && r.Count != 2 {
			t.Errorf("repeat not counted: %+v", r)
		}
	}
}

func TestProxyCloseEndsOpenTunnels(t *testing.T) {
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(echo)
	p, addr := testProxy(t, []string{"github.com"}, map[string]string{"github.com": "127.0.0.1"})
	c, resp := connect(t, addr, "github.com:"+port)
	defer c.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT %d", resp.StatusCode)
	}
	p.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		t.Errorf("tunnel still open after Close: %v", err)
	}
}

func TestProxyReachesLoopbackOnlyWhenTheListNamesIt(t *testing.T) {
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		return map[string][]netip.Addr{
			"localhost":   {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
			"rebind.test": {netip.MustParseAddr("127.0.0.1")},
		}[host], nil
	}
	cases := []struct {
		hosts  []string
		target string
		ok     bool
	}{
		{[]string{"localhost"}, "localhost:3000", true},
		{[]string{"127.0.0.1"}, "127.0.0.1:5432", true},
		{[]string{"localhost"}, "127.0.0.1:5432", false},
		{[]string{"*"}, "localhost:3000", false},
		{[]string{"localhost", "rebind.test"}, "rebind.test:80", false},
		{[]string{"localhost", "169.254.169.254"}, "169.254.169.254:80", false},
	}
	for _, c := range cases {
		p := NewProxy(c.hosts)
		p.resolve = resolve
		if _, rec := p.target(context.Background(), c.target, 443); rec.Allowed != c.ok {
			t.Errorf("%v → %s: %+v", c.hosts, c.target, rec)
		}
	}
}
