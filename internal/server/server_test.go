package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/watermelon/proxy-proxy/internal/agg"
	"github.com/watermelon/proxy-proxy/internal/config"
	"github.com/watermelon/proxy-proxy/internal/node"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := agg.NewStore()
	store.SetNodes("A", []*node.Node{
		node.FromURI("A", "trojan://pw@a.example.com:443?sni=a.example.com#NodeA"),
	}, "", "", "")
	store.SetNodes("B", []*node.Node{
		node.FromURI("B", "trojan://pw@b.example.com:443?sni=b.example.com#NodeB"),
	}, "", "", "")

	cfg := &config.Config{
		Subs: []config.Sub{
			{Name: "A", URL: "https://a/s", Interval: config.Duration(3600e9)},
			{Name: "B", URL: "https://b/s", Interval: config.Duration(3600e9)},
		},
		Keys: []config.Key{
			{Key: "pp-all", Resolved: []string{"A", "B"}},
			{Key: "pp-a", Resolved: []string{"A"}},
		},
	}
	var ptr atomic.Pointer[config.Config]
	ptr.Store(cfg)
	ts := httptest.NewServer((&Server{Store: store, Cfg: &ptr}).Routes())
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, url string, ua string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	return resp, string(buf[:n])
}

func TestKeyAuthAndFiltering(t *testing.T) {
	ts := testServer(t)

	resp, _ := get(t, ts.URL+"/sub", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing key: want 404, got %d", resp.StatusCode)
	}
	resp, _ = get(t, ts.URL+"/sub?key=wrong", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bad key: want 404, got %d", resp.StatusCode)
	}

	_, body := get(t, ts.URL+"/sub?key=pp-all&format=raw", "")
	if !strings.Contains(body, "a.example.com") || !strings.Contains(body, "b.example.com") {
		t.Fatalf("pp-all should see both subs:\n%s", body)
	}
	_, body = get(t, ts.URL+"/sub?key=pp-a&format=raw", "")
	if !strings.Contains(body, "a.example.com") || strings.Contains(body, "b.example.com") {
		t.Fatalf("pp-a must only see sub A:\n%s", body)
	}
}

func TestFormatNegotiation(t *testing.T) {
	ts := testServer(t)

	resp, body := get(t, ts.URL+"/sub?key=pp-all", "v2rayN/6.0")
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("want base64 for generic UA, got %s", resp.Header.Get("Content-Type"))
	}
	if _, err := base64.StdEncoding.DecodeString(body); err != nil {
		t.Fatalf("body is not base64: %v", err)
	}

	resp, body = get(t, ts.URL+"/sub?key=pp-all", "clash-verge/v1.6.6 mihomo")
	if !strings.Contains(resp.Header.Get("Content-Type"), "yaml") {
		t.Fatalf("want yaml for clash UA, got %s", resp.Header.Get("Content-Type"))
	}
	if !strings.HasPrefix(body, "proxies:") {
		t.Fatalf("want proxies-only yaml:\n%s", body)
	}

	_, body = get(t, ts.URL+"/sub?key=pp-all&format=clash&full=1", "")
	if !strings.Contains(body, "proxy-groups:") || !strings.Contains(body, "MATCH,PROXY") {
		t.Fatalf("full config missing groups/rules:\n%s", body)
	}
}

func TestETag304(t *testing.T) {
	ts := testServer(t)
	resp, _ := get(t, ts.URL+"/sub?key=pp-all&format=raw", "")
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing etag")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/sub?key=pp-all&format=raw", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("want 304, got %d", resp2.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	ts := testServer(t)
	resp, body := get(t, ts.URL+"/healthz", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"nodes":1`) {
		t.Fatalf("healthz: %d %s", resp.StatusCode, body)
	}
}

func TestClientIP(t *testing.T) {
	extra := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	cases := []struct {
		remote, xff, realIP string
		trusted             []netip.Prefix
		want                string
	}{
		{"203.0.113.9:1234", "1.2.3.4", "", nil, "203.0.113.9"}, // public peer: never trust headers
		{"192.168.1.5:1234", "", "", nil, "192.168.1.5"},
		{"192.168.1.5:1234", "1.2.3.4", "", nil, "1.2.3.4"},
		{"192.168.1.5:1234", "6.6.6.6, 1.2.3.4", "", nil, "1.2.3.4"}, // spoofed left entry ignored
		{"192.168.1.5:1234", "10.0.0.7, 172.16.0.1", "", nil, "10.0.0.7"},
		{"[::1]:1234", "", "1.2.3.4", nil, "1.2.3.4"},
		// trusted_proxies extends trust: as the peer and as an XFF hop
		{"100.64.0.3:1234", "1.2.3.4", "", extra, "1.2.3.4"},
		{"100.64.0.3:1234", "1.2.3.4", "", nil, "100.64.0.3"},
		{"192.168.1.5:1234", "1.2.3.4, 100.64.0.3", "", extra, "1.2.3.4"},
	}
	for _, c := range cases {
		r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.realIP != "" {
			r.Header.Set("X-Real-Ip", c.realIP)
		}
		if got := clientIP(r, c.trusted); got != c.want {
			t.Errorf("clientIP(%s, xff=%q, rip=%q) = %q, want %q", c.remote, c.xff, c.realIP, got, c.want)
		}
	}
}
