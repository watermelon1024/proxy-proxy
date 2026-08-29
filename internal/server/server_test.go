package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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
