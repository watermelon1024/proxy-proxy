package agg

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/watermelon/proxy-proxy/internal/config"
	"github.com/watermelon/proxy-proxy/internal/node"
)

func ssURI(pw, host, name string) string {
	return "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:"+pw)) + "@" + host + "#" + name
}

func TestRenderDedupAndFilter(t *testing.T) {
	s := NewStore()
	// subA and subB share the pw1 node; clash-sourced duplicate has another name.
	s.SetNodes("subA", []*node.Node{
		node.FromURI("subA", ssURI("pw1", "1.1.1.1:443", "a1")),
		node.FromURI("subA", ssURI("pw2", "2.2.2.2:443", "a2")),
	}, "", "", "")
	s.SetNodes("subB", []*node.Node{
		node.FromClashMap("subB", map[string]any{
			"name": "dup of a1", "type": "ss", "server": "1.1.1.1", "port": 443,
			"cipher": "aes-256-gcm", "password": "pw1",
		}),
		node.FromURI("subB", ssURI("pw3", "3.3.3.3:443", "b1")),
	}, "", "", "")

	body, _ := s.Render([]string{"subA", "subB"}, FormatRaw, false)
	lines := strings.Split(string(body), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 deduped nodes, got %d:\n%s", len(lines), body)
	}

	body, _ = s.Render([]string{"subB"}, FormatRaw, false)
	if lines := strings.Split(string(body), "\n"); len(lines) != 2 {
		t.Fatalf("filtered render want 2 nodes, got %d", len(lines))
	}

	body, _ = s.Render([]string{"subA", "subB"}, FormatClash, false)
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Proxies) != 3 {
		t.Fatalf("clash render: %v, %d proxies", err, len(doc.Proxies))
	}

	// base64 format must decode back to the raw lines.
	b64, _ := s.Render([]string{"subB"}, FormatBase64, false)
	dec, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil || !strings.Contains(string(dec), "3.3.3.3") {
		t.Fatalf("base64 render broken: %v %q", err, dec)
	}
}

func TestRenderCacheInvalidation(t *testing.T) {
	s := NewStore()
	s.SetNodes("a", []*node.Node{node.FromURI("a", ssURI("p", "1.1.1.1:1", "n"))}, "", "", "")
	_, etag1 := s.Render([]string{"a"}, FormatRaw, false)
	_, etag2 := s.Render([]string{"a"}, FormatRaw, false)
	if etag1 != etag2 {
		t.Fatal("cache should return identical etag")
	}
	s.SetNodes("a", []*node.Node{node.FromURI("a", ssURI("p2", "2.2.2.2:2", "n2"))}, "", "", "")
	_, etag3 := s.Render([]string{"a"}, FormatRaw, false)
	if etag3 == etag1 {
		t.Fatal("cache not invalidated after update")
	}
}

func TestFetchBase64AndConditional(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(
		ssURI("pw", "1.2.3.4:443", "n1") + "\n" + "trojan://p@t.example.com:443#n2"))
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"v1"`)
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=100")
		w.Write([]byte(payload))
	}))
	defer ts.Close()

	store := NewStore()
	cfg := &config.Config{UserAgent: "test", Timeout: config.Duration(0)}
	cfg.Timeout = config.Duration(1e10)
	r := NewRefresher(store, cfg)
	sub := config.Sub{Name: "s1", URL: ts.URL, Type: "auto"}

	if err := r.Fetch(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	if got := store.Statuses([]string{"s1"}); got[0].Nodes != 2 {
		t.Fatalf("want 2 nodes, got %+v", got)
	}
	if store.UserInfo("s1") == "" {
		t.Fatal("userinfo header not stored")
	}
	if err := r.Fetch(context.Background(), sub); err != nil {
		t.Fatal(err) // second fetch should be a 304, not an error
	}
	if hits != 2 {
		t.Fatalf("want 2 upstream hits, got %d", hits)
	}
}

func TestFetchErrorKeepsOldNodes(t *testing.T) {
	fail := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(ssURI("p", "1.1.1.1:1", "n")))))
	}))
	defer ts.Close()

	store := NewStore()
	r := NewRefresher(store, &config.Config{UserAgent: "t", Timeout: config.Duration(1e10)})
	sub := config.Sub{Name: "s", URL: ts.URL, Type: "base64"}
	if err := r.Fetch(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := r.Fetch(context.Background(), sub); err == nil {
		t.Fatal("expected error")
	}
	store.SetError("s", context.DeadlineExceeded)
	if got := store.Statuses([]string{"s"}); got[0].Nodes != 1 || got[0].Error == "" {
		t.Fatalf("old nodes should survive a failed refresh: %+v", got)
	}
}
