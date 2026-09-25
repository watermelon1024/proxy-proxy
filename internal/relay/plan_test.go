package relay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
	"gopkg.in/yaml.v3"

	"github.com/watermelon/proxy-proxy/internal/config"
	"github.com/watermelon/proxy-proxy/internal/node"
)

const baseConfig = `
subs:
  - url: https://a.example.com/sub
    name: A
keys:
  - key: k
relay:
`

func loadConfig(t *testing.T, relays string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy-proxy.yaml")
	if err := os.WriteFile(path, []byte(baseConfig+relays), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func relayNames(p *Plan) []string {
	var names []string
	for _, r := range p.relays {
		names = append(names, r.name)
	}
	return names
}

const socksUp = `
    upstream:
      - { name: up, type: socks5, server: 127.0.0.1, port: 21081 }`

func TestNewPlanRejectsInvalidRelay(t *testing.T) {
	cases := map[string]struct{ relay, wantErr string }{
		"no name": {`
  - downstream: [{ port: 1080 }]` + socksUp, "name is required"},
		"reserved name": {`
  - name: DIRECT
    downstream: [{ port: 1080 }]` + socksUp, "reserved"},
		"bad strategy": {`
  - name: r
    strategy: random
    downstream: [{ port: 1080 }]` + socksUp, "unknown strategy"},
		"no upstream": {`
  - name: r
    downstream: [{ port: 1080 }]`, "no upstream"},
		"unknown sub": {`
  - name: r
    upstream: [{ sub: B }]
    downstream: [{ port: 1080 }]`, `unknown sub "B"`},
		"interval on named sub": {`
  - name: r
    upstream: [{ sub: A, interval: 1h }]
    downstream: [{ port: 1080 }]`, "interval only applies to a sub URL"},
		"bad proxy": {`
  - name: r
    upstream: [{ type: nosuch, server: x, port: 1 }]
    downstream: [{ port: 1080 }]`, "upstream[0]"},
		"no downstream": {`
  - name: r` + socksUp, "no downstream"},
		"bad type": {`
  - name: r
    downstream: [{ type: vmess, port: 1080 }]` + socksUp, "unknown type"},
		"no port": {`
  - name: r
    downstream: [{ type: http }]` + socksUp, "port is required"},
		"own port": {`
  - name: r
    downstream: [{ port: 8080 }]` + socksUp, "own listen port"},
		"password only": {`
  - name: r
    downstream: [{ port: 1080, password: p }]` + socksUp, "password without username"},
		"username only socks5": {`
  - name: r
    downstream: [{ type: socks5, port: 1080, username: u }]` + socksUp, "only works with type http"},
		"username only mixed": {`
  - name: r
    downstream: [{ port: 1080, username: u }]` + socksUp, "only works with type http"},
		"bad username": {`
  - name: r
    downstream: [{ port: 1080, username: a/b, password: p }]` + socksUp, "must not contain"},
		"own port auth mix": {`
  - name: r
    downstream:
      - { port: 1080 }
      - { port: 1080, username: u, password: p }` + socksUp, "with and without a username"},
		"own username two passwords": {`
  - name: r
    downstream:
      - { type: http, port: 1080, username: u, password: p1 }
      - { type: socks5, port: 1080, username: u, password: p2 }` + socksUp, "two different passwords"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, errs := NewPlan(loadConfig(t, tc.relay))
			if len(p.relays) != 0 || len(p.listeners) != 0 {
				t.Fatalf("relay should be rejected, plan has %v", relayNames(p))
			}
			if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.wantErr) {
				t.Fatalf("errs = %v, want one containing %q", errs, tc.wantErr)
			}
		})
	}
}

func TestNewPlanUsernameOnlyHTTP(t *testing.T) {
	p, errs := NewPlan(loadConfig(t, `
  - name: r
    downstream: [{ type: http, port: 1080, username: u }]`+socksUp))
	if len(errs) != 0 || len(p.relays) != 1 {
		t.Fatalf("username-only http should be accepted: %v", errs)
	}
}

func TestNewPlanConflicts(t *testing.T) {
	cases := map[string]struct {
		relays  string
		kept    []string
		wantErr string
	}{
		"same username, different passwords": {`
  - name: a
    downstream: [{ port: 1080, username: u, password: p1 }]` + socksUp + `
  - name: b
    downstream: [{ port: 1080, username: u, password: p2 }]` + socksUp + `
  - name: c
    downstream: [{ port: 1080, username: v, password: p }]` + socksUp,
			[]string{"c"}, `username "u" is used by more than one relay; rejecting relays "a", "b"`},
		"two ports without auth": {`
  - name: a
    downstream: [{ port: 1080 }]` + socksUp + `
  - name: b
    downstream: [{ type: http, port: 1080 }]` + socksUp,
			nil, "without a username cannot be shared"},
		"no auth next to auth": {`
  - name: a
    downstream: [{ port: 1080 }]` + socksUp + `
  - name: b
    downstream: [{ port: 1080, username: u, password: p }]` + socksUp,
			nil, "without a username cannot be shared"},
		"different listen": {`
  - name: a
    downstream: [{ listen: 127.0.0.1, port: 1080, username: u, password: p }]` + socksUp + `
  - name: b
    downstream: [{ port: 1080, username: v, password: p }]` + socksUp,
			nil, "different listen addresses"},
		"conflict drops the whole relay": {`
  - name: a
    downstream:
      - { port: 1080 }
      - { port: 1081 }` + socksUp + `
  - name: b
    downstream: [{ port: 1080 }]` + socksUp,
			nil, `rejecting relays "a", "b"`},
		"duplicate name": {`
  - name: a
    downstream: [{ port: 1080 }]` + socksUp + `
  - name: a
    downstream: [{ port: 1081 }]` + socksUp,
			nil, "duplicate relay name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, errs := NewPlan(loadConfig(t, tc.relays))
			if got := relayNames(p); strings.Join(got, ",") != strings.Join(tc.kept, ",") {
				t.Fatalf("kept relays = %v, want %v", got, tc.kept)
			}
			if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.wantErr) {
				t.Fatalf("errs = %v, want one containing %q", errs, tc.wantErr)
			}
			for _, l := range p.listeners {
				if l.port == 1081 && len(tc.kept) == 0 {
					t.Fatalf("listener of a rejected relay kept: %+v", l)
				}
			}
		})
	}
}

// render renders the plan and checks that mihomo itself accepts the result.
func render(t *testing.T, p *Plan, nodes nodeSource) (map[string]any, []warning) {
	t.Helper()
	d, warns := p.Render(nodes)
	body, err := d.yaml()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(body); err != nil {
		t.Fatalf("mihomo rejects rendered config: %v\n%s", err, body)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, warns
}

func proxyNames(doc map[string]any) string {
	var names []string
	for _, px := range doc["proxies"].([]any) {
		names = append(names, px.(map[string]any)["name"].(string))
	}
	return strings.Join(names, "|")
}

// noNodes is a store whose subs were all fetched and came back empty.
func noNodes(string) ([]*node.Node, bool) { return nil, true }

func TestRenderSharedPort(t *testing.T) {
	p, errs := NewPlan(loadConfig(t, `
  - name: a
    downstream:
      - { type: http, port: 1080, username: ua, password: pa }
      - { type: socks5, port: 1080, username: ua, password: pa }
      - { type: socks5, port: 1081 }`+socksUp+`
  - name: b
    downstream: [{ type: http, port: 1080, username: ub }]`+socksUp))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	doc, _ := render(t, p, noNodes)

	listeners := doc["listeners"].([]any)
	if len(listeners) != 2 {
		t.Fatalf("want 2 listeners, got %v", listeners)
	}
	shared := listeners[0].(map[string]any)
	if shared["type"] != "mixed" || len(shared["users"].([]any)) != 2 || shared["udp"] != nil {
		t.Fatalf("port 1080 should be an auth-only mixed listener without udp: %v", shared)
	}
	own := listeners[1].(map[string]any)
	if own["type"] != "socks" || own["proxy"] != "a" || own["udp"] != true || len(own["users"].([]any)) != 0 {
		t.Fatalf("port 1081 should be a no-auth socks listener routed to a: %v", own)
	}

	rules := doc["rules"].([]any)
	want := []any{
		"AND,((IN-NAME,relay-1080),(IN-USER,ua)),a",
		"AND,((IN-NAME,relay-1080),(IN-USER,ub)),b",
		"MATCH,REJECT",
	}
	if len(rules) != len(want) {
		t.Fatalf("rules = %v, want %v", rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Fatalf("rules = %v, want %v", rules, want)
		}
	}
}

func TestRenderSubUpstreams(t *testing.T) {
	cfg := loadConfig(t, `
  - name: a
    strategy: round-robin
    upstream:
      - { name: DIRECT, type: socks5, server: 127.0.0.1, port: 1 }
      - sub: A
    downstream: [{ port: 1080 }]
  - name: b
    upstream: [{ sub: A }]
    downstream: [{ port: 1081 }]
  - name: c
    upstream: [{ sub: A }]
    downstream: [{ port: 1082 }]`)
	p, errs := NewPlan(cfg)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	subNodes := []*node.Node{
		node.FromClashMap("A", map[string]any{"name": "a", "type": "socks5", "server": "10.0.0.1", "port": 1080}),
		node.FromClashMap("A", map[string]any{"name": "bad", "type": "nosuch", "server": "10.0.0.2", "port": 1}),
		{Sub: "A", Name: "raw only", Key: "raw|x", Raw: "ssr://x"},
	}
	doc, warns := render(t, p, func(sub string) ([]*node.Node, bool) {
		if sub == "A" {
			return subNodes, true
		}
		return nil, true
	})

	// "DIRECT" and "a" collide with a built-in and a relay name; the sub node is shared, not duplicated.
	if names := proxyNames(doc); names != "DIRECT 2|a 2" {
		t.Fatalf("proxy names = %v", names)
	}
	// One warning per relay using sub A: the unknown type and the raw-only link are skipped.
	if len(warns) != 3 || warns[0].args[5] != 2 {
		t.Fatalf("warnings = %v", warns)
	}

	groups := map[string]map[string]any{}
	for _, g := range doc["proxy-groups"].([]any) {
		gm := g.(map[string]any)
		groups[gm["name"].(string)] = gm
	}
	if g := groups["a"]; g["type"] != "load-balance" || g["strategy"] != "round-robin" || len(g["proxies"].([]any)) != 2 {
		t.Fatalf("group a = %v", g)
	}
	if g := groups["b"]; g["type"] != "select" || len(g["proxies"].([]any)) != 1 {
		t.Fatalf("group b = %v", g)
	}
	if g := groups["c"]; g["proxies"].([]any)[0] != "a 2" {
		t.Fatalf("relays b and c should share the sub node: %v", g)
	}
}

func TestRenderNoUpstreamRejects(t *testing.T) {
	p, _ := NewPlan(loadConfig(t, `
  - name: a
    upstream: [{ sub: A }]
    downstream: [{ port: 1080 }]`))
	doc, warns := render(t, p, noNodes)
	if len(warns) != 1 || !strings.Contains(warns[0].msg, "no usable upstream") {
		t.Fatalf("warnings = %v", warns)
	}
	if l := doc["listeners"].([]any)[0].(map[string]any); l["proxy"] != "REJECT" {
		t.Fatalf("relay without upstream nodes should reject: %v", l)
	}
	if groups := doc["proxy-groups"].([]any); len(groups) != 0 {
		t.Fatalf("no group expected: %v", groups)
	}

	// Before the sub's first fetch finishes, the relay rejects callers without warning.
	doc, warns = render(t, p, func(string) ([]*node.Node, bool) { return nil, false })
	if len(warns) != 0 {
		t.Fatalf("warnings while the sub is still loading = %v", warns)
	}
	if l := doc["listeners"].([]any)[0].(map[string]any); l["proxy"] != "REJECT" {
		t.Fatalf("relay waiting for its sub should reject: %v", l)
	}
}

func TestRenderInlineProxiesKeepNames(t *testing.T) {
	p, errs := NewPlan(loadConfig(t, `
  - name: a
    upstream: [{ name: out-a, type: direct }]
    downstream: [{ port: 1080 }]
  - name: b
    upstream: [{ name: out-b, type: direct }]
    downstream: [{ port: 1081 }]
  - name: c
    upstream: [{ name: out-a, type: direct }]
    downstream: [{ port: 1082 }]`))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	doc, _ := render(t, p, noNodes)
	if names := proxyNames(doc); names != "out-a|out-b" {
		t.Fatalf("proxy names = %v", names)
	}
}
