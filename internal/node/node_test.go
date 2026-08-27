package node

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSSRoundTrip(t *testing.T) {
	uri := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass:word")) + "@1.2.3.4:8388#My%20Node"
	n := FromURI("s1", uri)
	if n == nil || n.Clash == nil {
		t.Fatalf("parse failed: %+v", n)
	}
	if n.Name != "My Node" || n.Clash["cipher"] != "aes-256-gcm" || n.Clash["password"] != "pass:word" ||
		n.Clash["server"] != "1.2.3.4" || n.Clash["port"] != 8388 {
		t.Fatalf("bad fields: %v", n.Clash)
	}
	built, ok := BuildURI(n.Clash, "renamed")
	if !ok {
		t.Fatal("build failed")
	}
	n2 := FromURI("s2", built)
	if n2.Key != n.Key {
		t.Fatalf("round-trip key mismatch: %q vs %q", n.Key, n2.Key)
	}
}

func TestSSLegacyForm(t *testing.T) {
	uri := "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@5.6.7.8:443")) + "#n"
	n := FromURI("s", uri)
	if n.Clash == nil || n.Clash["server"] != "5.6.7.8" || n.Clash["cipher"] != "chacha20-ietf-poly1305" {
		t.Fatalf("legacy parse failed: %+v", n)
	}
}

func TestVmessRoundTrip(t *testing.T) {
	j := `{"v":"2","ps":"vm1","add":"vm.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}`
	uri := "vmess://" + base64.StdEncoding.EncodeToString([]byte(j))
	n := FromURI("s", uri)
	if n.Clash == nil {
		t.Fatalf("parse failed: %+v", n)
	}
	if n.Name != "vm1" || n.Clash["uuid"] != "b831381d-6324-4d53-ad4f-8cda48b30811" ||
		n.Clash["network"] != "ws" || n.Clash["tls"] != true {
		t.Fatalf("bad fields: %v", n.Clash)
	}
	built, ok := BuildURI(n.Clash, "vm1")
	if !ok {
		t.Fatal("build failed")
	}
	if FromURI("s", built).Key != n.Key {
		t.Fatal("round-trip key mismatch")
	}
}

func TestVlessRealityRoundTrip(t *testing.T) {
	uri := "vless://uuid-1234@9.9.9.9:443?encryption=none&security=reality&sni=www.apple.com&pbk=PUBKEY&sid=ab12&fp=chrome&type=grpc&serviceName=grpc-svc&flow=xtls-rprx-vision#VL"
	n := FromURI("s", uri)
	if n.Clash == nil {
		t.Fatalf("parse failed: %+v", n)
	}
	ro, _ := n.Clash["reality-opts"].(map[string]any)
	if ro["public-key"] != "PUBKEY" || n.Clash["flow"] != "xtls-rprx-vision" || n.Clash["network"] != "grpc" {
		t.Fatalf("bad fields: %v", n.Clash)
	}
	built, _ := BuildURI(n.Clash, "VL")
	if FromURI("s", built).Key != n.Key {
		t.Fatal("round-trip key mismatch")
	}
}

func TestTrojanAndHysteria2(t *testing.T) {
	tr := FromURI("s", "trojan://pw123@t.example.com:443?sni=t.example.com&type=ws&path=%2Ftj#TJ")
	if tr.Clash == nil || tr.Clash["password"] != "pw123" || tr.Clash["network"] != "ws" {
		t.Fatalf("trojan parse failed: %+v", tr)
	}
	hy := FromURI("s", "hysteria2://hpw@h.example.com:8443?sni=h.example.com&obfs=salamander&obfs-password=opw&insecure=1#HY")
	if hy.Clash == nil || hy.Clash["password"] != "hpw" || hy.Clash["obfs"] != "salamander" ||
		hy.Clash["skip-cert-verify"] != true {
		t.Fatalf("hysteria2 parse failed: %+v", hy)
	}
	for _, n := range []*Node{tr, hy} {
		built, ok := BuildURI(n.Clash, n.Name)
		if !ok || FromURI("s", built).Key != n.Key {
			t.Fatalf("round-trip failed for %v", n.Clash["type"])
		}
	}
}

func TestDedupKeyAcrossFormats(t *testing.T) {
	uri := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret")) + "@10.0.0.1:9000#a"
	fromURI := FromURI("s1", uri)
	fromClash := FromClashMap("s2", map[string]any{
		"name": "different name", "type": "ss", "server": "10.0.0.1", "port": 9000,
		"cipher": "aes-128-gcm", "password": "secret", "udp": true,
	})
	if fromURI.Key != fromClash.Key {
		t.Fatalf("cross-format dedup broken: %q vs %q", fromURI.Key, fromClash.Key)
	}
}

func TestUnknownSchemePassThrough(t *testing.T) {
	raw := "tuic://uuid:pass@1.1.1.1:443?congestion_control=bbr#T"
	n := FromURI("s", raw)
	if n == nil || n.Clash != nil || n.Raw != raw || n.Name != "T" {
		t.Fatalf("pass-through broken: %+v", n)
	}
	if u, ok := n.URI(); !ok || u != raw {
		t.Fatal("raw URI not preserved")
	}
}

func TestParseContentAuto(t *testing.T) {
	lines := "trojan://pw@a.example.com:443#A\ntrojan://pw@b.example.com:443#B"
	b64 := base64.StdEncoding.EncodeToString([]byte(lines))
	nodes, err := ParseContent("s", []byte(b64), "auto")
	if err != nil || len(nodes) != 2 {
		t.Fatalf("auto base64: %v, %d nodes", err, len(nodes))
	}
	clash := "proxies:\n  - {name: c1, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: p}\n"
	nodes, err = ParseContent("s", []byte(clash), "auto")
	if err != nil || len(nodes) != 1 || nodes[0].Name != "c1" {
		t.Fatalf("auto clash: %v, %+v", err, nodes)
	}
	if _, err := ParseContent("s", []byte("<html>error page</html>"), "auto"); err == nil {
		t.Fatal("expected error for garbage content")
	}
}

func TestUniqueNames(t *testing.T) {
	nodes := []*Node{{Name: "X"}, {Name: "X"}, {Name: "X 2"}, {Name: ""}}
	names := UniqueNames(nodes)
	if names[0] != "X" || names[1] != "X 2" || names[2] != "X 2 2" || names[3] == "" {
		t.Fatalf("bad names: %v", names)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate name %q", n)
		}
		seen[n] = true
	}
}

func TestClashMapDoesNotMutateOriginal(t *testing.T) {
	n := FromClashMap("s", map[string]any{"name": "orig", "type": "ss", "server": "x", "port": 1, "cipher": "c", "password": "p"})
	m, _ := n.ClashMap("renamed")
	if m["name"] != "renamed" || n.Clash["name"] != "orig" {
		t.Fatal("rename leaked into stored node")
	}
	if !strings.Contains(n.Key, "ss|x|1") {
		t.Fatalf("unexpected key %q", n.Key)
	}
}
