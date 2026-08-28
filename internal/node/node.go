// Package node models proxy nodes and converts between share-link URIs and Clash proxy maps.
package node

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"maps"
	"net"
	"strconv"
	"strings"
)

// Node is one proxy from one subscription. At least one of Raw (share-link URI) and Clash (Clash proxy map) is set; both are immutable after creation.
type Node struct {
	Sub   string // source sub name
	Name  string // display name from the source
	Key   string // format-independent dedup key
	Clash map[string]any
	Raw   string
}

// URI returns the node as a share-link line, preferring the original link for fidelity.
// ok is false for Clash proxy types with no URI representation.
func (n *Node) URI() (string, bool) {
	if n.Raw != "" {
		return n.Raw, true
	}
	if n.Clash != nil {
		return BuildURI(n.Clash, n.Name)
	}
	return "", false
}

// ClashMap returns a copy of the Clash proxy map with the given final name.
// ok is false for links that could not be parsed into Clash format.
func (n *Node) ClashMap(name string) (map[string]any, bool) {
	if n.Clash == nil {
		return nil, false
	}
	m := maps.Clone(n.Clash)
	m["name"] = name
	return m, true
}

// FromClashMap wraps a proxy map from a Clash-format subscription.
func FromClashMap(sub string, m map[string]any) *Node {
	return &Node{Sub: sub, Name: str(m["name"]), Key: clashKey(m), Clash: m}
}

// clashKey builds a dedup key from the node identity (type, endpoint, credential, transport)
// so the same node is recognized across base64 and clash subscriptions regardless of cosmetic field differences.
func clashKey(m map[string]any) string {
	typ := str(m["type"])
	var auth string
	switch typ {
	case "ss":
		auth = str(m["cipher"]) + ":" + str(m["password"])
	case "vmess", "vless":
		auth = str(m["uuid"])
	case "trojan", "hysteria2", "hysteria":
		auth = str(m["password"])
	case "tuic":
		auth = str(m["uuid"]) + ":" + str(m["password"])
	case "http", "socks5":
		auth = str(m["username"]) + ":" + str(m["password"])
	default:
		auth = canonicalHash(m)
	}
	return strings.Join([]string{
		typ, str(m["server"]), strconv.Itoa(toInt(m["port"])), str(m["network"]), auth,
	}, "|")
}

// canonicalHash hashes the map minus its name, deterministically.
func canonicalHash(m map[string]any) string {
	c := maps.Clone(m)
	delete(c, "name")
	b, err := json.Marshal(c) // sorts keys
	if err != nil {
		b = []byte(fmt.Sprintf("%v", c))
	}
	h := fnv.New64a()
	h.Write(b)
	return strconv.FormatUint(h.Sum64(), 16)
}

// UniqueNames assigns each node a display name, deduplicating collisions with numeric suffixes (Clash requires unique proxy names).
func UniqueNames(nodes []*Node) []string {
	used := map[string]bool{}
	out := make([]string, len(nodes))
	for i, n := range nodes {
		base := n.Name
		if base == "" {
			base = fallbackName(n)
		}
		name := base
		for k := 2; used[name]; k++ {
			name = fmt.Sprintf("%s %d", base, k)
		}
		used[name] = true
		out[i] = name
	}
	return out
}

func fallbackName(n *Node) string {
	if n.Clash != nil {
		return str(n.Clash["type"]) + " " + net.JoinHostPort(str(n.Clash["server"]), strconv.Itoa(toInt(n.Clash["port"])))
	}
	return "node"
}

func str(v any) string {
	switch s := v.(type) {
	case nil:
		return ""
	case string:
		return s
	default:
		return fmt.Sprint(v)
	}
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}

func toBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true" || b == "1" || b == "tls"
	default:
		return false
	}
}
