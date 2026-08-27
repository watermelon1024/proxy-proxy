package node

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseContent parses a fetched subscription body into nodes.
// typ is "clash", "base64" or "auto".
func ParseContent(sub string, data []byte, typ string) ([]*Node, error) {
	text := strings.TrimPrefix(string(data), "\ufeff")
	switch typ {
	case "clash":
		return parseClash(sub, text)
	case "base64":
		if dec, err := b64Decode(text); err == nil && strings.Contains(string(dec), "://") {
			return parseLines(sub, string(dec))
		}
		// Tolerate providers that serve plain URI lines on a base64 sub.
		return parseLines(sub, text)
	default: // auto
		if strings.Contains(text, "proxies:") {
			if nodes, err := parseClash(sub, text); err == nil {
				return nodes, nil
			}
		}
		if dec, err := b64Decode(text); err == nil && strings.Contains(string(dec), "://") {
			return parseLines(sub, string(dec))
		}
		if strings.Contains(text, "://") {
			return parseLines(sub, text)
		}
		return nil, errors.New("unrecognized subscription format")
	}
}

func parseClash(sub, text string) ([]*Node, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("clash yaml: %w", err)
	}
	if len(doc.Proxies) == 0 {
		return nil, errors.New("clash yaml: no proxies")
	}
	nodes := make([]*Node, 0, len(doc.Proxies))
	for _, m := range doc.Proxies {
		if str(m["type"]) == "" || str(m["server"]) == "" {
			continue
		}
		nodes = append(nodes, FromClashMap(sub, m))
	}
	return nodes, nil
}

func parseLines(sub, text string) ([]*Node, error) {
	var nodes []*Node
	for _, line := range strings.Split(text, "\n") {
		if n := FromURI(sub, strings.TrimSuffix(line, "\r")); n != nil {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("no proxy links found")
	}
	return nodes, nil
}
