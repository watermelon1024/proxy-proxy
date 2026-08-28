// Package agg stores per-subscription node snapshots and renders aggregated, deduplicated subscription payloads.
package agg

import (
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/watermelon/proxy-proxy/internal/node"
)

type Format string

const (
	FormatBase64 Format = "base64"
	FormatRaw    Format = "raw"
	FormatClash  Format = "clash"
)

// SubState is the latest snapshot for one subscription. Old nodes are kept when a refresh fails.
type SubState struct {
	Nodes        []*node.Node
	Updated      time.Time
	Err          string
	ETag         string
	LastModified string
	UserInfo     string // upstream subscription-userinfo header
}

// Store holds sub snapshots plus a generation-tagged render cache: any sub update bumps the generation,
// and stale cache entries are re-rendered lazily on the next request.
type Store struct {
	mu    sync.Mutex
	subs  map[string]*SubState
	gen   uint64
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	gen  uint64
	body []byte
	etag string
}

func NewStore() *Store {
	return &Store{subs: map[string]*SubState{}, cache: map[string]*cacheEntry{}}
}

func (s *Store) SetNodes(name string, nodes []*node.Node, etag, lastModified, userInfo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[name] = &SubState{
		Nodes: nodes, Updated: time.Now(),
		ETag: etag, LastModified: lastModified, UserInfo: userInfo,
	}
	s.gen++
}

// SetError records a fetch failure but keeps the previous nodes.
func (s *Store) SetError(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.subs[name]
	if st == nil {
		st = &SubState{}
		s.subs[name] = st
	}
	st.Err = err.Error()
}

// Touch marks a sub fresh after an upstream 304.
func (s *Store) Touch(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.subs[name]; st != nil {
		st.Updated = time.Now()
		st.Err = ""
	}
}

// Validators returns the upstream cache validators for a conditional GET.
func (s *Store) Validators(name string) (etag, lastModified string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.subs[name]; st != nil {
		return st.ETag, st.LastModified
	}
	return "", ""
}

// UserInfo returns the upstream subscription-userinfo header for a sub.
func (s *Store) UserInfo(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.subs[name]; st != nil {
		return st.UserInfo
	}
	return ""
}

// Prune drops state for subs no longer configured and invalidates the cache.
func (s *Store) Prune(keep []string) {
	keepSet := map[string]bool{}
	for _, n := range keep {
		keepSet[n] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.subs {
		if !keepSet[name] {
			delete(s.subs, name)
		}
	}
	s.cache = map[string]*cacheEntry{}
	s.gen++
}

// Status is a point-in-time summary for /healthz.
type Status struct {
	Name    string    `json:"name"`
	Nodes   int       `json:"nodes"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

func (s *Store) Statuses(order []string) []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Status, 0, len(order))
	for _, name := range order {
		st := s.subs[name]
		if st == nil {
			out = append(out, Status{Name: name, Error: "not fetched yet"})
			continue
		}
		out = append(out, Status{Name: name, Nodes: len(st.Nodes), Updated: st.Updated, Error: st.Err})
	}
	return out
}

// Render aggregates the given subs (in config order) into one deduplicated subscription payload.
// Results are cached until any sub updates.
func (s *Store) Render(subs []string, format Format, full bool) (body []byte, etag string) {
	key := strings.Join(subs, "\x00") + "|" + string(format) + "|" + strconv.FormatBool(full)

	s.mu.Lock()
	gen := s.gen
	if e := s.cache[key]; e != nil && e.gen == gen {
		s.mu.Unlock()
		return e.body, e.etag
	}
	// Nodes are immutable, so collect refs under the lock and render outside.
	nodes := s.collectLocked(subs)
	s.mu.Unlock()

	body = render(nodes, format, full)
	h := fnv.New64a()
	h.Write(body)
	etag = fmt.Sprintf(`"%x"`, h.Sum64())

	s.mu.Lock()
	if s.gen == gen {
		s.cache[key] = &cacheEntry{gen: gen, body: body, etag: etag}
	}
	s.mu.Unlock()
	return body, etag
}

// collectLocked merges subs in order, keeping the first occurrence of each dedup key.
func (s *Store) collectLocked(subs []string) []*node.Node {
	var nodes []*node.Node
	seen := map[string]bool{}
	for _, name := range subs {
		st := s.subs[name]
		if st == nil {
			continue
		}
		for _, n := range st.Nodes {
			if !seen[n.Key] {
				seen[n.Key] = true
				nodes = append(nodes, n)
			}
		}
	}
	return nodes
}

func render(nodes []*node.Node, format Format, full bool) []byte {
	if format == FormatClash {
		return renderClash(nodes, full)
	}
	lines := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if u, ok := n.URI(); ok {
			lines = append(lines, u)
		}
	}
	text := strings.Join(lines, "\n")
	if format == FormatRaw {
		return []byte(text)
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(text)))
}

func renderClash(nodes []*node.Node, full bool) []byte {
	names := node.UniqueNames(nodes)
	proxies := make([]map[string]any, 0, len(nodes))
	included := make([]string, 0, len(nodes))
	for i, n := range nodes {
		if m, ok := n.ClashMap(names[i]); ok {
			proxies = append(proxies, m)
			included = append(included, names[i])
		}
	}

	var doc any
	if !full {
		doc = map[string]any{"proxies": proxies}
	} else {
		group := included
		if len(group) == 0 {
			group = []string{"DIRECT"}
		}
		doc = map[string]any{
			"mixed-port": 7890,
			"allow-lan":  false,
			"mode":       "rule",
			"log-level":  "info",
			"proxies":    proxies,
			"proxy-groups": []map[string]any{
				{"name": "PROXY", "type": "select", "proxies": append([]string{"AUTO"}, group...)},
				{"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
					"interval": 300, "proxies": group},
			},
			"rules": []string{"MATCH,PROXY"},
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return []byte("proxies: []\n")
	}
	return out
}
