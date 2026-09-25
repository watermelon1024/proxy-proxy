package relay

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/watermelon/proxy-proxy/internal/node"
)

var errNoClash = errors.New("link has no Clash form")

// warning is a problem found while rendering. Manager logs warnings only when it applies the config,
// so re-rendering an unchanged config does not repeat them.
type warning struct {
	msg  string
	args []any
}

// generalConfig holds the settings mihomo gets once at startup; they never change afterwards.
var generalConfig = map[string]any{
	"mode":              "rule",
	"log-level":         "silent", // Manager forwards mihomo's log events to slog instead
	"find-process-mode": "off",
	"profile":           map[string]any{"store-selected": false},
}

// desired is the mihomo state for a plan, in mihomo config syntax, plus the routing facts
// the core needs to tell which open connections a change affects.
type desired struct {
	proxies   []map[string]any // each with a unique name
	groups    []map[string]any // one per relay with usable upstreams, named after the relay
	listeners []map[string]any
	rules     []string

	routes  map[route]routeTarget
	members map[string][]string // group name -> proxy names
}

// route identifies callers: a listener plus the username they authenticated with ("" without auth).
type route struct{ listener, username string }

type routeTarget struct{ password, target string }

// yaml renders d as a complete mihomo config, for change detection and tests.
func (d *desired) yaml() ([]byte, error) {
	doc := maps.Clone(generalConfig)
	doc["proxies"] = d.proxies
	doc["proxy-groups"] = d.groups
	doc["listeners"] = d.listeners
	doc["rules"] = d.rules
	return yaml.Marshal(doc)
}

// nodeSource returns the current nodes of a sub, and whether a fetch of it has finished yet.
type nodeSource func(sub string) (nodes []*node.Node, fetched bool)

// Render builds the mihomo state for the plan.
// Sub nodes mihomo cannot load are skipped, and a relay left without upstreams rejects its callers.
func (p *Plan) Render(nodes nodeSource) (*desired, []warning) {
	reg := &proxyRegistry{used: map[string]bool{}, byContent: map[string]*registered{}}
	for _, name := range builtinProxies {
		reg.used[name] = true
	}
	for _, r := range p.relays {
		reg.used[r.name] = true // groups share the proxy namespace
	}

	d := &desired{
		groups:  []map[string]any{},
		routes:  map[route]routeTarget{},
		members: map[string][]string{},
	}
	target := map[string]string{}
	for _, r := range p.relays {
		members, pending := reg.members(r, nodes)
		if len(members) == 0 {
			if !pending { // a sub still on its first fetch is not a problem yet
				reg.warns = append(reg.warns, warning{"relay has no usable upstream; rejecting its connections", []any{"relay", r.name}})
			}
			target[r.name] = "REJECT"
			continue
		}
		target[r.name] = r.name
		d.groups = append(d.groups, relayGroup(r, members))
		d.members[r.name] = members
	}

	d.listeners = make([]map[string]any, 0, len(p.listeners))
	for _, l := range p.listeners {
		m := map[string]any{"name": l.name, "type": l.typ, "port": l.port}
		if l.listen != "" {
			m["listen"] = l.listen
		}
		if l.relay != "" {
			// An empty list disables auth; omitting users would fall back to mihomo's global authentication.
			m["users"] = []any{}
			m["proxy"] = target[l.relay]
			d.routes[route{l.name, ""}] = routeTarget{"", target[l.relay]}
			// UDP only here: socks5 UDP packets carry no username, so they could not be routed by user.
			if l.typ != "http" {
				m["udp"] = true
			}
		} else {
			users := make([]map[string]any, 0, len(l.users))
			for _, u := range l.users {
				users = append(users, map[string]any{"username": u.username, "password": u.password})
				// IN-USER alone matches the username on any listener, so pin the rule to this port.
				d.rules = append(d.rules, fmt.Sprintf("AND,((IN-NAME,%s),(IN-USER,%s)),%s", l.name, u.username, target[u.relay]))
				d.routes[route{l.name, u.username}] = routeTarget{u.password, target[u.relay]}
			}
			m["users"] = users
		}
		d.listeners = append(d.listeners, m)
	}
	d.rules = append(d.rules, "MATCH,REJECT")
	d.proxies = reg.proxies
	return d, reg.warns
}

func relayGroup(r relaySpec, members []string) map[string]any {
	if len(members) == 1 {
		return map[string]any{"name": r.name, "type": "select", "proxies": members}
	}
	// Health checks keep mihomo's defaults.
	s := strategies[r.strategy]
	g := map[string]any{"name": r.name, "type": s.groupType, "proxies": members}
	if s.loadBalance != "" {
		g["strategy"] = s.loadBalance
	}
	return g
}

// proxyRegistry collects the mihomo proxies of all relays, loading each distinct proxy once.
type proxyRegistry struct {
	used      map[string]bool // taken proxy and group names
	byContent map[string]*registered
	proxies   []map[string]any
	warns     []warning
}

type registered struct {
	name string
	err  error
}

// members returns the proxy names of one relay's upstreams, in config order.
// members registers the upstreams of r and returns their proxy names. pending reports that some sub of r
// has not been fetched yet.
func (g *proxyRegistry) members(r relaySpec, nodes nodeSource) (names []string, pending bool) {
	add := func(n *node.Node, inline bool) error {
		name, err := g.add(n, inline)
		if err == nil {
			names = appendUnique(names, name)
		}
		return err
	}
	for _, up := range r.upstreams {
		if up.proxy != nil {
			_ = add(node.FromClashMap("", up.proxy), true) // validated by NewPlan
			continue
		}
		subNodes, fetched := nodes(up.sub)
		pending = pending || !fetched
		skipped := 0
		var firstErr error
		for _, n := range subNodes {
			if err := add(n, false); err != nil {
				skipped++
				firstErr = cmp.Or(firstErr, err)
			}
		}
		if skipped > 0 {
			g.warns = append(g.warns, warning{"relay skipped sub nodes mihomo cannot load",
				[]any{"relay", r.name, "sub", up.sub, "skipped", skipped, "err", firstErr}})
		}
	}
	return names, pending
}

// add registers a proxy once and returns its mihomo name. Sub nodes are shared by content, so the same
// node from two subs is loaded once; inline proxies are shared only if their names match too.
func (g *proxyRegistry) add(n *node.Node, inline bool) (string, error) {
	if n.Clash == nil {
		return "", errNoClash
	}
	key := contentKey(n.Clash)
	if inline {
		key = "inline " + fmt.Sprint(n.Clash)
	}
	if reg, ok := g.byContent[key]; ok {
		return reg.name, reg.err
	}
	reg := &registered{}
	g.byContent[key] = reg
	if reg.err = checkProxy(n.Clash); reg.err != nil {
		return "", reg.err
	}
	reg.name = uniqueName(displayName(n), g.used)
	m, _ := n.ClashMap(reg.name)
	g.proxies = append(g.proxies, m)
	return reg.name, nil
}

// contentKey identifies a proxy by its full config minus the name.
// It is stricter than node.Key, which ignores fields like transport paths.
func contentKey(m map[string]any) string {
	c := maps.Clone(m)
	delete(c, "name")
	return fmt.Sprint(c) // fmt prints map keys sorted
}

func displayName(n *node.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return fmt.Sprintf("%v %v:%v", n.Clash["type"], n.Clash["server"], n.Clash["port"])
}

func uniqueName(base string, used map[string]bool) string {
	name := base
	for k := 2; used[name]; k++ {
		name = base + " " + strconv.Itoa(k)
	}
	used[name] = true
	return name
}
