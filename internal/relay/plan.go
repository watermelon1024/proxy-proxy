// Package relay turns the relay config into a mihomo config and runs it in the embedded mihomo core.
package relay

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter"

	"github.com/watermelon/proxy-proxy/internal/config"
)

type strategy struct {
	groupType   string // mihomo proxy-group type
	loadBalance string // load-balance strategy, if groupType is load-balance
}

var strategies = map[string]strategy{
	"url-test":           {groupType: "url-test"},
	"fallback":           {groupType: "fallback"},
	"round-robin":        {groupType: "load-balance", loadBalance: "round-robin"},
	"consistent-hashing": {groupType: "load-balance", loadBalance: "consistent-hashing"},
	"sticky-sessions":    {groupType: "load-balance", loadBalance: "sticky-sessions"},
}

// listenerTypes maps a downstream type to its mihomo listener type.
var listenerTypes = map[string]string{"http": "http", "socks5": "socks", "mixed": "mixed"}

// builtinProxies are the names of mihomo's built-in outbounds.
var builtinProxies = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"}

// Plan is the valid, conflict-free part of the relay config. It is immutable.
type Plan struct {
	relays    []relaySpec
	listeners []listenerSpec // sorted by port
}

type relaySpec struct {
	name      string
	strategy  string
	upstreams []upstreamSpec // config order, which fallback relies on
}

// upstreamSpec is exactly one of an inline proxy (validated) or a sub store name.
type upstreamSpec struct {
	proxy map[string]any
	sub   string
}

// endpoint is one validated downstream entry.
type endpoint struct {
	relay    string
	typ      string // downstream type
	listen   string
	port     int
	username string
	password string
}

type listenerSpec struct {
	name   string // mihomo listener name, matched by IN-NAME
	typ    string // mihomo listener type
	listen string
	port   int
	relay  string     // owner of a port without auth
	users  []endpoint // one per username, for a port with auth
}

// NewPlan validates cfg.Relays. An invalid relay, and every relay in a downstream conflict, is left out
// and reported in errs; the other relays are unaffected.
func NewPlan(cfg *config.Config) (*Plan, []error) {
	knownSubs := map[string]bool{}
	for _, name := range cfg.FetchedSubNames() {
		knownSubs[name] = true
	}
	ownPort := listenPort(cfg.Listen)
	nameCount := map[string]int{}
	for _, r := range cfg.Relays {
		nameCount[r.Name]++
	}

	var errs []error
	var relays []relaySpec
	var endpoints []endpoint
	for i, r := range cfg.Relays {
		label := fmt.Sprintf("relay[%d]", i)
		if r.Name != "" {
			label = fmt.Sprintf("relay %q", r.Name)
		}
		if r.Name != "" && nameCount[r.Name] > 1 {
			errs = append(errs, fmt.Errorf("%s: duplicate relay name", label))
			continue
		}
		spec, eps, err := validateRelay(r, knownSubs, ownPort)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
			continue
		}
		relays = append(relays, spec)
		endpoints = append(endpoints, eps...)
	}

	rejected, conflictErrs := findConflicts(endpoints)
	errs = append(errs, conflictErrs...)
	p := &Plan{}
	for _, r := range relays {
		if !rejected[r.name] {
			p.relays = append(p.relays, r)
		}
	}
	var kept []endpoint
	for _, e := range endpoints {
		if !rejected[e.relay] {
			kept = append(kept, e)
		}
	}
	p.listeners = buildListeners(kept)
	return p, errs
}

func listenPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

func validateRelay(r config.Relay, knownSubs map[string]bool, ownPort int) (relaySpec, []endpoint, error) {
	if err := checkRelayName(r.Name); err != nil {
		return relaySpec{}, nil, err
	}
	spec := relaySpec{name: r.Name, strategy: r.Strategy}
	if spec.strategy == "" {
		spec.strategy = "url-test"
	}
	if _, ok := strategies[spec.strategy]; !ok {
		return relaySpec{}, nil, fmt.Errorf(
			"unknown strategy %q (want url-test, fallback, round-robin, consistent-hashing or sticky-sessions)", spec.strategy)
	}

	if len(r.Upstream) == 0 {
		return relaySpec{}, nil, errors.New("no upstream")
	}
	for i, up := range r.Upstream {
		switch {
		case up.Sub != "" && up.SubName == "":
			return relaySpec{}, nil, fmt.Errorf("upstream[%d]: invalid sub URL %q", i, up.Sub)
		case up.Sub != "" && !knownSubs[up.SubName]:
			return relaySpec{}, nil, fmt.Errorf("upstream[%d]: unknown sub %q", i, up.Sub)
		case up.Interval != 0 && !config.IsSubURL(up.Sub):
			return relaySpec{}, nil, fmt.Errorf("upstream[%d]: interval only applies to a sub URL; sub %q refreshes on its own interval", i, up.Sub)
		case up.Sub != "":
			spec.upstreams = append(spec.upstreams, upstreamSpec{sub: up.SubName})
		default:
			if err := checkProxy(up.Proxy); err != nil {
				return relaySpec{}, nil, fmt.Errorf("upstream[%d]: %w", i, err)
			}
			spec.upstreams = append(spec.upstreams, upstreamSpec{proxy: up.Proxy})
		}
	}

	if len(r.Downstream) == 0 {
		return relaySpec{}, nil, errors.New("no downstream")
	}
	eps := make([]endpoint, 0, len(r.Downstream))
	for i, d := range r.Downstream {
		e, err := checkDownstream(d, ownPort)
		if err != nil {
			return relaySpec{}, nil, fmt.Errorf("downstream[%d]: %w", i, err)
		}
		e.relay = r.Name
		eps = append(eps, e)
	}
	if err := checkOwnPorts(eps); err != nil {
		return relaySpec{}, nil, err
	}
	return spec, eps, nil
}

// checkRelayName keeps names usable as the target of a mihomo rule line, which is split on commas.
func checkRelayName(name string) error {
	switch {
	case name == "":
		return errors.New("name is required")
	case strings.Contains(name, ",") || strings.TrimSpace(name) != name:
		return fmt.Errorf("name %q must not contain commas or surrounding spaces", name)
	case slices.Contains(builtinProxies, name):
		return fmt.Errorf("name %q is reserved by mihomo", name)
	}
	return nil
}

// checkProxy loads an upstream proxy the way mihomo will, because one bad proxy fails the whole mihomo config.
func checkProxy(m map[string]any) error {
	m = maps.Clone(m)
	if m == nil {
		m = map[string]any{}
	}
	m["name"] = "check"
	p, err := adapter.ParseProxy(m)
	if err != nil {
		return err
	}
	return p.Close()
}

func checkDownstream(d config.Downstream, ownPort int) (endpoint, error) {
	e := endpoint{typ: d.Type, listen: d.Listen, port: d.Port, username: d.Username, password: d.Password}
	if e.typ == "" {
		e.typ = "mixed"
	}
	if _, ok := listenerTypes[e.typ]; !ok {
		return e, fmt.Errorf("unknown type %q (want http, socks5 or mixed)", e.typ)
	}
	switch {
	case e.port == 0:
		return e, errors.New("port is required")
	case e.port < 0 || e.port > 65535:
		return e, fmt.Errorf("port %d out of range", e.port)
	case e.port == ownPort:
		return e, fmt.Errorf("port %d is proxy-proxy's own listen port", e.port)
	}
	switch {
	case e.username == "" && e.password != "":
		return e, errors.New("password without username")
	case e.username != "" && e.password == "" && e.typ != "http":
		// RFC 1929 requires a non-empty password, and mihomo enforces it.
		return e, errors.New("username without password only works with type http (socks5 needs a password)")
	case strings.ContainsAny(e.username, ",/():") || strings.TrimSpace(e.username) != e.username:
		// mihomo rule lines split on commas, IN-USER splits on slashes, and HTTP basic auth on the first colon.
		return e, fmt.Errorf("username %q must not contain , / ( ) : or surrounding spaces", e.username)
	}
	return e, nil
}

// checkOwnPorts rejects downstreams of one relay that cannot share a listener.
func checkOwnPorts(eps []endpoint) error {
	for i, e := range eps {
		for _, prev := range eps[:i] {
			if prev.port != e.port {
				continue
			}
			switch {
			case prev.listen != e.listen:
				return fmt.Errorf("port %d: listen addresses %q and %q differ", e.port, prev.listen, e.listen)
			case (prev.username == "") != (e.username == ""):
				return fmt.Errorf("port %d: downstreams with and without a username cannot share a port", e.port)
			case prev.username == e.username && prev.password != e.password:
				return fmt.Errorf("port %d: username %q has two different passwords", e.port, e.username)
			}
		}
	}
	return nil
}

// findConflicts finds ports where callers of different relays cannot be told apart, and rejects every relay involved.
// mihomo tells callers apart by (port, username) only: its user table is keyed by username, so passwords don't help.
func findConflicts(eps []endpoint) (rejected map[string]bool, errs []error) {
	rejected = map[string]bool{}
	reject := func(port int, reason string, relays []string) {
		for _, r := range relays {
			rejected[r] = true
		}
		errs = append(errs, fmt.Errorf("port %d: %s; rejecting relays %s", port, reason, quoteList(relays)))
	}

	ports, byPort := groupByPort(eps)
	for _, port := range ports {
		list := byPort[port]
		var relays, listens []string
		noAuth := false
		for _, e := range list {
			relays = appendUnique(relays, e.relay)
			listens = appendUnique(listens, e.listen)
			noAuth = noAuth || e.username == ""
		}
		switch {
		case len(relays) < 2:
			continue
		case len(listens) > 1:
			reject(port, "relays use different listen addresses", relays)
			continue
		case noAuth:
			reject(port, "a port without a username cannot be shared", relays)
			continue
		}

		var usernames []string
		owners := map[string][]string{}
		for _, e := range list {
			usernames = appendUnique(usernames, e.username)
			owners[e.username] = appendUnique(owners[e.username], e.relay)
		}
		for _, u := range usernames {
			if len(owners[u]) > 1 {
				reject(port, fmt.Sprintf("username %q is used by more than one relay", u), owners[u])
			}
		}
	}
	return rejected, errs
}

func buildListeners(eps []endpoint) []listenerSpec {
	ports, byPort := groupByPort(eps)
	out := make([]listenerSpec, 0, len(ports))
	for _, port := range ports {
		list := byPort[port]
		l := listenerSpec{
			name:   "relay-" + strconv.Itoa(port),
			typ:    listenerTypes[list[0].typ],
			listen: list[0].listen,
			port:   port,
		}
		for _, e := range list[1:] {
			if listenerTypes[e.typ] != l.typ {
				l.typ = "mixed" // serves both http and socks5 callers
			}
		}
		if list[0].username == "" {
			l.relay = list[0].relay
		} else {
			seen := map[string]bool{}
			for _, e := range list {
				if !seen[e.username] {
					seen[e.username] = true
					l.users = append(l.users, e)
				}
			}
		}
		out = append(out, l)
	}
	return out
}

// groupByPort returns the sorted ports and the endpoints on each, in input order.
func groupByPort(eps []endpoint) ([]int, map[int][]endpoint) {
	byPort := map[int][]endpoint{}
	for _, e := range eps {
		byPort[e.port] = append(byPort[e.port], e)
	}
	ports := slices.Sorted(maps.Keys(byPort))
	return ports, byPort
}

func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

func quoteList(list []string) string {
	quoted := make([]string, len(list))
	for i, s := range list {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ", ")
}
