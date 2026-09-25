package relay

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"gopkg.in/yaml.v3"
)

// drainTimeout is how long an open connection may keep using a route or upstream that a
// config change replaced or removed before it is closed.
const drainTimeout = 5 * time.Minute

// core drives the embedded mihomo. executor.ApplyConfig rebuilds every proxy and group on each
// call; core instead keeps the ones whose config is unchanged, so their handshakes and
// health-check results survive, and it builds only what changed.
// mihomo keeps global state, so a process must have at most one core.
type core struct {
	started  bool
	builtins map[string]C.Proxy // DIRECT, REJECT, ...
	current  *desired
	proxies  map[string]liveProxy
	groups   map[string]liveGroup
	draining map[string]time.Time // connection ID -> when to close it
}

type liveProxy struct {
	key   string // the mihomo config it was built from
	proxy C.Proxy
}

type liveGroup struct {
	key      string
	proxy    C.Proxy
	provider P.ProxyProvider // runs the group's health checks
}

type applyStats struct {
	reused, built, draining int
}

func newCore() *core {
	return &core{proxies: map[string]liveProxy{}, groups: map[string]liveGroup{}, draining: map[string]time.Time{}}
}

// start applies generalConfig once; proxies, groups, rules and listeners all go through apply.
func (c *core) start() error {
	body, err := yaml.Marshal(generalConfig)
	if err != nil {
		return err
	}
	cfg, err := executor.ParseWithBytes(body)
	if err != nil {
		return err
	}
	// This config has no proxies, so the GLOBAL group mihomo adds to it holds no upstream alive.
	executor.ApplyConfig(cfg, false)
	c.builtins = cfg.Proxies
	c.started = true
	return nil
}

// apply switches mihomo to d. If it fails, mihomo keeps its current state.
func (c *core) apply(d *desired) (applyStats, error) {
	var st applyStats
	all := maps.Clone(c.builtins)

	proxies := make(map[string]liveProxy, len(d.proxies))
	for _, m := range d.proxies {
		name, _ := m["name"].(string)
		key := fmt.Sprint(m)
		lp, ok := c.proxies[name]
		if ok && lp.key == key {
			st.reused++
		} else {
			p, err := adapter.ParseProxy(m, adapter.WithTunnelForAPI(tunnel.Tunnel))
			if err != nil {
				return st, fmt.Errorf("proxy %q: %w", name, err)
			}
			lp = liveProxy{key: key, proxy: p}
			st.built++
		}
		proxies[name] = lp
		all[name] = lp.proxy
	}

	groups := make(map[string]liveGroup, len(d.groups))
	providers := map[string]P.ProxyProvider{}
	var fresh []P.ProxyProvider
	for _, m := range d.groups {
		name, _ := m["name"].(string)
		key := fmt.Sprint(m)
		lg, ok := c.groups[name]
		// A group holds its member objects, so it is rebuilt whenever one of them is.
		if !ok || lg.key != key || !c.sameProxies(d.members[name], proxies) {
			g, err := outboundgroup.ParseProxyGroup(m, all, providers, nil, nil)
			if err != nil {
				return st, fmt.Errorf("group %q: %w", name, err)
			}
			lg = liveGroup{key: key, proxy: adapter.NewProxy(g), provider: providers[name]}
			fresh = append(fresh, lg.provider)
		}
		providers[name] = lg.provider
		groups[name] = lg
		all[name] = lg.proxy
	}

	rules := make([]C.Rule, 0, len(d.rules))
	for _, line := range d.rules {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		r, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			return st, fmt.Errorf("rule %q: %w", line, err)
		}
		rules = append(rules, RW.NewRuleWrapper(r))
	}

	listeners := make(map[string]C.InboundListener, len(d.listeners))
	for _, m := range d.listeners {
		l, err := listener.ParseListener(m)
		if err != nil {
			return st, fmt.Errorf("listener %v: %w", m["name"], err)
		}
		listeners[l.Name()] = l
	}

	// Everything parsed; switch over. Proxies go first so new rules never point at missing targets.
	for _, pd := range fresh {
		_ = pd.Initial() // starts health checks; cannot fail for a group's own provider
	}
	tunnel.UpdateProxies(all, providers)
	tunnel.UpdateRules(rules, nil, nil)
	// Restarts only listeners whose settings changed; accepted connections outlive their listener.
	listener.PatchInboundListeners(listeners, tunnel.Tunnel, true)
	for name, old := range c.groups {
		if groups[name].proxy != old.proxy {
			closeProvider(old.provider) // stops its health checks; open connections don't go through groups
		}
	}
	st.draining = c.markStale(d, proxies)
	c.current, c.proxies, c.groups = d, proxies, groups
	return st, nil
}

// sameProxies reports whether every named proxy is still the object currently in use.
func (c *core) sameProxies(names []string, next map[string]liveProxy) bool {
	for _, n := range names {
		if old, ok := c.proxies[n]; !ok || old.proxy != next[n].proxy {
			return false
		}
	}
	return true
}

// markStale schedules closing of open connections that d moves off their route or upstream:
// the caller's credentials or relay changed, or the upstream was replaced or dropped from the relay.
// Replaced objects stay alive while such connections last, so they get drainTimeout, not forever.
func (c *core) markStale(d *desired, proxies map[string]liveProxy) int {
	if c.current == nil {
		return 0
	}
	deadline := time.Now().Add(drainTimeout)
	n := 0
	statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
		if _, ok := c.draining[t.ID()]; !ok && c.stale(t.Info(), d, proxies) {
			c.draining[t.ID()] = deadline
			n++
		}
		return true
	})
	return n
}

func (c *core) stale(info *statistic.TrackerInfo, d *desired, proxies map[string]liveProxy) bool {
	r := route{info.Metadata.InName, info.Metadata.InUser}
	if c.current.routes[r] != d.routes[r] {
		return true
	}
	chain := info.Chain // the upstream proxy first, the relay group last
	if len(chain) == 0 {
		return false
	}
	proxy, group := chain[0], chain[len(chain)-1]
	if !slices.Contains(d.members[group], proxy) {
		return true
	}
	return c.proxies[proxy].proxy != proxies[proxy].proxy
}

// sweep closes draining connections that are past their deadline and returns how many it closed.
func (c *core) sweep(now time.Time) int {
	n := 0
	for id, deadline := range c.draining {
		t := statistic.DefaultManager.Get(id)
		switch {
		case t == nil:
			delete(c.draining, id) // finished on its own
		case !now.Before(deadline):
			_ = t.Close()
			delete(c.draining, id)
			n++
		}
	}
	return n
}

// nextDeadline returns the earliest drain deadline; ok is false when nothing is draining.
func (c *core) nextDeadline() (next time.Time, ok bool) {
	for _, deadline := range c.draining {
		if !ok || deadline.Before(next) {
			next, ok = deadline, true
		}
	}
	return next, ok
}

// closeProvider stops a group's health checks. ProxyProvider doesn't declare Close, but the
// compatible provider behind every group has it.
func closeProvider(pd P.ProxyProvider) {
	if cl, ok := pd.(io.Closer); ok {
		_ = cl.Close()
	}
}

func (c *core) stop() {
	if !c.started {
		return
	}
	listener.PatchInboundListeners(nil, tunnel.Tunnel, true) // executor.Shutdown leaves them open
	for _, g := range c.groups {
		closeProvider(g.provider)
	}
	executor.Shutdown()
}
