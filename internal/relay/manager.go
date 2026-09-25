package relay

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	mlog "github.com/metacubex/mihomo/log"

	"github.com/watermelon/proxy-proxy/internal/agg"
)

// debounce coalesces bursts of sub updates, such as the initial fetch of every sub, into one mihomo reload.
const debounce = time.Second

// Manager keeps the embedded mihomo core in sync with the current plan and the nodes of its subs.
// mihomo keeps global state, so a process must run at most one Manager.
type Manager struct {
	store *agg.Store
	plans chan *Plan
}

func NewManager(store *agg.Store) *Manager {
	return &Manager{store: store, plans: make(chan *Plan, 1)}
}

// SetPlan hands a new plan to Run; an earlier plan not yet picked up is dropped.
// It must not be called concurrently.
func (m *Manager) SetPlan(p *Plan) {
	select {
	case <-m.plans:
	default:
	}
	m.plans <- p
}

// Run applies plans and sub updates until ctx is done, then shuts mihomo down.
// mihomo is not started until a plan has at least one relay.
func (m *Manager) Run(ctx context.Context) {
	mlog.SetLevel(mlog.SILENT) // mihomo prints to stdout on its own; forward its events to slog instead
	events := mlog.Subscribe()
	go forwardLogs(events)

	var (
		c          = newCore()
		plan       *Plan
		applied    []byte
		timer      <-chan time.Time // debounced sub updates
		sweepTimer <-chan time.Time // next drain deadline
	)
	scheduleSweep := func() {
		sweepTimer = nil
		if next, ok := c.nextDeadline(); ok {
			sweepTimer = time.After(time.Until(next))
		}
	}
	apply := func() {
		if plan == nil || (!c.started && len(plan.relays) == 0) {
			return
		}
		d, warns := plan.Render(m.store.Nodes)
		body, err := d.yaml()
		if err != nil {
			slog.Error("relay config render failed", "err", err)
			return
		}
		if c.started && bytes.Equal(body, applied) {
			return
		}
		if !c.started {
			if err := c.start(); err != nil {
				slog.Error("mihomo failed to start", "err", err)
				return
			}
		}
		st, err := c.apply(d)
		if err != nil {
			slog.Error("relay config apply failed, keeping the current one", "err", err)
			return
		}
		applied = body
		for _, w := range warns {
			slog.Warn(w.msg, w.args...)
		}
		slog.Info("relay config applied", "relays", len(plan.relays), "listeners", len(plan.listeners),
			"upstreams_kept", st.reused, "upstreams_built", st.built)
		if st.draining > 0 {
			slog.Info("connections on a changed route will be closed unless they finish first",
				"connections", st.draining, "in", drainTimeout)
			scheduleSweep()
		}
	}

	for {
		select {
		case <-ctx.Done():
			mlog.UnSubscribe(events)
			c.stop()
			return
		case plan = <-m.plans:
			timer = nil
			apply()
		case <-m.store.Changed():
			if timer == nil {
				timer = time.After(debounce)
			}
		case <-timer:
			timer = nil
			apply()
		case <-sweepTimer:
			if n := c.sweep(time.Now()); n > 0 {
				slog.Info("closed connections still on a changed route", "connections", n)
			}
			scheduleSweep()
		}
	}
}

// forwardLogs sends mihomo log events to slog. mihomo logs every connection at info, so info becomes debug here.
func forwardLogs(events <-chan mlog.Event) {
	for e := range events {
		level := slog.LevelDebug
		switch e.LogLevel {
		case mlog.ERROR:
			level = slog.LevelError
		case mlog.WARNING:
			level = slog.LevelWarn
		}
		slog.Log(context.Background(), level, e.Payload, "component", "mihomo")
	}
}
