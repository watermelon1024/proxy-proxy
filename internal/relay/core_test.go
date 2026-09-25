package relay

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startEcho(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// socksDial opens a no-auth socks5 CONNECT through 127.0.0.1:via to 127.0.0.1:dst.
func socksDial(t *testing.T, via, dst int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", via))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 10)
	c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(dst >> 8), byte(dst)})
	if _, err := io.ReadFull(c, buf); err != nil || buf[1] != 0 {
		t.Fatalf("socks5 connect failed: %v %v", err, buf)
	}
	return c
}

func echoes(c net.Conn) bool {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return false
	}
	b := make([]byte, 4)
	_, err := io.ReadFull(c, b)
	return err == nil && string(b) == "ping"
}

func TestCoreKeepsUnchangedAndDrainsChanged(t *testing.T) {
	echo := startEcho(t)
	back, front, extra := freePort(t), freePort(t), freePort(t)
	backRelay := fmt.Sprintf(`
  - name: back
    upstream: [{ name: out, type: direct }]
    downstream: [{ type: socks5, listen: 127.0.0.1, port: %d }]`, back)
	frontRelay := func(upstream string) string {
		return fmt.Sprintf(`
  - name: front
    upstream: [{ name: %s, type: socks5, server: 127.0.0.1, port: %d }]
    downstream: [{ type: socks5, listen: 127.0.0.1, port: %d }]`, upstream, back, front)
	}
	extraRelay := func(auth string) string {
		return fmt.Sprintf(`
  - name: extra
    upstream: [{ name: out-extra, type: direct }]
    downstream: [{ type: socks5, listen: 127.0.0.1, port: %d%s }]`, extra, auth)
	}

	c := newCore()
	if err := c.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.stop)
	apply := func(relays string) applyStats {
		t.Helper()
		p, errs := NewPlan(loadConfig(t, relays))
		if len(errs) != 0 {
			t.Fatal(errs)
		}
		d, _ := p.Render(noNodes)
		st, err := c.apply(d)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	apply(backRelay + frontRelay("via"))
	conn := socksDial(t, front, echo)
	if !echoes(conn) {
		t.Fatal("relay chain does not work")
	}
	frontGroup := c.groups["front"].proxy

	// An unrelated change keeps every existing upstream and group, and the open connection.
	st := apply(backRelay + frontRelay("via") + extraRelay(""))
	if st.reused != 2 || st.built != 1 || st.draining != 0 {
		t.Fatalf("adding a relay: %+v, want 2 kept, 1 built, 0 draining", st)
	}
	if c.groups["front"].proxy != frontGroup {
		t.Fatal("unchanged group was rebuilt")
	}
	if !echoes(conn) {
		t.Fatal("open connection broke on an unrelated change")
	}

	// Requiring a password on extra's port drains the caller who came in without one.
	extraConn := socksDial(t, extra, echo)
	st = apply(backRelay + frontRelay("via") + extraRelay(", username: u, password: p"))
	if st.built != 0 || st.draining != 1 {
		t.Fatalf("changing credentials: %+v, want 0 built, 1 draining", st)
	}

	// Replacing front's upstream drains the connection still using the old one.
	st = apply(backRelay + frontRelay("via-new") + extraRelay(", username: u, password: p"))
	if st.built != 1 || st.draining != 1 {
		t.Fatalf("replacing an upstream: %+v, want 1 built, 1 draining", st)
	}
	if n := c.sweep(time.Now()); n != 0 || !echoes(conn) || !echoes(extraConn) {
		t.Fatalf("connections closed before their deadline (closed %d)", n)
	}
	if n := c.sweep(time.Now().Add(drainTimeout)); n != 2 {
		t.Fatalf("sweep after the deadline closed %d connections, want 2", n)
	}
	if echoes(conn) || echoes(extraConn) {
		t.Fatal("drained connections still work")
	}
	if fresh := socksDial(t, front, echo); !echoes(fresh) {
		t.Fatal("new connections should use the new upstream")
	}
}
