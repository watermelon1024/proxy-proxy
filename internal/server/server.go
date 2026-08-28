// Package server exposes the aggregated subscriptions over HTTP.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/watermelon/proxy-proxy/internal/agg"
	"github.com/watermelon/proxy-proxy/internal/config"
)

type Server struct {
	Store *agg.Store
	Cfg   *atomic.Pointer[config.Config] // swapped atomically on hot reload
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sub", s.handleSub)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// findKey compares against every configured key in constant time.
func findKey(cfg *config.Config, key string) *config.Key {
	if key == "" {
		return nil
	}
	var found *config.Key
	for i := range cfg.Keys {
		if subtle.ConstantTimeCompare([]byte(cfg.Keys[i].Key), []byte(key)) == 1 {
			found = &cfg.Keys[i]
		}
	}
	return found
}

// clientIP resolves the real client address: when the direct peer is a
// trusted proxy (loopback/private/link-local, or in trustedNets), the
// rightmost untrusted hop in X-Forwarded-For wins, falling back to X-Real-Ip.
func clientIP(r *http.Request, trustedNets []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !trustedIP(host, trustedNets) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			if hop := strings.TrimSpace(hops[i]); hop != "" && !trustedIP(hop, trustedNets) {
				return hop
			}
		}
		// Every hop is trusted infrastructure, so the leftmost is the origin client.
		if hop := strings.TrimSpace(hops[0]); hop != "" {
			return hop
		}
	}
	if rip := r.Header.Get("X-Real-Ip"); rip != "" {
		return rip
	}
	return host
}

func trustedIP(s string, trustedNets []netip.Prefix) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range trustedNets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// maskKey keeps enough of a key to tell configured keys apart in logs without recording the secret itself.
func maskKey(k string) string {
	if len(k) <= 8 {
		return "***"
	}
	return k[:4] + "***"
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Load()
	k := findKey(cfg, r.URL.Query().Get("key"))
	if k == nil {
		slog.Warn("rejected sub request", "remote", clientIP(r, cfg.TrustedNets))
		http.NotFound(w, r)
		return
	}

	format, full := negotiateFormat(r)
	slog.Info("sub request", "remote", clientIP(r, cfg.TrustedNets), "key", maskKey(k.Key), "format", format)
	body, etag := s.Store.Render(k.Resolved, format, full)

	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "no-cache")
	h.Set("Profile-Update-Interval", strconv.Itoa(updateIntervalHours(cfg, k.Resolved)))
	// Quota display only makes sense when the key maps to exactly one sub.
	if len(k.Resolved) == 1 {
		if ui := s.Store.UserInfo(k.Resolved[0]); ui != "" {
			h.Set("Subscription-Userinfo", ui)
		}
	}
	if format == agg.FormatClash {
		h.Set("Content-Type", "application/x-yaml; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="proxy-proxy.yaml"`)
	} else {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="proxy-proxy.txt"`)
	}
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}

var clashUAs = []string{"clash", "mihomo", "stash", "verge", "meta"}

func negotiateFormat(r *http.Request) (agg.Format, bool) {
	q := r.URL.Query()
	full := q.Get("full") == "1" || q.Get("full") == "true"
	switch q.Get("format") {
	case "clash", "yaml":
		return agg.FormatClash, full
	case "base64":
		return agg.FormatBase64, false
	case "raw", "uri":
		return agg.FormatRaw, false
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	for _, s := range clashUAs {
		if strings.Contains(ua, s) {
			return agg.FormatClash, full
		}
	}
	return agg.FormatBase64, false
}

// updateIntervalHours advertises the shortest refresh interval among the key's subs, in whole hours (minimum 1).
func updateIntervalHours(cfg *config.Config, allowed []string) int {
	set := map[string]bool{}
	for _, n := range allowed {
		set[n] = true
	}
	minIv := time.Duration(0)
	for _, sub := range cfg.Subs {
		if set[sub.Name] && (minIv == 0 || sub.Interval.D() < minIv) {
			minIv = sub.Interval.D()
		}
	}
	if h := int(minIv.Hours()); h > 1 {
		return h
	}
	return 1
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Load()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"subs":   s.Store.Statuses(cfg.SubNames()),
	})
}
