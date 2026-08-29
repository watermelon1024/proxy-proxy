// proxy-proxy aggregates upstream proxy subscriptions into one deduplicated subscription, served per access key.
package main

import (
	"context"
	"flag"
	"hash/fnv"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/watermelon/proxy-proxy/internal/agg"
	"github.com/watermelon/proxy-proxy/internal/config"
	"github.com/watermelon/proxy-proxy/internal/server"
)

func main() {
	configPath := flag.String("config", envStr("PP_CONFIG", "proxy-proxy.yaml"), "path to config file (env PP_CONFIG)")
	listen := flag.String("listen", os.Getenv("PP_LISTEN"), "listen address override (env PP_LISTEN)")
	watch := flag.Bool("watch", envBool("PP_WATCH", true), "watch config file and hot-reload on change (env PP_WATCH)")
	debug := flag.Bool("debug", false, "enable debug logging")
	clientIPSource := flag.String(
		"client-ip-source",
		envStr("PP_CLIENT_IP_SOURCE", "direct"),
		"client IP source: direct, cf, xff:<n>, xff:<cidr,...>, or header:<name> (env PP_CLIENT_IP_SOURCE)",
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ipSource, err := server.ParseClientIPSource(*clientIPSource)
	if err != nil {
		slog.Error("invalid client IP source", "err", err)
		os.Exit(1)
	}
	slog.Info("client IP source configured", "source", ipSource.String())

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if len(cfg.Keys) == 0 {
		slog.Warn("no keys configured; /sub will reject every request")
	}

	store := agg.NewStore()
	var cfgPtr atomic.Pointer[config.Config]
	cfgPtr.Store(cfg)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var refreshCancel context.CancelFunc
	startRefreshers := func(c *config.Config) {
		ctx, cancel := context.WithCancel(rootCtx)
		refreshCancel = cancel
		ref := agg.NewRefresher(store, c)
		for _, sub := range c.Subs {
			go ref.Run(ctx, sub)
		}
	}
	startRefreshers(cfg)

	// Reloads from SIGHUP and the file watcher funnel through one channel so refresher restarts never race.
	reloadCh := make(chan string, 1)
	go func() {
		for reason := range reloadCh {
			ncfg, err := config.Load(*configPath)
			if err != nil {
				slog.Error("config reload failed, keeping current config", "err", err)
				continue
			}
			if *listen != "" {
				ncfg.Listen = *listen
			}
			old := cfgPtr.Load()
			if ncfg.Listen != old.Listen {
				slog.Warn("listen address change requires a restart", "current", old.Listen)
				ncfg.Listen = old.Listen
			}
			refreshCancel()
			cfgPtr.Store(ncfg)
			store.Prune(ncfg.SubNames())
			startRefreshers(ncfg)
			slog.Info("config reloaded", "reason", reason, "subs", len(ncfg.Subs), "keys", len(ncfg.Keys))
		}
	}()

	requestReload := func(reason string) {
		select {
		case reloadCh <- reason:
		default: // a reload is already queued
		}
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			requestReload("SIGHUP")
		}
	}()

	if *watch {
		go watchConfig(rootCtx, *configPath, func() { requestReload("file changed") })
		slog.Info("config watch enabled", "path", *configPath)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           (&server.Server{Store: store, Cfg: &cfgPtr, ClientIPSource: ipSource}).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("listening", "addr", cfg.Listen)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("http server", "err", err)
			stop()
		}
	}()

	<-rootCtx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

// watchConfig polls the file every 2s; mtime/size gates a read, and a content
// hash gates the actual reload so touch(1) and editor no-ops are ignored.
func watchConfig(ctx context.Context, path string, changed func()) {
	var lastMod time.Time
	var lastSize int64
	lastHash := uint64(0)
	if fi, err := os.Stat(path); err == nil {
		lastMod, lastSize = fi.ModTime(), fi.Size()
	}
	if data, err := os.ReadFile(path); err == nil {
		lastHash = hashBytes(data)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if fi.ModTime().Equal(lastMod) && fi.Size() == lastSize {
			continue
		}
		lastMod, lastSize = fi.ModTime(), fi.Size()
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if h := hashBytes(data); h != lastHash {
			lastHash = h
			changed()
		}
	}
}

func hashBytes(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
