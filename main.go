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

type runtimeOptions struct {
	configPath     string
	listen         string
	clientIPSource string
	watch          bool
	debug          bool
}

type reloadOptions struct {
	ctx           context.Context
	configPath    string
	listen        string
	store         *agg.Store
	cfg           *atomic.Pointer[config.Config]
	reloadCh      <-chan string
	refreshCancel context.CancelFunc
}

func main() {
	opts := parseOptions()
	configureLogging(opts.debug)
	clientIPSource, err := server.ParseClientIPSource(opts.clientIPSource)
	if err != nil {
		slog.Error("invalid client IP source", "err", err)
		os.Exit(1)
	}
	slog.Info("client IP source configured", "source", clientIPSource.String())
	cfg, err := loadConfig(opts.configPath, opts.listen)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if len(cfg.Keys) == 0 {
		slog.Warn("no keys configured; /sub will reject every request")
	}
	store := agg.NewStore()
	var cfgPtr atomic.Pointer[config.Config]
	cfgPtr.Store(cfg)
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	refreshCancel := startRefreshers(rootCtx, store, cfg)
	reloadCh := make(chan string, 1)
	go reloadLoop(reloadOptions{
		ctx:           rootCtx,
		configPath:    opts.configPath,
		listen:        opts.listen,
		store:         store,
		cfg:           &cfgPtr,
		reloadCh:      reloadCh,
		refreshCancel: refreshCancel,
	})
	startReloadTriggers(rootCtx, opts, reloadCh)
	handler := (&server.Server{Store: store, Cfg: &cfgPtr, ClientIPSource: clientIPSource}).Routes()
	srv := newHTTPServer(cfg.Listen, handler)
	go serveHTTP(srv, stop)
	<-rootCtx.Done()
	shutdownHTTP(srv)
}

func parseOptions() runtimeOptions {
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
	return runtimeOptions{
		configPath:     *configPath,
		listen:         *listen,
		clientIPSource: *clientIPSource,
		watch:          *watch,
		debug:          *debug,
	}
}

func configureLogging(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func loadConfig(path, listen string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err == nil && listen != "" {
		cfg.Listen = listen
	}
	return cfg, err
}

func startRefreshers(ctx context.Context, store *agg.Store, cfg *config.Config) context.CancelFunc {
	refreshCtx, cancel := context.WithCancel(ctx)
	ref := agg.NewRefresher(store, cfg)
	for _, sub := range cfg.Subs {
		go ref.Run(refreshCtx, sub)
	}
	return cancel
}

// reloadLoop serializes SIGHUP and file-watcher reloads so refresher restarts cannot race.
func reloadLoop(opts reloadOptions) {
	refreshCancel := opts.refreshCancel
	for {
		select {
		case <-opts.ctx.Done():
			return
		case reason := <-opts.reloadCh:
			ncfg, err := loadConfig(opts.configPath, opts.listen)
			if err != nil {
				slog.Error("config reload failed, keeping current config", "err", err)
				continue
			}
			old := opts.cfg.Load()
			if ncfg.Listen != old.Listen {
				slog.Warn("listen address change requires a restart", "current", old.Listen)
				ncfg.Listen = old.Listen
			}
			refreshCancel()
			opts.cfg.Store(ncfg)
			opts.store.Prune(ncfg.SubNames())
			refreshCancel = startRefreshers(opts.ctx, opts.store, ncfg)
			slog.Info("config reloaded", "reason", reason, "subs", len(ncfg.Subs), "keys", len(ncfg.Keys))
		}
	}
}

func startReloadTriggers(ctx context.Context, opts runtimeOptions, reloadCh chan<- string) {
	requestReload := func(reason string) {
		select {
		case reloadCh <- reason:
		default: // a reload is already queued
		}
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				requestReload("SIGHUP")
			}
		}
	}()
	if opts.watch {
		go watchConfig(ctx, opts.configPath, func() { requestReload("file changed") })
		slog.Info("config watch enabled", "path", opts.configPath)
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

func serveHTTP(srv *http.Server, stop context.CancelFunc) {
	slog.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("http server", "err", err)
		stop()
	}
}

func shutdownHTTP(srv *http.Server) {
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server shutdown", "err", err)
	}
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
