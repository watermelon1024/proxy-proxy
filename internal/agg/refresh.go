package agg

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/watermelon/proxy-proxy/internal/config"
	"github.com/watermelon/proxy-proxy/internal/node"
)

const maxBodySize = 32 << 20 // 32 MiB

// Refresher fetches subscriptions on their own schedules.
type Refresher struct {
	Store     *Store
	Client    *http.Client
	UserAgent string
}

func NewRefresher(store *Store, cfg *config.Config) *Refresher {
	return &Refresher{
		Store:     store,
		Client:    &http.Client{Timeout: cfg.Timeout.D()},
		UserAgent: cfg.UserAgent,
	}
}

// Run fetches one sub immediately, then on its interval; failures keep the previous snapshot and retry with exponential backoff capped at the interval.
func (r *Refresher) Run(ctx context.Context, sub config.Sub) {
	backoff := time.Minute
	for {
		err := r.Fetch(ctx, sub)
		var wait time.Duration
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("sub refresh failed", "sub", sub.Name, "err", err, "retry_in", backoff)
			r.Store.SetError(sub.Name, err)
			wait = backoff
			backoff = min(backoff*2, sub.Interval.D())
		} else {
			backoff = time.Minute
			wait = sub.Interval.D()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Fetch performs one conditional GET and stores the parsed nodes.
func (r *Refresher) Fetch(ctx context.Context, sub config.Sub) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", r.UserAgent)
	if etag, lastMod := r.Store.Validators(sub.Name); etag != "" || lastMod != "" {
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if lastMod != "" {
			req.Header.Set("If-Modified-Since", lastMod)
		}
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		r.Store.Touch(sub.Name)
		slog.Debug("sub not modified", "sub", sub.Name)
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("upstream status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return err
	}
	if len(body) > maxBodySize {
		return fmt.Errorf("body exceeds %d bytes", maxBodySize)
	}

	nodes, detected, err := node.ParseContent(sub.Name, body, sub.Type)
	if err != nil {
		return err
	}
	r.Store.SetNodes(sub.Name, nodes,
		resp.Header.Get("Etag"), resp.Header.Get("Last-Modified"),
		resp.Header.Get("Subscription-Userinfo"))
	typ := sub.Type
	if typ == "auto" {
		typ = detected + "(auto)"
	}
	slog.Info("sub updated", "sub", sub.Name, "type", typ, "nodes", len(nodes))
	return nil
}
