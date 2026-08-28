# proxy-proxy

*A proxy of proxies, because one layer of indirection is never enough.*

proxy-proxy fetches your upstream proxy subscriptions on a schedule, merges and
deduplicates the nodes, and re-serves them as a single subscription — with
per-key access control over which upstream subs each downstream user can see.

## Quick start (Docker)

Images are built for linux/amd64 + arm64 and pushed to GHCR by CI on every
push to `main`.

```sh
mkdir -p config && curl -fsSL -o config/proxy-proxy.yaml \
  https://raw.githubusercontent.com/watermelon1024/proxy-proxy/main/proxy-proxy.example.yaml
# edit config/proxy-proxy.yaml (your subs and keys), then:
docker run -d --name proxy-proxy \
  -p 8080:8080 \
  -v "$(pwd)/config:/etc/proxy-proxy:ro" \
  --restart unless-stopped \
  ghcr.io/watermelon1024/proxy-proxy:latest
```

Or with compose:

```yaml
services:
  proxy-proxy:
    image: ghcr.io/watermelon1024/proxy-proxy:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/proxy-proxy:ro
    restart: unless-stopped
```

Downstream users subscribe to:

```text
http://your-host:8080/sub?key=pp-123456
```

To update, `docker compose pull && docker compose up -d` (or run watchtower).
Every image is also tagged `:sha-xxxxxxx`, so you can pin or roll back to any
commit without version tags.

Mount the config **directory**, not the single file: editors and `cp` replace
the file by rename, and a single-file bind mount would keep pointing at the
old inode, so hot reload would never see your edits. The image runs as a
non-root user and ships a `/healthz`-based HEALTHCHECK.

## Build from source

```sh
cp proxy-proxy.example.yaml proxy-proxy.yaml   # then fill in your subs and keys
go build -o proxy-proxy .
./proxy-proxy -config proxy-proxy.yaml
```

`docker build -t proxy-proxy .` works too if you want a local image.

The real `proxy-proxy.yaml` is gitignored — it contains your subscription URLs
and access keys. Only `proxy-proxy.example.yaml` is committed.

## Configuration

```yaml
listen: :8080                  # optional, default :8080
user_agent: clash.meta/1.19.0  # optional UA sent to upstreams
timeout: 30s                   # optional upstream fetch timeout
trusted_proxies: [100.64.0.0/10]  # optional extra CIDRs/IPs trusted for X-Forwarded-For

subs:
  - url: https://example.com/subscription
    type: auto        # auto | base64 | clash (default auto)
    interval: 3h      # refresh interval (e.g. 3h, 30min, 1d; default 1h, min 1m)
    name: Provider A  # optional; used by allowed_subs (defaults to the URL host)

keys:
  - key: pp-123456
    allowed_subs:     # leave empty to allow ALL subs
      - Provider A
```

Changes to the config file are hot-reloaded automatically (see below), except
`listen`, which requires a restart.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /sub?key=K` | The aggregated subscription for key `K`. |
| `GET /healthz` | JSON status of every upstream sub. |

`/sub` picks the output format from the client's User-Agent (Clash-family
clients get Clash YAML, everything else gets base64). Override with:

- `format=base64` — base64-encoded share links (default)
- `format=clash` — Clash `proxies:` list (usable as a proxy-provider)
- `format=clash&full=1` — a complete minimal Clash config with proxy groups
- `format=raw` — plain share-link lines (handy for debugging)

Responses carry an `ETag` (clients get 304s), and when a key maps to exactly
one sub, the upstream `Subscription-Userinfo` quota header is forwarded.

## Behavior notes

- **Protocols converted both ways** (share link ⇄ Clash): ss, vmess, vless,
  trojan, hysteria2. Other links (tuic, ssr, ...) are passed through verbatim
  in base64/raw output; other Clash proxy types (tuic, wireguard, snell, ...)
  appear in Clash output only.
- **Dedup** is format-independent: a node listed in a base64 sub and a Clash
  sub is recognized as the same node (by type, server, port, credential and
  transport). First sub in config order wins; duplicate display names get
  numeric suffixes in Clash output.
- **Refresh**: each sub is fetched on its own interval with conditional GETs
  (ETag / Last-Modified). A failed refresh keeps the previous snapshot and
  retries with exponential backoff capped at the interval.
- **Hot reload**: the config file is watched (2s poll + content hash) and
  applied atomically; in-flight data survives a reload. `SIGHUP` also triggers
  a reload. Disable watching with `-watch=false` or `PP_WATCH=0`.
- **Request logs** resolve the client IP from `X-Forwarded-For` (rightmost
  untrusted hop) only when the direct peer is trusted: loopback / private /
  link-local, i.e. a reverse proxy on the same host or Docker network, plus
  anything listed in `trusted_proxies`. Headers from untrusted peers are
  never trusted.

## Flags & environment

| Flag | Env | Default | Purpose |
| --- | --- | --- | --- |
| `-config` | `PP_CONFIG` | `proxy-proxy.yaml` | Config file path |
| `-listen` | `PP_LISTEN` | from config | Listen address override |
| `-watch` | `PP_WATCH` | `true` | Watch config for changes |
| `-debug` | | `false` | Debug logging |
