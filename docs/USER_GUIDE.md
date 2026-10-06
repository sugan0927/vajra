# Vajra user guide

## Install
```
rustup toolchain install stable           # 1.80 or newer
cargo build --release                      # target/release/vajra
```
Linux 5.19+ is recommended (multishot accept, COOP_TASKRUN, SINGLE_ISSUER; older kernels fall back where possible).
Containers need io_uring permitted (Docker's default seccomp profile blocks it on some versions; see deploy/Dockerfile).

## Run
```
vajra --config /etc/vajra/vajra.toml
vajra --check --config vajra.toml          # validate and exit
vajra --listen 0.0.0.0:8080 --root ./public --workers 4
```
Flags override the file. Signals: `SIGHUP` reload, `SIGTERM`/`SIGINT` graceful stop, a second signal exits immediately.

## Configuration reference (`vajra.toml`)
Unknown keys are errors. Relative paths are relative to the config file.

| section | key | default | notes |
|---|---|---|---|
| `[server]` | `listen` | `0.0.0.0:8080` | plain HTTP / HTTP/1.1 |
| | `workers` | 1 | `0` = one per CPU |
| | `pin` | true | pin worker *n* to CPU *n* |
| | `grace_secs` | 5 | drain deadline on shutdown |
| `[limits]` | `max_conns` | 65536 | per worker, includes in-flight HTTP/3 proxy requests |
| | `read_buf_size` | 8192 | receive staging buffer |
| | `ring_entries` | 1024 | io_uring SQ size |
| | `max_body_bytes` | 1 MiB | buffered request bodies (proxy, h2, h3) |
| | `max_proxy_response_bytes` | 16 MiB | buffered upstream responses |
| `[static]` | `root` | – | enables static files |
| | `index` | `index.html` | |
| | `cache_ttl_secs` | 2 | open-file cache TTL |
| | `max_cached_files` | 4096 | |
| `[tls]` | `listen`, `cert`, `key` | – | HTTPS + HTTP/2 (ALPN) |
| `[quic]` | `listen` | – | UDP port for HTTP/3; **requires `[tls]`** (same certificate) |
| | `retry` | true | address validation |
| | `idle_timeout_secs` | 30 | |
| | `max_streams` | 100 | concurrent requests per connection |
| | `advertise` | true | `Alt-Svc` on HTTP/1.1 and HTTP/2 |
| `[cache]` | `max_entries`, `max_bytes`, `max_object_bytes` | 4096 / 64 MiB / 1 MiB | per worker |
| `[logging]` | `access_log` | off | Common Log Format, reopened on reload |
| `[admin]` | `listen` | off | `/metrics`, `/healthz`, `POST /reload`; no auth |
| `[[proxy]]` | `prefix` | – | longest prefix wins |
| | `upstream` / `upstreams` | – | one of the two |
| | `balance` | `round_robin` | `least_conn`, `ip_hash` |
| | `strip_prefix` | false | |
| | `timeout_secs` | 30 | connect, send and receive each |
| | `max_fails`, `fail_timeout_secs` | 3 / 10 | passive health |
| | `cache`, `cache_default_ttl_secs` | false / 30 | |

Changes to `server.listen/workers/pin`, `[limits]`, `tls.listen`, `[quic]`, and `admin.listen` need a restart;
a reload refuses them and keeps the running configuration. Everything else reloads without dropping connections.

## Enabling HTTPS, HTTP/2 and HTTP/3
```
./scripts/gen-dev-cert.sh                  # development only
```
```toml
[tls]
listen = "0.0.0.0:8443"
cert = "certs/cert.pem"
key  = "certs/key.pem"

[quic]
listen = "0.0.0.0:8443"                    # same port number, UDP
```
Check: `curl -k --http2 https://localhost:8443/`, `curl -k --http3 https://localhost:8443/` (curl built with HTTP/3),
or Chrome with `--origin-to-force-quic-on=localhost:8443`. Browsers learn about HTTP/3 from `Alt-Svc`, so the first
request is over TCP. Open UDP 8443 in the firewall.

## Reverse proxy examples
```toml
[[proxy]]
prefix = "/api/"
upstreams = ["10.0.0.11:9000", "10.0.0.12:9000"]
balance = "least_conn"
max_fails = 3
fail_timeout_secs = 10
cache = true

[[proxy]]
prefix = "/ws/"                            # WebSocket needs no special settings
upstream = "127.0.0.1:9001"
timeout_secs = 3600                        # the timeout applies to the handshake only
```
Behaviour to know: `X-Forwarded-For` is *replaced* with the client address (never appended); requests with
`Authorization` or `Cache-Control: no-cache` skip the cache; failover never replays a non-idempotent request
that may have reached an upstream.

## PHP and WordPress (FastCGI)
See [WORDPRESS.md](WORDPRESS.md) for a complete setup. In short:
```toml
[static]
root = "/var/www/html"

[limits]
max_body_bytes = 67108864            # largest upload you accept (buffered in memory)

[php]
upstream = "unix:/run/php/php8.3-fpm.sock"     # or "127.0.0.1:9000", or upstreams = [...]
```
Order of decisions for a request: `/health`, explicit `[[proxy]]` prefixes, PHP scripts (`/x.php`, `/x.php/path/info`),
static files, directory index script, front controller (`/index.php`, which makes WordPress permalinks work).
Options: `index`, `front_controller` (`""` disables), `extensions`, `deny_exec`, `script_root` (document root as
PHP-FPM sees it, for containers), `timeout_secs`, `balance`, `max_fails`, `fail_timeout_secs`. The `[php]` section is
hot-reloadable. Upstream `unix:/path` also works for ordinary `[[proxy]]` routes.

## Observability
* `GET /metrics` – Prometheus text: connections, requests by protocol (http1/http2/http3), status classes,
  bytes, TLS handshakes, QUIC connections/retries/protocol errors, WebSocket upgrades, response-cache stats,
  and per-upstream requests, errors, timeouts, active connections and a latency histogram.
* Access log – Common Log Format (control characters escaped), written with io_uring.
* Prometheus scrape config:
  ```
  scrape_configs:
    - job_name: vajra
      static_configs: [{targets: ["127.0.0.1:9100"]}]
  ```
Counters are summed over workers; gauges such as `vajra_connections_active` carry a `worker` label.

## Operations
* systemd unit: `deploy/vajra.service` (`ExecReload` sends SIGHUP; raise `LimitNOFILE`; `LimitMEMLOCK` for the ring).
* Log rotation: rename the file, then `systemctl reload vajra` (the log is reopened on reload).
* Certificate renewal: replace the files and reload; new TLS and QUIC connections use the new certificate.
* Zero-downtime upgrade: start the new binary on the same ports (`SO_REUSEPORT` allows both), then stop the old
  one with SIGTERM; it drains. UDP flows that land on the old process finish there.

## Troubleshooting
| symptom | check |
|---|---|
| `io_uring setup failed` | kernel < 5.1, seccomp/AppArmor, or `kernel.io_uring_disabled` sysctl |
| HTTP/3 never used | UDP port blocked; `[quic]` missing; browser needs one TCP visit to see `Alt-Svc` |
| 502 from proxy | upstream down: `vajra_upstream_connect_errors_total` |
| reload ignored | log line `restart required: ...`; the running config is kept |
| WebSocket closes on shutdown | by design: drain ends tunnels |
