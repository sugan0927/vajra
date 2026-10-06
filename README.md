# Vajra 0.7

Thread-per-core, share-nothing web server for Linux on io_uring (Rust).

> **Status (read this first):** Phases 1-4 were compiled and tested by the project owner. The Phase 5
> (WebSocket), Phase 6 (HTTP/3, fuzzing, docs) and Phase 7 (FastCGI/PHP-FPM) code was written **without a compiler or
> crates.io access**. Only the dependency-free modules were compiled and tested standalone: `src/h3.rs` (21 tests),
> `src/fastcgi.rs` (14) and `src/php.rs` (10). Expect compile errors, most likely in
> `src/quic.rs`, `src/worker/quic_io.rs`, `src/worker.rs`, `tests/http3.rs` (quinn-proto API drift) and the new PHP hooks in `worker.rs`/`proxy.rs`/`config.rs`.
> Nothing has been benchmarked; no performance numbers are claimed.

## Features
- HTTP/1.1 and HTTP/2 (hand-written), TLS via rustls with ALPN
- Zero-copy static files (splice file→pipe→socket on plain HTTP/1.1), per-core file cache
- Reverse proxy: longest-prefix routes, multiple upstreams, `round_robin` / `least_conn` / `ip_hash`,
  passive health (`max_fails`, `fail_timeout_secs`), failover (connect errors; idempotent I/O errors before any response byte), 502/504
- Per-core LRU response cache (`X-Cache: HIT|MISS`); skips `Set-Cookie`, `Vary`, `no-store|no-cache|private`; unsafe methods invalidate
- Prometheus metrics, Common Log Format access log (io_uring writes)
- Hot reload (SIGHUP or `POST /reload`) and graceful shutdown (SIGINT/SIGTERM; second signal exits)

- **WebSocket** (`ws://` and `wss://`) through any proxy route: the upgrade request is forwarded, a
  `101` answer turns the connection into an opaque two-way byte tunnel (frames are never parsed, so
  subprotocols and `permessage-deflate` pass through), with back-pressure in both directions
- **HTTP/3 (QUIC)** via quinn-proto (sans-I/O) driven by the per-core io_uring loop (UDP recvmsg/sendmsg), stateless QPACK,
  Retry on by default, `Alt-Svc` advertised on h1/h2, static files and reverse proxy/cache shared with h1/h2
- **PHP / WordPress** via FastCGI to PHP-FPM (TCP or Unix socket): script + `PATH_INFO` splitting, directory index, front
  controller for pretty permalinks, no PHP execution in `uploads`, dotfiles hidden, balancing/health/failover shared with
  the proxy. Unix-socket upstreams also work for ordinary proxy routes. See `docs/WORDPRESS.md`.
- Fuzz targets (`fuzz/`, cargo-fuzz) and deterministic mutation tests (`tests/robustness.rs`)
- Benchmark suite in `bench/`: wrk throughput + vegeta fixed-rate latency vs. Nginx, WebSocket echo load

## WebSocket tunnels
- Detected on `GET` with `Upgrade: websocket` + `Connection: Upgrade` on a proxy route (HTTP/1.1 clients only;
  RFC 8441 extended CONNECT over HTTP/2 is not supported). Upgrades always dial a fresh upstream connection,
  are never cached, and fail over only on connect errors.
- A tunnel uses four concurrent io_uring operations (client recv/send, upstream recv/send) with separate op codes;
  each direction stops reading once 256 KiB is queued toward a slow peer.
- A half-close from the client is forwarded (`SHUT_WR`) and the tunnel ends when the upstream closes;
  when the upstream closes first the client is closed after the last bytes (and TLS `close_notify`) are flushed.
- Graceful shutdown/drain **closes tunnels immediately** (plain TCP close; clients should reconnect).
- There is no idle timeout or ping handling in the proxy: use application-level pings.
  Tunnels are not counted as "active" for `least_conn` after the handshake.
- Metric: `vajra_websocket_upgrades_total`.

## Run
```
cargo build --release
./scripts/gen-dev-cert.sh            # optional, for TLS
./target/release/vajra --config vajra.toml --admin 127.0.0.1:9100
./target/release/vajra --config vajra.toml --check
```
Signals: `kill -HUP <pid>` reloads; `kill -TERM <pid>` drains within `grace_secs`.
Admin: `curl 127.0.0.1:9100/metrics`, `/healthz`, `curl -X POST 127.0.0.1:9100/reload`.

Prometheus scrape config:
```
scrape_configs:
  - job_name: vajra
    static_configs: [{targets: ["127.0.0.1:9100"]}]
```

## Test
```
cargo test                       # unit + integration (tests/*.rs; io_uring tests skip if unavailable)
python3 scripts/mock-upstream.py 9000
```
Benchmarks (needs nginx, wrk; vegeta optional):
```
cargo build --release
bench/run.sh -w 4 -d 20 -c 256 -r 20000      # writes bench/results/<timestamp>/summary.md
python3 scripts/mock-upstream.py 9000 &      # optional WebSocket echo upstream
python3 bench/ws_load.py 127.0.0.1 8080 /api/ws 200 10
```
`run.sh` pins the servers to the first N CPUs and the load generator to the rest, serves the same files and the same
proxy target from both servers, and records the environment. Compare only runs from the same machine; no numbers are
claimed here because none have been measured.

## Semantics and caveats
- Load-balancer state, health and caches are **per core**; counters and cache contents are not global.
- Reload builds new state on every core and swaps only if it succeeds, but cores swap independently (not atomic across cores).
  In-flight requests finish on the old state; the response cache is cleared. `listen`, `workers`, limits and TLS listen address need a restart.
- **The admin endpoint has no authentication.** Bind it to loopback.
- Limits: HTTP/3: no connection migration (SO_REUSEPORT), no GSO/GRO, no 0-RTT, no dynamic QPACK table, files read with synchronous `pread`; proxy bodies are buffered; one proxied request in flight per h2 connection;
  synchronous open on file-cache miss; TOCTOU window in canonicalize+open; no Range; no kTLS.

## Docs
`docs/ARCHITECTURE.md`, `docs/USER_GUIDE.md`, `docs/WORDPRESS.md`, `docs/API.md`, `docs/TUNING.md`, `docs/BENCHMARKS.md`, `SECURITY.md`, `fuzz/README.md`.

## Roadmap
Get Phase 5/6 compiling and green; measure vs. Nginx; Range requests, upstream TLS, streaming proxy bodies, GSO/GRO.
