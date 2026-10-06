# Vajra architecture

## Goals and non-goals
Vajra is a thread-per-core, share-nothing web server for Linux. Everything that touches the network
goes through io_uring; there is no async runtime and no `epoll`. It serves static files, reverse
proxies, and speaks HTTP/1.1, HTTP/2, HTTP/3 (QUIC) and WebSocket tunnels. It is a study in how far
a small, explicit design goes, not a drop-in nginx replacement: no FastCGI, gzip, rewrite language,
or range requests.

## Process model
```
main thread ── signals (sigwait), admin HTTP thread, control channels
   │
   ├─ worker 0 (pinned to CPU 0) ── io_uring ring, TCP + UDP sockets (SO_REUSEPORT)
   ├─ worker 1 (pinned to CPU 1) ── ...
   └─ worker N-1
```
* Each worker creates **its own** listeners (kernel load-balances new connections / UDP flows by
  4-tuple hash), ring, slab buffer pool, file cache, response cache, upstream pools, balancer state,
  TLS and QUIC configuration, metrics and access-log buffer.
* After startup the only cross-thread traffic is the **control channel**: an `std::sync::mpsc`
  queue plus an `eventfd` that wakes the worker's ring (`control.rs`). Commands: `Scrape`,
  `Reload(Arc<Dynamic>)`, `Shutdown`. Replies travel back over a one-shot channel.
* Metrics are plain (non-atomic) counters owned by the worker; the manager sums snapshots at scrape time.

## The event loop (`worker.rs`)
Every completion carries `user_data = [op:8 | idx:56]`. The loop drains the completion queue into a
batch, dispatches by op code, then flushes access logs and the QUIC engine, and sleeps in
`submit_and_wait`.

Invariant: **one operation in flight per connection**, which makes buffers address-stable without
locks. Exceptions are deliberate and documented where they occur: WebSocket tunnels (four
independent operations, separate op codes) and the QUIC engine (32 receive and 64 send slots).

| area | operations |
|------|-----------|
| accept | `AcceptMulti` (falls back to single-shot) |
| client I/O | `Recv`, `Send` (TLS: ciphertext through rustls, sans-I/O) |
| files | `Splice` file→pipe→socket (plain HTTP/1.1); `Read` into a chunk buffer (TLS, HTTP/2) |
| upstream | `Connect` + `LinkTimeout`, `Send`, `Recv` with linked timeouts |
| UDP | `RecvMsg`, `SendMsg`, `Timeout` |
| misc | `Read` on the control eventfd, `Write` for the access log, `Close`, `AsyncCancel` |

## Protocol layers (all I/O-free)
* `http.rs` – HTTP/1.1 parsing and serialisation; `process()` handles pipelining and yields an
  `Action` (file, proxy, need-body) for the worker.
* `h2.rs` – framing, HPACK (decoder from the `hpack` crate, literal-only encoder), flow control,
  abuse limits (rapid reset, continuation floods, settings floods, ping floods).
* `h3.rs` – HTTP/3 framing and **stateless** QPACK: Vajra advertises a zero-size dynamic table, so
  encoding and decoding use only the static table and literals.
* `quic.rs` – wraps `quinn-proto` (sans-I/O QUIC) and `h3.rs`; `worker/quic_io.rs` is the io_uring glue.
* `router.rs` – one routing decision shared by HTTP/1.1, 2 and 3: `/health` → proxy prefix (longest match) → static files.

## Static files
Path mapping (`static_files.rs`) percent-decodes, rejects `..`/NUL/backslashes, canonicalises and
checks the result is under the canonical root. A per-core cache holds open file descriptors with a
TTL. Plain HTTP/1.1 bodies use `splice`; TLS/HTTP-2/HTTP-3 bodies are read in chunks (no kTLS).
Known gap: opening a file on a cache miss is a synchronous syscall, and HTTP/3 uses `pread`.

## Reverse proxy (`proxy.rs`)
* Routes: longest prefix, one or more upstreams, `round_robin | least_conn | ip_hash`.
* Passive health: `max_fails` consecutive failures open a circuit for `fail_timeout_secs`; when all
  upstreams are down the balancer fails open.
* Failover: connect errors always; I/O errors only for idempotent methods before any response byte.
  A stale pooled socket is retried once on the same upstream without a health penalty.
* Timeouts: `LinkTimeout` on connect/send/recv → 504; other failures → 502.
* Bodies are buffered (requests up to `max_body_bytes`, responses up to `max_proxy_response_bytes`).
* **WebSocket**: an `Upgrade: websocket` GET dials a fresh upstream, forwards the handshake, and on `101`
  switches both sockets to an opaque tunnel with per-direction back-pressure.
* HTTP/3 proxying reuses all of this through *pseudo connection slots* (a `Conn` with no socket).

## FastCGI / PHP-FPM (`fastcgi.rs`, `php.rs`)
PHP is a *protocol adapter on the proxy path*, not a separate subsystem, so balancing, passive health, failover,
timeouts, metrics and access logging all apply unchanged.

* **Routing** (`php.rs`, called from `router.rs` after `/health` and explicit `[[proxy]]` prefixes): percent-decode and
  normalise; `..`/NUL/backslash -> 400; dot-segments (except `.well-known`) -> 404; the first segment ending in a PHP
  extension whose file exists splits `SCRIPT_NAME`/`PATH_INFO`; a script path that does not exist, or lies under
  `deny_exec`, is a 404 (it never falls through to static files or the front controller). Everything else tries the
  per-core static file cache first, then a directory index script, then the front controller (`/index.php`) with the
  original `REQUEST_URI`.
* **Request** (`fastcgi::build_request`): `BEGIN_REQUEST` (responder, no `KEEP_CONN`), `PARAMS`, `STDIN`, built in memory
  from the already-buffered body and sent like any other upstream request. Upstreams may be TCP or Unix sockets (`UpAddr`).
* **Response**: records are decoded incrementally (`fastcgi::Decoder`) in `Worker::on_up_recv_fcgi`. At `END_REQUEST` the
  CGI output (`Status:`/headers/body) is rewritten into `HTTP/1.1 ...` with a recomputed `Content-Length` and
  `Connection: close`, placed in `job.resp`, and the ordinary `progress()`/`proxy_done()` path finishes the request.
  The upstream socket is closed afterwards (one request per connection, as PHP-FPM does without `KEEP_CONN`).
* Whole responses are buffered (bounded by `max_proxy_response_bytes`), as for every proxied response.
* `STDERR` records (PHP warnings) are logged to stderr, first 512 bytes per request.

## Response cache (`cache.rs`)
Per-core LRU keyed by `host + target`. TTL from `s-maxage`/`max-age`/default. Never stores
`Set-Cookie`, `Vary`, `no-store|no-cache|private`; `Authorization` and `Cache-Control: no-cache`
requests bypass; unsafe methods invalidate. Adds `X-Cache: HIT|MISS`.

## Control plane
`admin.rs`: `Manager` (scrape/reload/shutdown fan-out) and a small blocking HTTP thread serving
`/metrics`, `/healthz`, `POST /reload`. **No authentication**: bind to loopback.

* **Reload** (SIGHUP or `POST /reload`): the manager re-reads the file, rejects changes that need a
  restart, and sends the new `Dynamic` settings to each worker. A worker builds everything first
  (file cache, TLS, QUIC, proxy state, log) and swaps only if all of it succeeded. In-flight requests
  keep the old route table through an `Rc`. Workers swap independently; the cache is cleared.
* **Graceful shutdown**: stop accepting, close idle connections, send GOAWAY (h2/h3), end WebSocket
  tunnels, exit when nothing is live or the grace period ends. A second signal exits at once.

## Memory
`arena.rs` provides a slab pool of fixed-size buffers per worker (receive staging buffers are carved
from it). Per-connection `Vec`s grow on demand and are shrunk when they exceed a threshold. A fully
arena-allocated request path is future work; see TUNING.md for the allocator discussion.
`Conn` records are `align(64)` so neighbouring connections never share a cache line.

## HTTP/3 specifics
* One UDP socket per worker (`SO_REUSEPORT`). A flow's 4-tuple pins it to a core, so **connection
  migration is disabled**; a QUIC-aware eBPF reuseport program would restore it.
* Address validation with Retry is on by default (amplification protection).
* TLS 1.3 only, ALPN `h3`, 0-RTT off. `Alt-Svc` is added to HTTP/1.1 and HTTP/2 responses.
* No GSO/GRO yet: one datagram per `sendmsg`.

## Threat model summary
See SECURITY.md. In short: parsers are bounded and fuzzed, h2/h3 abuse limits exist, file access is
confined to the root, headers sent upstream are rebuilt (`X-Forwarded-*` overwritten, hop-by-hop
removed), and the admin port must not be exposed.
