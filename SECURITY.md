# Security notes

Vajra has not had an independent audit. Treat it as experimental before putting it on the open internet.

## Reporting
Open a private advisory with the repository owner; include a reproducer and the version (`vajra --help` prints it).

## Hardening already in place
* HTTP/1.1: header count/size limits, single `Content-Length`, no request smuggling via `Transfer-Encoding` on proxy routes
  (rejected with 411), bounded pipelining buffers.
* HTTP/2: caps on concurrent streams, header list size, continuation frames, rapid reset, PING/SETTINGS floods, window overflow.
* HTTP/3/QUIC: stateless QPACK (no compression-state attacks), bounded field sections and fields, strict header validation
  (lowercase names, pseudo-header order, connection-specific headers rejected), critical-stream rules, Retry address
  validation, connection limit, 0-RTT disabled.
* Static files: decoded path must stay under the canonical root; symlinks leaving the root are not served.
  Known gap: a TOCTOU window between canonicalisation and `open`; do not let untrusted users create symlinks in the root.
* Proxy: hop-by-hop headers removed, `X-Forwarded-*` overwritten (never trusted), upstream response size capped.
* Access log: control characters escaped (no log injection).
* Fuzzing: see `fuzz/README.md`; deterministic mutation tests run in CI.

* PHP (FastCGI): scripts run only if the file exists under the document root; missing `.php` paths never fall through to
  static serving or the front controller (no source disclosure, no `/pic.jpg/x.php` tricks); scripts under
  `deny_exec` (default `/wp-content/uploads/`) never run; dotfiles (`.git`, `.env`) are hidden; client `Proxy` (httpoxy)
  and `X-Forwarded-*` headers and header names containing `_` are not passed to PHP; output headers that control
  framing/connection are dropped.

## Things you must do
* PHP-FPM: listen on a Unix socket (mode 0660, shared group with the Vajra user) or on `127.0.0.1` only. FastCGI has
  no authentication; an exposed FPM port is remote code execution. Keep `cgi.fix_pathinfo=0`, run each site's pool as its
  own user, and keep the web root writable only by the deploy user (WordPress needs write access to `uploads`; Vajra
  never executes there).
* **Never expose the admin port** (no authentication, no TLS). Bind it to loopback and front it with SSH or a mesh.
* Run as an unprivileged user (`deploy/vajra.service` does); bind low ports with `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
* Keep the TLS private key readable only by the service user.
* Put Vajra behind a rate limiter / WAF if it faces hostile traffic; it has no request-rate limiting.

## Known limitations
No client-certificate authentication, no OCSP stapling, no HTTP/2 or HTTP/3 server push (never sent), no per-IP connection limits,
WebSocket tunnels have no idle timeout, symlinks inside the document root are followed for PHP scripts, chunked request bodies to PHP get 411, upstream TLS is not supported (plain TCP to upstreams only).
