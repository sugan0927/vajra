# API reference

## Admin HTTP API
Enabled with `[admin] listen` / `--admin`. **No authentication or TLS**: bind to loopback or a private network.

| request | response |
|---|---|
| `GET /metrics` | `200`, Prometheus text format 0.0.4 |
| `GET /healthz` | `200 ok` while running |
| `POST /reload` | `200` with a summary, or `409`/`500` with the reason; same effect as SIGHUP |

## Metric families
`vajra_connections_accepted_total`, `vajra_connections_closed_total`, `vajra_connections_active{worker}`,
`vajra_tls_handshakes_total`, `vajra_websocket_upgrades_total`, `vajra_http_requests_total{protocol}`,
`vajra_http_responses_total{class}`, `vajra_bytes_received_total`, `vajra_bytes_sent_total`,
`vajra_fastcgi_requests_total`, `vajra_quic_connections_total`, `vajra_quic_retries_total`, `vajra_quic_protocol_errors_total`,
`vajra_cache_*`, `vajra_upstream_*{upstream}` including the `vajra_upstream_request_duration_seconds` histogram.
`curl -s :9100/metrics | grep '^# HELP'` lists the exact set for a build.

## Response headers added by Vajra
`Server: Vajra`, `Date`, `X-Cache: HIT|MISS` (cacheable proxy routes), `Alt-Svc` (when `[quic].advertise`).

## Embedding as a library
`vajra` is also a library. The stable-ish entry points:

```rust
use vajra::config::{Dynamic, Settings};
use vajra::worker::{Config, Listener, Worker};
use vajra::{control, sys};

let sock = sys::listener("127.0.0.1:8080".parse()?, /*reuse_port*/ true, 4096)?;
let (handle, inbox) = control::channel()?;
std::thread::spawn(move || {
    let l = [Listener { fd: sock.as_raw_fd(), tls: false }];
    let mut w = Worker::new(&l, Config::default(), &Dynamic::default(), None).unwrap();
    w.attach_control(0, inbox, std::time::Duration::from_secs(5));
    w.run().unwrap();               // returns after a graceful drain
});
```
* `Worker::attach_quic(udp_fd, QuicConfig, quic::server_config(cert, key, &cfg)?, cert_paths, alt_svc)` adds HTTP/3.
* `admin::Manager::new(handles, config_path, settings)` provides `scrape()`, `reload()`, `shutdown()`.
* Protocol layers (`http`, `h2`, `h3`, `proxy`, `cache`, `config`) are I/O-free and unit-testable.

Rust API docs: `cargo doc --no-deps --open`. Every public module starts with a design note.
The library is not semver-stable before 1.0.
