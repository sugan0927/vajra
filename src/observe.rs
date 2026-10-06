//! Observability: per-worker metrics, access-log formatting, and the
//! Prometheus text renderer.
//!
//! ## Share-nothing metrics
//! Every worker owns a plain [`Metrics`] struct and increments it with
//! ordinary (non-atomic) arithmetic: no cache-line ping-pong between cores,
//! no locks. A scrape asks each worker for a [`Snapshot`] over the control
//! channel (see `control.rs`) and sums them here. Counters therefore cost
//! nothing on the hot path; the price is paid by the scraper.
//!
//! ## Access log
//! One line per response, appended to the worker's in-memory buffer; the
//! worker flushes it with `IORING_OP_WRITE`. Lines are written when the
//! response is *generated* (declared body length), not when its last byte is
//! sent.

use crate::cache::CacheStats;
use crate::config::UpAddr;
use crate::control::Snapshot;
use crate::date::format_clf;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;

/// Upstream latency histogram bounds, in microseconds (the last bucket is +Inf).
pub const LAT_BOUNDS_US: [u64; 12] = [
    1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000,
    5_000_000, 10_000_000,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Http {
    H1,
    H2,
    H3,
}

impl Http {
    pub fn name(self) -> &'static str {
        match self {
            Http::H1 => "HTTP/1.1",
            Http::H2 => "HTTP/2",
            Http::H3 => "HTTP/3.0",
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Hist {
    /// Per-bucket (non-cumulative) counts; index 12 is the +Inf bucket.
    pub buckets: [u64; 13],
    pub sum_us: u64,
    pub count: u64,
}

impl Hist {
    pub fn observe(&mut self, us: u64) {
        let i = LAT_BOUNDS_US.iter().position(|&b| us <= b).unwrap_or(12);
        self.buckets[i] += 1;
        self.sum_us += us;
        self.count += 1;
    }

    pub fn merge(&mut self, o: &Hist) {
        for (a, b) in self.buckets.iter_mut().zip(o.buckets.iter()) {
            *a += *b;
        }
        self.sum_us += o.sum_us;
        self.count += o.count;
    }
}

#[derive(Clone, Debug)]
pub struct UpMetrics {
    pub addr: UpAddr,
    pub requests: u64,
    pub connect_errors: u64,
    pub io_errors: u64,
    pub timeouts: u64,
    /// Gauge: attempts currently in flight on this core.
    pub active: i64,
    pub latency: Hist,
}

impl UpMetrics {
    fn new(addr: UpAddr) -> Self {
        Self { addr, requests: 0, connect_errors: 0, io_errors: 0, timeouts: 0, active: 0, latency: Hist::default() }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Metrics {
    pub conns_accepted: u64,
    pub conns_closed: u64,
    pub tls_handshakes: u64,
    /// WebSocket upgrades completed (upstream answered 101).
    pub ws_upgrades: u64,
    /// Requests answered by a FastCGI (PHP-FPM) application.
    pub fcgi_requests: u64,
    pub requests_h1: u64,
    pub requests_h2: u64,
    pub requests_h3: u64,
    /// QUIC connections accepted / closed (HTTP/3).
    pub quic_conns_accepted: u64,
    pub quic_retries: u64,
    pub quic_protocol_errors: u64,
    /// Index 0 = other, 1..=5 = 1xx..5xx.
    pub status: [u64; 6],
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub reloads_ok: u64,
    pub reloads_failed: u64,
    pub log_write_errors: u64,
    pub ups: Vec<UpMetrics>,
}

impl Metrics {
    /// Stable index for an upstream address (interned on first sight).
    pub fn up_index(&mut self, addr: &UpAddr) -> usize {
        if let Some(i) = self.ups.iter().position(|u| u.addr == *addr) {
            return i;
        }
        self.ups.push(UpMetrics::new(addr.clone()));
        self.ups.len() - 1
    }

    pub fn merge(&mut self, o: &Metrics) {
        self.conns_accepted += o.conns_accepted;
        self.conns_closed += o.conns_closed;
        self.tls_handshakes += o.tls_handshakes;
        self.ws_upgrades += o.ws_upgrades;
        self.fcgi_requests += o.fcgi_requests;
        self.requests_h1 += o.requests_h1;
        self.requests_h2 += o.requests_h2;
        self.requests_h3 += o.requests_h3;
        self.quic_conns_accepted += o.quic_conns_accepted;
        self.quic_retries += o.quic_retries;
        self.quic_protocol_errors += o.quic_protocol_errors;
        for (a, b) in self.status.iter_mut().zip(o.status.iter()) {
            *a += *b;
        }
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        self.reloads_ok += o.reloads_ok;
        self.reloads_failed += o.reloads_failed;
        self.log_write_errors += o.log_write_errors;
        for u in &o.ups {
            let i = self.up_index(&u.addr);
            let t = &mut self.ups[i];
            t.requests += u.requests;
            t.connect_errors += u.connect_errors;
            t.io_errors += u.io_errors;
            t.timeouts += u.timeouts;
            t.active += u.active;
            t.latency.merge(&u.latency);
        }
    }
}

/// Per-worker sink for "a response was produced" events.
pub struct Observer {
    pub m: Metrics,
    pub log_enabled: bool,
    /// Pending access-log bytes; the worker swaps this out and writes it.
    pub log: Vec<u8>,
    /// Unix seconds, refreshed once per event-loop batch.
    pub now: u64,
    clf: (u64, [u8; 28]),
}

impl Default for Observer {
    fn default() -> Self {
        Self::new()
    }
}

impl Observer {
    pub fn new() -> Self {
        Self { m: Metrics::default(), log_enabled: false, log: Vec::new(), now: 0, clf: (u64::MAX, [b' '; 28]) }
    }

    /// Record one response: updates counters and (if enabled) appends a log line.
    pub fn response(
        &mut self,
        ip: Option<IpAddr>,
        proto: Http,
        method: &str,
        target: &str,
        status: u16,
        bytes: u64,
    ) {
        match proto {
            Http::H1 => self.m.requests_h1 += 1,
            Http::H2 => self.m.requests_h2 += 1,
            Http::H3 => self.m.requests_h3 += 1,
        }
        let class = match status {
            100..=599 => (status / 100) as usize,
            _ => 0,
        };
        self.m.status[class] += 1;

        if !self.log_enabled {
            return;
        }
        if self.clf.0 != self.now {
            format_clf(self.now, &mut self.clf.1);
            self.clf.0 = self.now;
        }
        let log = &mut self.log;
        match ip {
            Some(ip) => {
                let _ = write!(log_writer(log), "{ip}");
            }
            None => log.push(b'-'),
        }
        log.extend_from_slice(b" - - ");
        log.extend_from_slice(&self.clf.1);
        log.extend_from_slice(b" \"");
        push_escaped(log, method.as_bytes(), 16);
        log.push(b' ');
        push_escaped(log, target.as_bytes(), 2048);
        log.push(b' ');
        log.extend_from_slice(proto.name().as_bytes());
        let _ = writeln!(log_writer(log), "\" {status} {bytes}");
    }
}

/// Tiny adapter so `write!` can target a `Vec<u8>` without `io::Write` errors.
struct VecWriter<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for VecWriter<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

fn log_writer(v: &mut Vec<u8>) -> VecWriter<'_> {
    VecWriter(v)
}

/// Append `s` (truncated to `max` bytes) with quotes, backslashes and control
/// characters hex-escaped, so a hostile request line cannot forge log lines.
fn push_escaped(out: &mut Vec<u8>, s: &[u8], max: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in s.iter().take(max) {
        if b < 0x20 || b >= 0x7f || b == b'"' || b == b'\\' {
            out.extend_from_slice(&[b'\\', b'x', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        } else {
            out.push(b);
        }
    }
}

// ───────────────────────── Prometheus text exposition ─────────────────────────

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

fn upstream_counter(
    out: &mut String,
    name: &str,
    help: &str,
    ups: &[&UpMetrics],
    value: impl Fn(&UpMetrics) -> u64,
) {
    header(out, name, "counter", help);
    for u in ups {
        let _ = writeln!(out, "{name}{{upstream=\"{}\"}} {}", u.addr, value(u));
    }
}

/// Sum per-worker snapshots into the Prometheus text format (version 0.0.4).
pub fn render_prometheus(snaps: &[Snapshot]) -> String {
    let mut total = Metrics::default();
    let mut cache = CacheStats::default();
    for s in snaps {
        total.merge(&s.metrics);
        cache.hits += s.cache.hits;
        cache.misses += s.cache.misses;
        cache.stores += s.cache.stores;
        cache.evictions += s.cache.evictions;
        cache.invalidations += s.cache.invalidations;
    }

    let mut o = String::with_capacity(4096);

    header(&mut o, "vajra_workers", "gauge", "Number of worker threads that answered the scrape.");
    let _ = writeln!(o, "vajra_workers {}", snaps.len());

    header(&mut o, "vajra_connections_total", "counter", "Connections accepted.");
    let _ = writeln!(o, "vajra_connections_total {}", total.conns_accepted);
    header(&mut o, "vajra_connections_closed_total", "counter", "Connections closed.");
    let _ = writeln!(o, "vajra_connections_closed_total {}", total.conns_closed);
    header(&mut o, "vajra_connections_active", "gauge", "Open connections per worker.");
    for s in snaps {
        let _ = writeln!(o, "vajra_connections_active{{worker=\"{}\"}} {}", s.worker, s.active_conns);
    }
    header(&mut o, "vajra_tls_handshakes_total", "counter", "Completed TLS handshakes.");
    let _ = writeln!(o, "vajra_tls_handshakes_total {}", total.tls_handshakes);

    header(&mut o, "vajra_websocket_upgrades_total", "counter", "WebSocket tunnels established.");
    let _ = writeln!(o, "vajra_websocket_upgrades_total {}", total.ws_upgrades);

    header(&mut o, "vajra_fastcgi_requests_total", "counter", "Requests answered by a FastCGI (PHP-FPM) application.");
    let _ = writeln!(o, "vajra_fastcgi_requests_total {}", total.fcgi_requests);

    header(&mut o, "vajra_http_requests_total", "counter", "Responses produced, by protocol.");
    let _ = writeln!(o, "vajra_http_requests_total{{protocol=\"http1\"}} {}", total.requests_h1);
    let _ = writeln!(o, "vajra_http_requests_total{{protocol=\"http2\"}} {}", total.requests_h2);
    let _ = writeln!(o, "vajra_http_requests_total{{protocol=\"http3\"}} {}", total.requests_h3);
    header(&mut o, "vajra_quic_connections_total", "counter", "QUIC connections accepted.");
    let _ = writeln!(o, "vajra_quic_connections_total {}", total.quic_conns_accepted);
    header(&mut o, "vajra_quic_retries_total", "counter", "QUIC Retry packets sent (address validation).");
    let _ = writeln!(o, "vajra_quic_retries_total {}", total.quic_retries);
    header(&mut o, "vajra_quic_protocol_errors_total", "counter", "QUIC/HTTP3 connections closed for protocol violations.");
    let _ = writeln!(o, "vajra_quic_protocol_errors_total {}", total.quic_protocol_errors);
    header(&mut o, "vajra_http_responses_total", "counter", "Responses produced, by status class.");
    for (i, class) in ["other", "1xx", "2xx", "3xx", "4xx", "5xx"].iter().enumerate() {
        let _ = writeln!(o, "vajra_http_responses_total{{class=\"{class}\"}} {}", total.status[i]);
    }

    header(&mut o, "vajra_received_bytes_total", "counter", "Bytes read from client sockets.");
    let _ = writeln!(o, "vajra_received_bytes_total {}", total.bytes_in);
    header(&mut o, "vajra_sent_bytes_total", "counter", "Bytes written to client sockets.");
    let _ = writeln!(o, "vajra_sent_bytes_total {}", total.bytes_out);

    header(&mut o, "vajra_cache_hits_total", "counter", "Proxy cache hits.");
    let _ = writeln!(o, "vajra_cache_hits_total {}", cache.hits);
    header(&mut o, "vajra_cache_misses_total", "counter", "Proxy cache misses.");
    let _ = writeln!(o, "vajra_cache_misses_total {}", cache.misses);
    header(&mut o, "vajra_cache_stores_total", "counter", "Responses stored in the proxy cache.");
    let _ = writeln!(o, "vajra_cache_stores_total {}", cache.stores);
    header(&mut o, "vajra_cache_evictions_total", "counter", "LRU evictions.");
    let _ = writeln!(o, "vajra_cache_evictions_total {}", cache.evictions);
    header(&mut o, "vajra_cache_invalidations_total", "counter", "Entries dropped by unsafe methods.");
    let _ = writeln!(o, "vajra_cache_invalidations_total {}", cache.invalidations);
    header(&mut o, "vajra_cache_entries", "gauge", "Cached responses per worker.");
    for s in snaps {
        let _ = writeln!(o, "vajra_cache_entries{{worker=\"{}\"}} {}", s.worker, s.cache_entries);
    }
    header(&mut o, "vajra_cache_bytes", "gauge", "Cache memory accounted per worker.");
    for s in snaps {
        let _ = writeln!(o, "vajra_cache_bytes{{worker=\"{}\"}} {}", s.worker, s.cache_bytes);
    }

    // Per-upstream series, in a stable order.
    let mut ups: Vec<_> = total.ups.iter().collect();
    ups.sort_by(|a, b| a.addr.cmp(&b.addr));
    upstream_counter(&mut o, "vajra_upstream_requests_total", "Proxy attempts started.", &ups, |u| u.requests);
    upstream_counter(&mut o, "vajra_upstream_connect_errors_total", "Failed upstream connects.", &ups, |u| u.connect_errors);
    upstream_counter(&mut o, "vajra_upstream_io_errors_total", "Upstream send/recv failures.", &ups, |u| u.io_errors);
    upstream_counter(&mut o, "vajra_upstream_timeouts_total", "Upstream operations that timed out.", &ups, |u| u.timeouts);
    header(&mut o, "vajra_upstream_active", "gauge", "Proxy attempts in flight.");
    for u in &ups {
        let _ = writeln!(o, "vajra_upstream_active{{upstream=\"{}\"}} {}", u.addr, u.active.max(0));
    }
    header(&mut o, "vajra_upstream_latency_seconds", "histogram", "Time from starting an upstream attempt to a complete response.");
    for u in &ups {
        let mut cum = 0u64;
        for (i, &b) in LAT_BOUNDS_US.iter().enumerate() {
            cum += u.latency.buckets[i];
            let _ = writeln!(
                o,
                "vajra_upstream_latency_seconds_bucket{{upstream=\"{}\",le=\"{}\"}} {cum}",
                u.addr,
                b as f64 / 1e6
            );
        }
        cum += u.latency.buckets[12];
        let _ = writeln!(o, "vajra_upstream_latency_seconds_bucket{{upstream=\"{}\",le=\"+Inf\"}} {cum}", u.addr);
        let _ = writeln!(o, "vajra_upstream_latency_seconds_sum{{upstream=\"{}\"}} {}", u.addr, u.latency.sum_us as f64 / 1e6);
        let _ = writeln!(o, "vajra_upstream_latency_seconds_count{{upstream=\"{}\"}} {}", u.addr, u.latency.count);
    }

    header(&mut o, "vajra_config_reloads_total", "counter", "Configuration reload attempts applied by workers.");
    let _ = writeln!(o, "vajra_config_reloads_total{{result=\"ok\"}} {}", total.reloads_ok);
    let _ = writeln!(o, "vajra_config_reloads_total{{result=\"error\"}} {}", total.reloads_failed);
    header(&mut o, "vajra_access_log_write_errors_total", "counter", "Failed access-log writes.");
    let _ = writeln!(o, "vajra_access_log_write_errors_total {}", total.log_write_errors);

    o
}

/// Group helper used by tests and the admin endpoint.
pub fn sum_by_class(m: &Metrics) -> HashMap<&'static str, u64> {
    ["other", "1xx", "2xx", "3xx", "4xx", "5xx"].iter().copied().zip(m.status.iter().copied()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(p: u16) -> UpAddr {
        UpAddr::Tcp(format!("127.0.0.1:{p}").parse().unwrap())
    }

    #[test]
    fn histogram_buckets() {
        let mut h = Hist::default();
        h.observe(500); // <= 1ms
        h.observe(1_000); // boundary is inclusive
        h.observe(7_000); // <= 10ms
        h.observe(99_000_000); // +Inf
        assert_eq!(h.buckets[0], 2);
        assert_eq!(h.buckets[2], 1);
        assert_eq!(h.buckets[12], 1);
        assert_eq!((h.count, h.sum_us), (4, 500 + 1_000 + 7_000 + 99_000_000));
    }

    #[test]
    fn merge_sums_by_upstream_address() {
        let mut a = Metrics::default();
        let i = a.up_index(&addr(1));
        a.ups[i].requests = 3;
        a.ups[i].latency.observe(2_000);
        a.status[2] = 5;
        let mut b = Metrics::default();
        b.up_index(&addr(2));
        let j = b.up_index(&addr(1));
        b.ups[j].requests = 4;
        b.ups[j].latency.observe(2_000);
        b.status[2] = 1;

        a.merge(&b);
        assert_eq!(a.ups.len(), 2);
        let idx1 = a.up_index(&addr(1));
        assert_eq!(a.ups[idx1].requests, 7);
        assert_eq!(a.ups[idx1].latency.count, 2);
        assert_eq!(a.status[2], 6);
    }

    #[test]
    fn up_index_is_stable() {
        let mut m = Metrics::default();
        assert_eq!(m.up_index(&addr(1)), 0);
        assert_eq!(m.up_index(&addr(2)), 1);
        assert_eq!(m.up_index(&addr(1)), 0);
    }

    #[test]
    fn access_log_line_format() {
        let mut o = Observer::new();
        o.log_enabled = true;
        o.now = 784_111_777; // 1994-11-06 08:49:37 UTC
        o.response(Some("203.0.113.9".parse().unwrap()), Http::H1, "GET", "/a/b?x=1", 200, 123);
        o.response(None, Http::H2, "POST", "/up", 502, 0);
        let s = String::from_utf8(o.log.clone()).unwrap();
        let mut lines = s.lines();
        assert_eq!(
            lines.next().unwrap(),
            "203.0.113.9 - - [06/Nov/1994:08:49:37 +0000] \"GET /a/b?x=1 HTTP/1.1\" 200 123"
        );
        assert_eq!(lines.next().unwrap(), "- - - [06/Nov/1994:08:49:37 +0000] \"POST /up HTTP/2\" 502 0");
        assert_eq!((o.m.requests_h1, o.m.requests_h2), (1, 1));
        assert_eq!((o.m.status[2], o.m.status[5]), (1, 1));
    }

    #[test]
    fn access_log_cannot_be_forged() {
        let mut o = Observer::new();
        o.log_enabled = true;
        o.response(None, Http::H1, "GET", "/x\" 200 0\n1.2.3.4 - - \"GET /evil", 200, 1);
        let s = String::from_utf8(o.log).unwrap();
        assert_eq!(s.lines().count(), 1, "newline must be escaped: {s}");
        assert!(s.contains("\\x22") && s.contains("\\x0a"));
    }

    #[test]
    fn disabled_log_still_counts() {
        let mut o = Observer::new();
        o.response(None, Http::H1, "GET", "/", 404, 0);
        assert!(o.log.is_empty());
        assert_eq!(o.m.status[4], 1);
    }

    #[test]
    fn prometheus_rendering() {
        let mut m1 = Metrics::default();
        m1.conns_accepted = 2;
        m1.requests_h1 = 3;
        m1.status[2] = 3;
        let i = m1.up_index(&addr(9000));
        m1.ups[i].requests = 5;
        m1.ups[i].latency.observe(3_000);
        m1.ups[i].latency.observe(40_000);
        let mut m2 = Metrics::default();
        m2.conns_accepted = 1;
        let s1 = Snapshot { worker: 0, metrics: m1, active_conns: 4, cache: CacheStats { hits: 2, ..Default::default() }, cache_entries: 7, cache_bytes: 700 };
        let s2 = Snapshot { worker: 1, metrics: m2, active_conns: 1, cache: CacheStats { hits: 1, ..Default::default() }, cache_entries: 0, cache_bytes: 0 };

        let text = render_prometheus(&[s1, s2]);
        assert!(text.contains("vajra_workers 2\n"));
        assert!(text.contains("vajra_connections_total 3\n"));
        assert!(text.contains("vajra_connections_active{worker=\"0\"} 4\n"));
        assert!(text.contains("vajra_connections_active{worker=\"1\"} 1\n"));
        assert!(text.contains("vajra_http_requests_total{protocol=\"http1\"} 3\n"));
        assert!(text.contains("vajra_http_responses_total{class=\"2xx\"} 3\n"));
        assert!(text.contains("vajra_cache_hits_total 3\n"));
        assert!(text.contains("vajra_cache_entries{worker=\"0\"} 7\n"));
        assert!(text.contains("vajra_upstream_requests_total{upstream=\"127.0.0.1:9000\"} 5\n"));
        // Histogram buckets are cumulative.
        assert!(text.contains("vajra_upstream_latency_seconds_bucket{upstream=\"127.0.0.1:9000\",le=\"0.005\"} 1\n"));
        assert!(text.contains("vajra_upstream_latency_seconds_bucket{upstream=\"127.0.0.1:9000\",le=\"0.05\"} 2\n"));
        assert!(text.contains("vajra_upstream_latency_seconds_bucket{upstream=\"127.0.0.1:9000\",le=\"+Inf\"} 2\n"));
        assert!(text.contains("vajra_upstream_latency_seconds_count{upstream=\"127.0.0.1:9000\"} 2\n"));
        // Every sample line is preceded by TYPE metadata for its family.
        assert!(text.contains("# TYPE vajra_upstream_latency_seconds histogram"));
    }
}
