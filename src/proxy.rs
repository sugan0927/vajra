//! Reverse-proxy building blocks. No socket I/O happens here: this module holds
//! the route table, the per-route load balancer, the idle-connection pool, the
//! upstream *request* serialiser and the incremental upstream *response* parser.
//! The worker drives the actual sockets.
//!
//! ## Load balancing (per worker, share-nothing)
//! Each worker keeps its own [`Balancer`] per route, so counters and health
//! state are private to a core: no atomics, no cross-core traffic. The cost is
//! that "least connections" and failure counts are *per core* views, which is
//! a good approximation under SO_REUSEPORT's even spreading.
//!
//! * `round_robin`, `least_conn` and `ip_hash` (client IP, stable per upstream set).
//! * Passive health: after `max_fails` consecutive transport failures an
//!   upstream is skipped for `fail_timeout`; the first attempt after that is a
//!   probe (one more failure re-opens the circuit immediately).
//! * If every upstream is marked down the balancer fails open and tries the
//!   one that recovers soonest, rather than returning 502 without trying.
//! * A request never tries the same upstream twice (`tried` bitmask, so at
//!   most 64 upstreams per route).
//!
//! ## Hot reload
//! A [`ProxyState`] is an immutable route table plus its mutable runtime
//! (balancers, idle sockets). Workers hold it in an `Rc`; in-flight requests
//! keep their snapshot alive while new requests use the new one. Dropping the
//! last reference closes the idle upstream sockets.
//!
//! Model limits: requests and responses are buffered (bounded), upstream
//! connections are HTTP/1.1 keep-alive, client `X-Forwarded-*` headers are
//! overwritten, never trusted. WebSocket upgrades become opaque tunnels (see `worker.rs`); body streaming is still buffered.

use crate::cache::{CacheMode, CachePolicy};
use crate::config::{Balance, ProxySettings, UpAddr};
use crate::fastcgi;
use crate::php::{PhpConfig, Target};
use crate::observe::Metrics;
use io_uring::types::Timespec;
use socket2::SockAddr;
use std::cell::RefCell;
use std::net::IpAddr;
use std::os::fd::RawFd;

/// Idle upstream connections kept per (route, upstream).
pub const MAX_IDLE_PER_UPSTREAM: usize = 64;

pub struct Upstream {
    pub addr: UpAddr,
    /// Kept in a stable heap location: handed to `IORING_OP_CONNECT` by pointer.
    pub sockaddr: SockAddr,
}

pub struct ProxyRoute {
    pub prefix: String,
    pub strip: bool,
    pub upstreams: Vec<Upstream>,
    /// Linked timeout applied to every upstream operation of an attempt.
    pub timeout: Timespec,
    /// `Some` when this route's GET responses may be cached.
    pub cache: Option<CachePolicy>,
    /// `Some`: FastCGI (PHP-FPM) route, selected by the PHP resolver, never by prefix.
    pub php: Option<PhpConfig>,
}

fn to_sockaddr(a: &UpAddr) -> SockAddr {
    match a {
        UpAddr::Tcp(s) => SockAddr::from(*s),
        // Length and absoluteness are validated by the config parser.
        UpAddr::Unix(p) => SockAddr::unix(p).expect("validated unix socket path"),
    }
}

pub struct ProxyTable {
    routes: Vec<ProxyRoute>,
    php: Option<usize>,
}

impl ProxyTable {
    pub fn empty() -> Self {
        Self { routes: Vec::new(), php: None }
    }

    pub fn new(cfg: &[ProxySettings], max_object_bytes: usize) -> Self {
        let routes = cfg
            .iter()
            .map(|p| ProxyRoute {
                prefix: p.prefix.clone(),
                strip: p.strip_prefix,
                upstreams: p
                    .upstreams
                    .iter()
                    .map(|a| Upstream { addr: a.clone(), sockaddr: to_sockaddr(a) })
                    .collect(),
                timeout: Timespec::new().sec(p.timeout_secs).nsec(0),
                cache: p.cache.then_some(CachePolicy {
                    default_ttl: p.cache_default_ttl_secs,
                    max_object_bytes,
                }),
                php: p.php.clone(),
            })
            .collect::<Vec<_>>();
        let php = routes.iter().position(|r| r.php.is_some());
        Self { routes, php }
    }

    /// The FastCGI route, if `[php]` is configured.
    pub fn php_route(&self) -> Option<(usize, &PhpConfig)> {
        self.php.and_then(|i| self.routes[i].php.as_ref().map(|c| (i, c)))
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn route(&self, i: usize) -> &ProxyRoute {
        &self.routes[i]
    }

    /// Longest matching prefix. A prefix without a trailing slash only matches
    /// on a path-segment boundary (`/api` matches `/api` and `/api/x`, not `/apix`).
    pub fn find(&self, path: &str) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for (i, r) in self.routes.iter().enumerate() {
            let p = r.prefix.as_str();
            let ok = r.php.is_none()
                && path.starts_with(p)
                && (p.ends_with('/') || path.len() == p.len() || path.as_bytes()[p.len()] == b'/');
            if ok && best.map_or(true, |(_, l)| p.len() > l) {
                best = Some((i, p.len()));
            }
        }
        best.map(|(i, _)| i)
    }
}

// ───────────────────────── load balancing ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    RoundRobin,
    LeastConn,
    IpHash,
}

impl From<Balance> for Algo {
    fn from(b: Balance) -> Self {
        match b {
            Balance::RoundRobin => Algo::RoundRobin,
            Balance::LeastConn => Algo::LeastConn,
            Balance::IpHash => Algo::IpHash,
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
struct UpState {
    fails: u32,
    down_until: u64,
    active: u32,
}

pub struct Balancer {
    algo: Algo,
    rr: usize,
    ups: Vec<UpState>,
    max_fails: u32,
    fail_timeout: u64,
}

impl Balancer {
    pub fn new(algo: Algo, n: usize, max_fails: u32, fail_timeout_secs: u64) -> Self {
        assert!((1..=64).contains(&n), "1..=64 upstreams per route");
        Self { algo, rr: 0, ups: vec![UpState::default(); n], max_fails, fail_timeout: fail_timeout_secs }
    }

    fn is_up(&self, i: usize, now: u64) -> bool {
        self.ups[i].down_until <= now
    }

    /// Choose an upstream not in the `tried` bitmask and count the attempt as
    /// active. Pair every `Some` with a [`release`](Self::release).
    pub fn pick(&mut self, now: u64, hash: u64, tried: u64) -> Option<usize> {
        let n = self.ups.len();
        let untried = |i: usize| tried & (1u64 << i) == 0;

        let mut cands: Vec<usize> = (0..n).filter(|&i| untried(i) && self.is_up(i, now)).collect();
        if cands.is_empty() {
            // Everything untried is marked down: fail open on the soonest to recover.
            let soonest = (0..n).filter(|&i| untried(i)).min_by_key(|&i| self.ups[i].down_until)?;
            cands.push(soonest);
        }

        let choice = match self.algo {
            Algo::RoundRobin => {
                // First candidate at or after the rotating cursor.
                let c = cands.iter().copied().find(|&i| i >= self.rr % n).unwrap_or(cands[0]);
                self.rr = c + 1;
                c
            }
            Algo::LeastConn => {
                let start = self.rr % n;
                let c = cands
                    .iter()
                    .copied()
                    .min_by_key(|&i| (self.ups[i].active, (i + n - start) % n))
                    .expect("non-empty");
                self.rr = c + 1;
                c
            }
            Algo::IpHash => {
                let start = (hash % n as u64) as usize;
                cands.iter().copied().min_by_key(|&i| (i + n - start) % n).expect("non-empty")
            }
        };
        self.ups[choice].active += 1;
        Some(choice)
    }

    /// End an attempt. Success clears the failure streak; failure extends it
    /// and (at `max_fails`) opens the circuit for `fail_timeout`.
    pub fn release(&mut self, i: usize, ok: bool, now: u64) {
        let u = &mut self.ups[i];
        u.active = u.active.saturating_sub(1);
        if ok {
            u.fails = 0;
            u.down_until = 0;
        } else {
            u.fails = u.fails.saturating_add(1);
            if u.fails >= self.max_fails {
                u.down_until = now + self.fail_timeout;
            }
        }
    }

    pub fn active(&self, i: usize) -> u32 {
        self.ups[i].active
    }

    pub fn is_down(&self, i: usize, now: u64) -> bool {
        !self.is_up(i, now)
    }
}

/// Stable hash of a client address for `ip_hash` (FNV-1a over the octets).
pub fn ip_hash(ip: Option<IpAddr>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    match ip {
        Some(IpAddr::V4(a)) => feed(&a.octets()),
        Some(IpAddr::V6(a)) => feed(&a.octets()),
        None => {}
    }
    h
}

/// A route table plus its runtime state. One `Rc<ProxyState>` per worker per
/// configuration generation.
pub struct ProxyState {
    pub table: ProxyTable,
    pub bal: RefCell<Vec<Balancer>>,
    /// `idle[route][upstream]` = pooled, currently unused upstream sockets.
    idle: RefCell<Vec<Vec<Vec<RawFd>>>>,
    /// `mids[route][upstream]` = index into `Metrics::ups`.
    pub mids: Vec<Vec<usize>>,
}

impl ProxyState {
    pub fn empty() -> Self {
        Self {
            table: ProxyTable::empty(),
            bal: RefCell::new(Vec::new()),
            idle: RefCell::new(Vec::new()),
            mids: Vec::new(),
        }
    }

    pub fn new(cfg: &[ProxySettings], max_object_bytes: usize, metrics: &mut Metrics) -> Self {
        let table = ProxyTable::new(cfg, max_object_bytes);
        let bal = cfg
            .iter()
            .map(|p| Balancer::new(p.balance.into(), p.upstreams.len(), p.max_fails, p.fail_timeout_secs))
            .collect();
        let idle = cfg.iter().map(|p| vec![Vec::new(); p.upstreams.len()]).collect();
        let mids = cfg
            .iter()
            .map(|p| p.upstreams.iter().map(|a| metrics.up_index(a)).collect())
            .collect();
        Self { table, bal: RefCell::new(bal), idle: RefCell::new(idle), mids }
    }

    pub fn take_idle(&self, route: usize, up: usize) -> Option<RawFd> {
        self.idle.borrow_mut()[route][up].pop()
    }

    /// Pool `fd` for reuse; returns false (caller must close it) when the pool is full.
    pub fn give_idle(&self, route: usize, up: usize, fd: RawFd) -> bool {
        let mut idle = self.idle.borrow_mut();
        let pool = &mut idle[route][up];
        if pool.len() < MAX_IDLE_PER_UPSTREAM {
            pool.push(fd);
            true
        } else {
            false
        }
    }
}

impl Drop for ProxyState {
    fn drop(&mut self) {
        for route in self.idle.get_mut().iter() {
            for pool in route {
                for &fd in pool {
                    // SAFETY: the pool owns these descriptors exclusively.
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }
    }
}

// ───────────────────────── upstream request building ─────────────────────────

/// Everything the worker needs to run one proxied request.
pub struct ProxySpec {
    pub route: usize,
    /// Fully serialised upstream request (head + body).
    pub request: Vec<u8>,
    pub head: bool,
    /// Safe to retry on another upstream / a stale pooled connection.
    pub idempotent: bool,
    /// For access logging.
    pub method: String,
    pub target: String,
    pub cache: CacheMode,
    /// WebSocket handshake: on a `101` answer the connection becomes an opaque tunnel.
    pub upgrade: bool,
    /// `request` holds FastCGI records and the answer is a FastCGI stream.
    pub fcgi: bool,
}

pub struct ReqParts<'a> {
    pub method: &'a str,
    /// Request target as received: path plus optional `?query`.
    pub target: &'a str,
    pub host: Option<&'a [u8]>,
    pub headers: &'a [(&'a [u8], &'a [u8])],
    pub body: &'a [u8],
    pub client_ip: Option<IpAddr>,
    pub secure: bool,
    /// Forward this request as a WebSocket upgrade (`Connection: Upgrade`).
    pub upgrade: bool,
    /// Script to run (set for PHP routes).
    pub php: Option<&'a Target>,
}

/// FastCGI request for a PHP route.
fn build_php_request(cfg: &PhpConfig, t: &Target, p: &ReqParts) -> Vec<u8> {
    let query = p.target.split_once('?').map_or("", |(_, q)| q);
    fastcgi::build_request(&fastcgi::CgiRequest {
        method: p.method,
        request_uri: p.target,
        query,
        script_name: &t.script_name,
        path_info: &t.path_info,
        document_root: &cfg.fpm_root,
        host: p.host,
        headers: p.headers,
        body: p.body,
        remote_addr: p.client_ip,
        https: p.secure,
    })
}

pub fn make_spec(table: &ProxyTable, route: usize, p: &ReqParts) -> ProxySpec {
    let r = table.route(route);
    let (request, fcgi) = match (&r.php, p.php) {
        (Some(cfg), Some(t)) => (build_php_request(cfg, t, p), true),
        _ => (build_request(r, p), false),
    };
    ProxySpec {
        route,
        request,
        fcgi,
        head: p.method == "HEAD",
        idempotent: !p.upgrade && matches!(p.method, "GET" | "HEAD" | "OPTIONS"),
        method: p.method.to_string(),
        target: p.target.to_string(),
        cache: CacheMode::None,
        upgrade: p.upgrade,
    }
}

const SKIP_REQ: &[&str] = &[
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
    "x-forwarded-for", "x-forwarded-proto", "expect",
];

/// True for a WebSocket opening handshake: `Upgrade: websocket` and a
/// `Connection` header listing `upgrade` (both token lists, case-insensitive).
pub fn is_websocket_upgrade(headers: &[(&[u8], &[u8])]) -> bool {
    let has_token = |name: &str, tok: &str| {
        headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case(name.as_bytes())
                && v.split(|&b| b == b',').any(|t| t.trim_ascii().eq_ignore_ascii_case(tok.as_bytes()))
        })
    };
    has_token("upgrade", "websocket") && has_token("connection", "upgrade")
}

/// Hop-by-hop headers (RFC 9110 7.6.1) that a proxy must not forward.
pub fn is_hop_by_hop(name: &[u8]) -> bool {
    const HOP: &[&str] = &[
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h.as_bytes()))
}

/// Serialise the upstream HTTP/1.1 request. The `Host` fallback uses the
/// route's first upstream; every upstream of a route receives identical bytes.
pub fn build_request(route: &ProxyRoute, p: &ReqParts) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + p.body.len());

    let (path, query) = match p.target.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (p.target, None),
    };
    out.extend_from_slice(p.method.as_bytes());
    out.push(b' ');
    if route.strip {
        let rest = &path[route.prefix.len().min(path.len())..];
        if !rest.starts_with('/') {
            out.push(b'/');
        }
        out.extend_from_slice(rest.as_bytes());
    } else {
        out.extend_from_slice(path.as_bytes());
    }
    if let Some(q) = query {
        out.push(b'?');
        out.extend_from_slice(q.as_bytes());
    }
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    match p.host {
        Some(h) => out.extend_from_slice(h),
        None => out.extend_from_slice(route.upstreams[0].addr.to_string().as_bytes()),
    }
    out.extend_from_slice(b"\r\n");

    for (name, value) in p.headers {
        if SKIP_REQ.iter().any(|s| name.eq_ignore_ascii_case(s.as_bytes())) {
            continue;
        }
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }

    if let Some(ip) = p.client_ip {
        out.extend_from_slice(b"X-Forwarded-For: ");
        out.extend_from_slice(ip.to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(if p.secure {
        b"X-Forwarded-Proto: https\r\n"
    } else {
        b"X-Forwarded-Proto: http\r\n"
    });

    if !p.body.is_empty() || matches!(p.method, "POST" | "PUT" | "PATCH") {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(p.body.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if p.upgrade {
        out.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    } else {
        out.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
    }
    out.extend_from_slice(p.body);
    out
}

// ───────────────────── upstream response parsing ─────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body (HEAD, 204, 304).
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

pub struct RespHead {
    pub status: u16,
    pub head_len: usize,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub framing: Framing,
    pub keepalive: bool,
}

pub enum HeadParse {
    Partial,
    Bad,
    Done(RespHead),
}

pub fn parse_response_head(buf: &[u8], head_req: bool) -> HeadParse {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut resp = httparse::Response::new(&mut headers);
    let n = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return HeadParse::Partial,
        Err(_) => return HeadParse::Bad,
    };

    let status = resp.code.unwrap_or(0);
    if status < 200 {
        return HeadParse::Bad; // interim (1xx) responses are not supported
    }

    let mut keepalive = resp.version == Some(1);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut out = Vec::with_capacity(resp.headers.len());

    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("connection") {
            let has = |t: &str| {
                h.value.split(|&b| b == b',').any(|x| x.trim_ascii().eq_ignore_ascii_case(t.as_bytes()))
            };
            if has("close") {
                keepalive = false;
            } else if has("keep-alive") {
                keepalive = true;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            let v = std::str::from_utf8(h.value).ok().and_then(|s| s.trim().parse::<usize>().ok());
            match v {
                Some(v) if content_length.map_or(true, |p| p == v) => content_length = Some(v),
                _ => return HeadParse::Bad,
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if h.value.trim_ascii().eq_ignore_ascii_case(b"chunked") {
                chunked = true;
            } else {
                return HeadParse::Bad; // gzip etc. as a transfer coding: unsupported
            }
        }
        out.push((h.name.as_bytes().to_vec(), h.value.to_vec()));
    }

    let framing = if head_req || status == 204 || status == 304 {
        Framing::None
    } else if chunked {
        Framing::Chunked
    } else if let Some(l) = content_length {
        Framing::Length(l)
    } else {
        keepalive = false;
        Framing::UntilClose
    };

    HeadParse::Done(RespHead { status, head_len: n, headers: out, framing, keepalive })
}

/// Incremental chunked-transfer decoder. `advance` is fed the *entire* raw
/// body area (everything after the response head) each time and resumes where
/// it stopped, so every byte is examined once.
#[derive(Default)]
pub struct Chunked {
    pos: usize,
    pub body: Vec<u8>,
    pub done: bool,
    /// Raw bytes consumed once `done` (to detect trailing garbage).
    pub consumed: usize,
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

impl Chunked {
    pub fn advance(&mut self, raw: &[u8], max_body: usize) -> Result<(), ()> {
        while !self.done {
            let rest = &raw[self.pos..];
            let Some(nl) = find_crlf(rest) else {
                return if rest.len() > 128 { Err(()) } else { Ok(()) };
            };
            let line = &rest[..nl];
            let hex = line.split(|&b| b == b';').next().unwrap_or(line).trim_ascii();
            if hex.is_empty() || hex.len() > 16 {
                return Err(());
            }
            let mut size: usize = 0;
            for &c in hex {
                let d = (c as char).to_digit(16).ok_or(())? as usize;
                size = size.checked_mul(16).and_then(|s| s.checked_add(d)).ok_or(())?;
            }

            if size == 0 {
                // Last chunk: skip optional trailer lines until the empty line.
                let mut p = self.pos + nl + 2;
                loop {
                    let Some(e) = find_crlf(&raw[p..]) else { return Ok(()) };
                    if e == 0 {
                        self.pos = p + 2;
                        self.consumed = self.pos;
                        self.done = true;
                        return Ok(());
                    }
                    p += e + 2;
                }
            }

            if size > max_body || self.body.len() + size > max_body {
                return Err(());
            }
            let data_start = self.pos + nl + 2;
            let end = data_start + size;
            if raw.len() < end + 2 {
                return Ok(());
            }
            if &raw[end..end + 2] != b"\r\n" {
                return Err(());
            }
            self.body.extend_from_slice(&raw[data_start..end]);
            self.pos = end + 2;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(prefix: &str, port: u16, strip: bool) -> ProxySettings {
        ProxySettings::simple(prefix, format!("127.0.0.1:{port}").parse().unwrap(), strip, 5)
    }

    fn table(strip: bool) -> ProxyTable {
        ProxyTable::new(&[s("/api/", 9000, strip), s("/api/v2/", 9001, false), s("/svc", 9002, true)], 1 << 20)
    }

    #[test]
    fn longest_prefix_and_boundaries() {
        let t = table(false);
        assert_eq!(t.find("/api/x"), Some(0));
        assert_eq!(t.find("/api/v2/x"), Some(1));
        assert_eq!(t.find("/svc"), Some(2));
        assert_eq!(t.find("/svc/a"), Some(2));
        assert_eq!(t.find("/svcx"), None);
        assert_eq!(t.find("/nothing"), None);
    }

    #[test]
    fn cache_policy_comes_from_settings() {
        let mut a = s("/a/", 1, false);
        a.cache = true;
        a.cache_default_ttl_secs = 30;
        let t = ProxyTable::new(&[a, s("/b/", 2, false)], 777);
        let p = t.route(0).cache.expect("cache enabled");
        assert_eq!((p.default_ttl, p.max_object_bytes), (30, 777));
        assert!(t.route(1).cache.is_none());
    }

    fn parts<'a>(method: &'a str, target: &'a str, headers: &'a [(&'a [u8], &'a [u8])], body: &'a [u8]) -> ReqParts<'a> {
        ReqParts { method, target, host: Some(b"example.com"), headers, body, client_ip: Some("10.1.2.3".parse().unwrap()), secure: true, upgrade: false, php: None }
    }

    #[test]
    fn websocket_detection_and_upgrade_request() {
        let h: [(&[u8], &[u8]); 3] = [
            (b"Upgrade", b"WebSocket"),
            (b"Connection", b"keep-alive, Upgrade"),
            (b"Sec-WebSocket-Key", b"dGhlIHNhbXBsZSBub25jZQ=="),
        ];
        assert!(is_websocket_upgrade(&h));
        assert!(!is_websocket_upgrade(&h[1..]));
        let h2: [(&[u8], &[u8]); 2] = [(b"Upgrade", b"h2c"), (b"Connection", b"Upgrade")];
        assert!(!is_websocket_upgrade(&h2));

        let t = table(false);
        let mut pr = parts("GET", "/api/ws", &h, b"");
        pr.upgrade = true;
        let s = String::from_utf8(build_request(t.route(0), &pr)).unwrap();
        assert!(s.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(s.ends_with("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"));
        assert!(!s.contains("keep-alive"));
        assert_eq!(s.matches("Upgrade: ").count(), 1);
        assert!(!make_spec(&t, 0, &pr).idempotent);
    }

    #[test]
    fn request_building_filters_and_adds_headers() {
        let t = table(false);
        let hdrs: [(&[u8], &[u8]); 5] = [
            (b"Accept", b"*/*"),
            (b"Connection", b"close"),
            (b"X-Forwarded-For", b"6.6.6.6"),
            (b"Content-Length", b"999"),
            (b"Cookie", b"a=b"),
        ];
        let r = String::from_utf8(build_request(t.route(0), &parts("GET", "/api/users?id=1", &hdrs, b""))).unwrap();
        assert!(r.starts_with("GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(r.contains("Accept: */*\r\n") && r.contains("Cookie: a=b\r\n"));
        assert!(!r.contains("6.6.6.6") && !r.contains("999"));
        assert!(r.contains("X-Forwarded-For: 10.1.2.3\r\n") && r.contains("X-Forwarded-Proto: https\r\n"));
        assert!(r.ends_with("Connection: keep-alive\r\n\r\n"));
    }

    #[test]
    fn strip_prefix_rewrites_target() {
        let t = table(true);
        let r = String::from_utf8(build_request(t.route(0), &parts("GET", "/api/users?x=1", &[], b""))).unwrap();
        assert!(r.starts_with("GET /users?x=1 HTTP/1.1"));
        let r = String::from_utf8(build_request(t.route(2), &parts("GET", "/svc", &[], b""))).unwrap();
        assert!(r.starts_with("GET / HTTP/1.1"));
        let r = String::from_utf8(build_request(t.route(2), &parts("GET", "/svc/a/b", &[], b""))).unwrap();
        assert!(r.starts_with("GET /a/b HTTP/1.1"));
    }

    #[test]
    fn body_gets_content_length_and_spec_flags() {
        let t = table(false);
        let spec = make_spec(&t, 0, &parts("POST", "/api/x", &[], b"hello"));
        assert!(!spec.idempotent && !spec.head);
        assert_eq!((spec.method.as_str(), spec.target.as_str()), ("POST", "/api/x"));
        let s = String::from_utf8(spec.request).unwrap();
        assert!(s.contains("Content-Length: 5\r\n") && s.ends_with("\r\n\r\nhello"));
        assert!(make_spec(&t, 0, &parts("GET", "/api/x", &[], b"")).idempotent);
    }

    // ---- balancer ----

    fn bal(algo: Algo, n: usize) -> Balancer {
        Balancer::new(algo, n, 2, 10)
    }

    /// Pick and immediately release as a success (so `active` stays 0).
    fn pick_ok(b: &mut Balancer, now: u64, hash: u64, tried: u64) -> Option<usize> {
        let i = b.pick(now, hash, tried)?;
        b.release(i, true, now);
        Some(i)
    }

    #[test]
    fn round_robin_cycles_evenly() {
        let mut b = bal(Algo::RoundRobin, 3);
        let seq: Vec<_> = (0..7).map(|_| pick_ok(&mut b, 0, 0, 0).unwrap()).collect();
        assert_eq!(seq, [0, 1, 2, 0, 1, 2, 0]);
    }

    #[test]
    fn tried_mask_excludes_and_exhausts() {
        let mut b = bal(Algo::RoundRobin, 3);
        let a = b.pick(0, 0, 0).unwrap();
        let c = b.pick(0, 0, 1 << a).unwrap();
        assert_ne!(a, c);
        let d = b.pick(0, 0, (1 << a) | (1 << c)).unwrap();
        assert!(d != a && d != c);
        assert!(b.pick(0, 0, 0b111).is_none(), "all upstreams already tried");
    }

    #[test]
    fn failing_upstream_is_skipped_then_probed() {
        let mut b = bal(Algo::RoundRobin, 2); // max_fails 2, fail_timeout 10
        for _ in 0..2 {
            let i = b.pick(100, 0, 0b10).unwrap(); // force upstream 0 by excluding 1
            assert_eq!(i, 0);
            b.release(i, false, 100);
        }
        assert!(b.is_down(0, 105));
        for _ in 0..5 {
            assert_eq!(pick_ok(&mut b, 105, 0, 0), Some(1), "down upstream is skipped");
        }
        // After fail_timeout the upstream is a candidate again (a probe).
        assert!(!b.is_down(0, 110));
        // A failed probe re-opens the circuit at once: the failure streak is
        // only cleared by a success, so it is still at `max_fails`.
        let i = b.pick(110, 0, 0b10).unwrap();
        assert_eq!(i, 0);
        b.release(i, false, 110);
        assert!(b.is_down(0, 111));
        // A success closes it for good.
        let i = b.pick(130, 0, 0b10).unwrap();
        b.release(i, true, 130);
        assert!(!b.is_down(0, 130));
    }

    #[test]
    fn all_down_fails_open_on_soonest_recovery() {
        let mut b = Balancer::new(Algo::RoundRobin, 2, 1, 10);
        let i = b.pick(0, 0, 0b10).unwrap();
        b.release(i, false, 0); // upstream 0 down until 10
        let j = b.pick(5, 0, 0b01).unwrap();
        b.release(j, false, 5); // upstream 1 down until 15
        assert_eq!(b.pick(6, 0, 0), Some(0), "0 recovers soonest");
    }

    #[test]
    fn least_conn_prefers_idle_upstreams() {
        let mut b = bal(Algo::LeastConn, 3);
        let first = b.pick(0, 0, 0).unwrap(); // stays active
        let second = b.pick(0, 0, 0).unwrap(); // stays active
        let third = b.pick(0, 0, 0).unwrap();
        let mut all = [first, second, third];
        all.sort();
        assert_eq!(all, [0, 1, 2], "spreads across idle upstreams first");
        b.release(second, true, 0);
        assert_eq!(b.pick(0, 0, 0), Some(second), "the freed upstream is now least loaded");
        assert_eq!(b.active(second), 1);
    }

    #[test]
    fn ip_hash_is_sticky_and_spreads() {
        let mut b = bal(Algo::IpHash, 4);
        let ip = |s: &str| ip_hash(Some(s.parse().unwrap()));
        let h = ip("198.51.100.7");
        let first = pick_ok(&mut b, 0, h, 0).unwrap();
        for _ in 0..10 {
            assert_eq!(pick_ok(&mut b, 0, h, 0), Some(first));
        }
        let distinct: std::collections::HashSet<_> =
            (1..=60).map(|i| pick_ok(&mut b, 0, ip(&format!("10.0.0.{i}")), 0).unwrap()).collect();
        assert!(distinct.len() >= 3, "{distinct:?}");
        // If the preferred upstream was already tried, the next one is used.
        assert_ne!(pick_ok(&mut b, 0, h, 1 << first), Some(first));
    }

    #[test]
    fn proxy_state_pools_and_interns_metrics() {
        let mut m = Metrics::default();
        let cfg = [s("/a/", 9000, false), s("/b/", 9001, false)];
        let st = ProxyState::new(&cfg, 1024, &mut m);
        assert_eq!(st.mids, vec![vec![0], vec![1]]);
        assert_eq!(m.ups.len(), 2);
        // Re-building with the same addresses reuses the metric slots.
        let st2 = ProxyState::new(&cfg, 1024, &mut m);
        assert_eq!(st2.mids, st.mids);

        // Idle pool is bounded; use harmless pipe fds as stand-ins.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert!(st.take_idle(0, 0).is_none());
        assert!(st.give_idle(0, 0, fds[0]));
        assert_eq!(st.take_idle(0, 0), Some(fds[0]));
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    // ---- response parsing ----

    #[test]
    fn response_head_framings() {
        let h = |s: &str, head: bool| match parse_response_head(s.as_bytes(), head) {
            HeadParse::Done(h) => h,
            _ => panic!("not done: {s}"),
        };
        let r = h("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false);
        assert_eq!((r.status, r.framing, r.keepalive), (200, Framing::Length(5), true));
        assert_eq!(r.head_len, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".len());
        assert_eq!(h("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false).framing, Framing::Chunked);
        let r = h("HTTP/1.1 200 OK\r\n\r\n", false);
        assert_eq!((r.framing, r.keepalive), (Framing::UntilClose, false));
        assert_eq!(h("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", true).framing, Framing::None);
        assert_eq!(h("HTTP/1.1 304 Not Modified\r\n\r\n", false).framing, Framing::None);
        assert!(!h("HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", false).keepalive);
        assert!(!h("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n", false).keepalive);
    }

    #[test]
    fn response_head_rejects_garbage() {
        assert!(matches!(parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5", false), HeadParse::Partial));
        assert!(matches!(parse_response_head(b"garbage\r\n\r\n", false), HeadParse::Bad));
        assert!(matches!(parse_response_head(b"HTTP/1.1 100 Continue\r\n\r\n", false), HeadParse::Bad));
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", false),
            HeadParse::Bad
        ));
        assert!(matches!(
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n", false),
            HeadParse::Bad
        ));
    }

    #[test]
    fn chunked_decoding_in_pieces() {
        let full = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
        for cut in 0..=full.len() {
            let mut c = Chunked::default();
            c.advance(&full[..cut], 1 << 20).unwrap();
            if cut == full.len() {
                assert!(c.done);
                assert_eq!(c.body, b"hello world");
                assert_eq!(c.consumed, full.len());
            } else {
                assert!(!c.done, "finished early at {cut}");
            }
        }
    }

    #[test]
    fn chunked_errors() {
        let mut c = Chunked::default();
        assert!(c.advance(b"zz\r\n", 100).is_err());
        let mut c = Chunked::default();
        assert!(c.advance(b"5\r\nhelloXX", 100).is_err());
        let mut c = Chunked::default();
        assert!(c.advance(b"ffffffffffffffff\r\n", 100).is_err());
        let mut c = Chunked::default();
        assert!(c.advance(b"5\r\nhello\r\n", 3).is_err());
    }
}
