//! HTTP/1.1 request handling plus the response renderers shared with HTTP/2.
//!
//! No socket I/O happens here: `process` turns bytes in into response bytes
//! out, plus an optional [`Action`] the worker must carry out (stream a file,
//! run a proxy request, or wait for more body bytes).
//!
//! Request bodies are only accepted on proxy routes (buffered, bounded by
//! `Ctx::max_body`, `Content-Length` framing only). Everywhere else a request
//! that declares a body is answered and then the connection is closed, so the
//! byte stream can never desynchronise.
//!
//! Phase 4: every response produced here is reported to the worker's
//! [`Observer`] (metrics + access log), and proxied `GET`s are answered from the
//! per-core response cache when a fresh entry exists (`X-Cache: HIT`).

use crate::cache::{self, Cache, CacheMode};
use crate::date::DATE_LEN;
use crate::h2::{H2Body, H2Response};
use crate::observe::{Http, Observer};
use crate::proxy::{self, is_hop_by_hop, ProxySpec, ProxyTable, ReqParts};
use crate::router::{self, Reply};
use crate::static_files::{FileCache, OpenFile};
use std::cell::RefCell;
use std::net::IpAddr;
use std::rc::Rc;

/// Max request headers accepted per request (stack-allocated array).
pub const MAX_HEADERS: usize = 64;
/// An incomplete request head larger than this gets a 431.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Per-call context borrowed from the worker.
pub struct Ctx<'a> {
    pub files: Option<&'a mut FileCache>,
    pub proxies: &'a ProxyTable,
    pub cache: &'a mut Cache,
    pub obs: &'a mut Observer,
    /// Unix seconds (cache freshness).
    pub now: u64,
    pub max_body: usize,
    pub secure: bool,
    pub client_ip: Option<IpAddr>,
}

thread_local! {
    /// `Alt-Svc` value advertised on HTTP/1.1 and HTTP/2 responses (empty = none).
    /// Thread-local: each worker sets its own copy, nothing is shared.
    static ALT_SVC: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Advertise HTTP/3 on this thread's responses, e.g. `h3=":443"; ma=86400`.
pub fn set_alt_svc(value: Option<&str>) {
    ALT_SVC.with(|a| *a.borrow_mut() = value.map(|v| v.as_bytes().to_vec()).unwrap_or_default());
}

/// `Alt-Svc: ..\r\n` for an HTTP/1.1 head, or nothing.
fn push_alt_svc_h1(out: &mut Vec<u8>) {
    ALT_SVC.with(|a| {
        let a = a.borrow();
        if !a.is_empty() {
            out.extend_from_slice(b"Alt-Svc: ");
            out.extend_from_slice(&a);
            out.extend_from_slice(b"\r\n");
        }
    });
}

fn push_alt_svc_h2(out: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    ALT_SVC.with(|a| {
        let a = a.borrow();
        if !a.is_empty() {
            out.push((b"alt-svc".to_vec(), a.clone()));
        }
    });
}

pub enum Action {
    None,
    /// Stream this file as the body of the response whose head is in `out`.
    File(Rc<OpenFile>),
    /// Run this upstream request; the response is written when it completes.
    Proxy(ProxySpec),
    /// A proxy request's head is complete but its body is not: call again with more bytes.
    NeedBody,
}

pub struct Outcome {
    /// Bytes of `input` fully consumed.
    pub consumed: usize,
    /// Close the connection after everything is flushed.
    pub close: bool,
    pub action: Action,
}

fn done(consumed: usize, close: bool) -> Outcome {
    Outcome { consumed, close, action: Action::None }
}

/// Error response + metrics/log entry (the request line may be unparsed).
pub fn fail(
    out: &mut Vec<u8>,
    obs: &mut Observer,
    ip: Option<IpAddr>,
    status: u16,
    date: &[u8; DATE_LEN],
) {
    obs.response(ip, Http::H1, "-", "-", status, error_body(status).len() as u64);
    write_error(out, status, date);
}

/// Parse as many complete (possibly pipelined) requests as `input` holds,
/// appending responses to `out`. Stops after a request that needs an action.
pub fn process(
    input: &[u8],
    out: &mut Vec<u8>,
    date: &[u8; DATE_LEN],
    ctx: &mut Ctx,
) -> Outcome {
    let mut consumed = 0;
    loop {
        if consumed == input.len() {
            return done(consumed, false);
        }

        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&input[consumed..]) {
            Ok(httparse::Status::Complete(n)) => {
                let method = req.method.unwrap_or("");
                let target = req.path.unwrap_or("/");
                let path = target.split('?').next().unwrap_or("/");

                let mut keep_alive = req.version == Some(1);
                let mut content_length: Option<usize> = None;
                let mut bad_length = false;
                let mut chunked = false;
                let mut if_none_match: Option<&[u8]> = None;
                let mut host: Option<&[u8]> = None;

                for h in req.headers.iter() {
                    if h.name.eq_ignore_ascii_case("connection") {
                        let has = |t: &str| {
                            h.value
                                .split(|&b| b == b',')
                                .any(|x| x.trim_ascii().eq_ignore_ascii_case(t.as_bytes()))
                        };
                        if has("close") {
                            keep_alive = false;
                        } else if has("keep-alive") {
                            keep_alive = true;
                        }
                    } else if h.name.eq_ignore_ascii_case("content-length") {
                        let v = std::str::from_utf8(h.value)
                            .ok()
                            .and_then(|s| s.trim().parse::<usize>().ok());
                        match v {
                            Some(v) if content_length.map_or(true, |p| p == v) => {
                                content_length = Some(v)
                            }
                            _ => bad_length = true,
                        }
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        chunked = true;
                    } else if h.name.eq_ignore_ascii_case("if-none-match") {
                        if_none_match = Some(h.value);
                    } else if h.name.eq_ignore_ascii_case("host") {
                        host = Some(h.value);
                    }
                }

                if bad_length {
                    fail(out, ctx.obs, ctx.client_ip, 400, date);
                    return done(input.len(), true);
                }

                let head_only = method == "HEAD";
                let reply = router::route(
                    method,
                    path,
                    if_none_match,
                    ctx.files.as_deref_mut(),
                    ctx.proxies,
                );

                if let Some((ri, php_target)) = reply.proxy_parts() {
                    if chunked {
                        fail(out, ctx.obs, ctx.client_ip, 411, date);
                        return done(input.len(), true);
                    }
                    let cl = content_length.unwrap_or(0);
                    let hdrs_all: Vec<(&[u8], &[u8])> = req
                        .headers
                        .iter()
                        .map(|h| (h.name.as_bytes(), h.value))
                        .collect();
                    // A WebSocket handshake is a body-less GET; anything else is plain HTTP.
                    let upgrade = method == "GET"
                        && cl == 0
                        && php_target.is_none()
                        && proxy::is_websocket_upgrade(&hdrs_all);
                    if cl > ctx.max_body {
                        fail(out, ctx.obs, ctx.client_ip, 413, date);
                        return done(input.len(), true);
                    }
                    if input.len() - consumed < n + cl {
                        // Head complete, body still arriving: consume nothing.
                        return Outcome { consumed, close: false, action: Action::NeedBody };
                    }
                    let body = &input[consumed + n..consumed + n + cl];
                    let hdrs = hdrs_all;

                    let cache_on = !upgrade && ctx.proxies.route(ri).cache.is_some();
                    let mode = match cache::lookup_for_request(
                        ctx.cache,
                        cache_on,
                        method,
                        host.unwrap_or(b""),
                        target,
                        &hdrs,
                        ctx.now,
                    ) {
                        cache::Lookup::Hit(hit) => {
                            write_proxy_response(
                                out, hit.status, &hit.headers, &hit.body, false, keep_alive, date,
                                Some("HIT"),
                            );
                            let bytes = if hit.status == 204 || hit.status == 304 { 0 } else { hit.body.len() as u64 };
                            ctx.obs.response(ctx.client_ip, Http::H1, method, target, hit.status, bytes);
                            consumed += n + cl;
                            if !keep_alive {
                                return done(consumed, true);
                            }
                            continue;
                        }
                        cache::Lookup::Miss(m) => m,
                    };

                    let mut spec = proxy::make_spec(
                        ctx.proxies,
                        ri,
                        &ReqParts {
                            method,
                            target,
                            host,
                            headers: &hdrs,
                            body,
                            client_ip: ctx.client_ip,
                            secure: ctx.secure,
                            upgrade,
                            php: php_target,
                        },
                    );
                    spec.cache = mode;
                    return Outcome {
                        consumed: consumed + n + cl,
                        // An upgrade never keeps HTTP semantics: the tunnel owns the socket.
                        close: !keep_alive && !upgrade,
                        action: Action::Proxy(spec),
                    };
                }

                consumed += n;
                if chunked || content_length.is_some_and(|v| v > 0) {
                    keep_alive = false; // body is not consumed on these routes
                }
                if matches!(reply, Reply::Mem { status: 405, .. } | Reply::BadRequest) {
                    keep_alive = false;
                }

                let bad = matches!(reply, Reply::BadRequest);
                let (status, bytes) = reply_meta(&reply, head_only);
                ctx.obs.response(ctx.client_ip, Http::H1, method, target, status, bytes);
                let file = write_reply(out, &reply, head_only, keep_alive, date);
                if bad {
                    return done(input.len(), true);
                }
                if let Some(f) = file {
                    return Outcome { consumed, close: !keep_alive, action: Action::File(f) };
                }
                if !keep_alive {
                    return done(consumed, true);
                }
            }
            Ok(httparse::Status::Partial) => return done(consumed, false),
            Err(httparse::Error::TooManyHeaders) => {
                fail(out, ctx.obs, ctx.client_ip, 431, date);
                return done(input.len(), true);
            }
            Err(_) => {
                fail(out, ctx.obs, ctx.client_ip, 400, date);
                return done(input.len(), true);
            }
        }
    }
}

/// Status and declared body size of a router reply, for logs and metrics.
pub fn reply_meta(reply: &Reply, head_only: bool) -> (u16, u64) {
    match reply {
        Reply::Mem { status, body, .. } => (*status, if head_only { 0 } else { body.len() as u64 }),
        Reply::File { file, not_modified } => {
            if *not_modified {
                (304, 0)
            } else {
                (200, if head_only { 0 } else { file.size })
            }
        }
        Reply::BadRequest => (400, error_body(400).len() as u64),
        Reply::Proxy(_) | Reply::Php(..) => (0, 0),
    }
}

// ───────────────────────── HTTP/1.1 renderers ─────────────────────────

/// Render a router reply. Returns the file to stream when there is a body.
fn write_reply(
    out: &mut Vec<u8>,
    reply: &Reply,
    head_only: bool,
    keep_alive: bool,
    date: &[u8; DATE_LEN],
) -> Option<Rc<OpenFile>> {
    match reply {
        Reply::Mem { status, ctype, body, allow } => {
            let extra: &[u8] = if *allow { b"Allow: GET, HEAD\r\n" } else { b"" };
            write_head(out, *status, extra, ctype, body.len() as u64, keep_alive, date);
            if !head_only {
                out.extend_from_slice(body);
            }
            None
        }
        Reply::File { file, not_modified } => {
            if *not_modified {
                write_head(out, 304, &file.head_extra, file.ctype, file.size, keep_alive, date);
                None
            } else {
                write_head(out, 200, &file.head_extra, file.ctype, file.size, keep_alive, date);
                (!head_only && file.size > 0).then(|| Rc::clone(file))
            }
        }
        Reply::BadRequest => {
            write_error(out, 400, date);
            None
        }
        Reply::Proxy(_) | Reply::Php(..) => unreachable!("proxy replies are handled by the caller"),
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

pub fn error_body(status: u16) -> &'static [u8] {
    match status {
        400 => b"bad request\n",
        411 => b"length required\n",
        413 => b"payload too large\n",
        431 => b"request header fields too large\n",
        502 => b"bad gateway\n",
        504 => b"gateway timeout\n",
        _ => b"error\n",
    }
}

/// Minimal error response that always closes the connection.
pub fn write_error(out: &mut Vec<u8>, status: u16, date: &[u8; DATE_LEN]) {
    let body = error_body(status);
    write_head(out, status, b"", router::TEXT, body.len() as u64, false, date);
    out.extend_from_slice(body);
}

/// Status line + headers + blank line. Hand-rolled (no `write!`) to keep the
/// hot path free of the formatting machinery. `extra` is zero or more
/// complete `Name: value\r\n` lines.
fn write_head(
    out: &mut Vec<u8>,
    status: u16,
    extra: &[u8],
    content_type: &str,
    content_length: u64,
    keep_alive: bool,
    date: &[u8; DATE_LEN],
) {
    out.extend_from_slice(b"HTTP/1.1 ");
    push_u64(out, status as u64);
    out.push(b' ');
    out.extend_from_slice(reason(status).as_bytes());
    out.extend_from_slice(b"\r\nServer: Vajra\r\nDate: ");
    out.extend_from_slice(date);
    out.extend_from_slice(b"\r\n");
    push_alt_svc_h1(out);
    out.extend_from_slice(b"Content-Type: ");
    out.extend_from_slice(content_type.as_bytes());
    out.extend_from_slice(b"\r\nContent-Length: ");
    push_u64(out, content_length);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(extra);
    out.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n\r\n"
    } else {
        b"Connection: close\r\n\r\n"
    });
}

/// Render a buffered upstream (or cached) response for an HTTP/1.1 client.
/// `xcache` adds an `X-Cache` header (`HIT` / `MISS`).
#[allow(clippy::too_many_arguments)]
pub fn write_proxy_response(
    out: &mut Vec<u8>,
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: &[u8],
    head_req: bool,
    keep_alive: bool,
    date: &[u8; DATE_LEN],
    xcache: Option<&str>,
) {
    let bodyless = status == 204 || status == 304;
    out.extend_from_slice(b"HTTP/1.1 ");
    push_u64(out, status as u64);
    out.push(b' ');
    out.extend_from_slice(reason(status).as_bytes());
    out.extend_from_slice(b"\r\nServer: Vajra\r\nDate: ");
    out.extend_from_slice(date);
    out.extend_from_slice(b"\r\n");
    push_alt_svc_h1(out);
    for (n, v) in headers {
        if is_hop_by_hop(n)
            || n.eq_ignore_ascii_case(b"date")
            || n.eq_ignore_ascii_case(b"server")
            || n.eq_ignore_ascii_case(b"x-cache")
            || (n.eq_ignore_ascii_case(b"content-length") && !head_req)
        {
            continue;
        }
        out.extend_from_slice(n);
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(x) = xcache {
        out.extend_from_slice(b"X-Cache: ");
        out.extend_from_slice(x.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !head_req && !bodyless {
        out.extend_from_slice(b"Content-Length: ");
        push_u64(out, body.len() as u64);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n\r\n"
    } else {
        b"Connection: close\r\n\r\n"
    });
    if !head_req && !bodyless {
        out.extend_from_slice(body);
    }
}

#[inline]
fn push_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&tmp[i..]);
}

// ───────────────────────── HTTP/2 renderers ─────────────────────────

fn h2_base(date: &[u8; DATE_LEN], ctype: &str, len: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut v = vec![
        (b"server".to_vec(), b"Vajra".to_vec()),
        (b"date".to_vec(), date.to_vec()),
        (b"content-type".to_vec(), ctype.as_bytes().to_vec()),
        (b"content-length".to_vec(), len.to_string().into_bytes()),
    ];
    push_alt_svc_h2(&mut v);
    v
}

pub fn h2_response(reply: &Reply, head_only: bool, date: &[u8; DATE_LEN]) -> H2Response {
    match reply {
        Reply::Mem { status, ctype, body, allow } => {
            let mut headers = h2_base(date, ctype, body.len() as u64);
            if *allow {
                headers.push((b"allow".to_vec(), b"GET, HEAD".to_vec()));
            }
            H2Response {
                status: *status,
                headers,
                body: if head_only { H2Body::Empty } else { H2Body::Mem(body.to_vec()) },
            }
        }
        Reply::File { file, not_modified } => {
            let mut headers = h2_base(date, file.ctype, file.size);
            headers.push((b"etag".to_vec(), file.etag.as_bytes().to_vec()));
            headers.push((b"last-modified".to_vec(), file.last_modified.to_vec()));
            if *not_modified {
                H2Response { status: 304, headers, body: H2Body::Empty }
            } else {
                let body = if head_only || file.size == 0 {
                    H2Body::Empty
                } else {
                    H2Body::File(Rc::clone(file))
                };
                H2Response { status: 200, headers, body }
            }
        }
        Reply::BadRequest | Reply::Proxy(_) | Reply::Php(..) => h2_error(400, date),
    }
}

pub fn h2_error(status: u16, date: &[u8; DATE_LEN]) -> H2Response {
    let body = error_body(status);
    H2Response {
        status,
        headers: h2_base(date, router::TEXT, body.len() as u64),
        body: H2Body::Mem(body.to_vec()),
    }
}

pub fn h2_proxy_response(
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: Vec<u8>,
    head_req: bool,
    date: &[u8; DATE_LEN],
    xcache: Option<&'static str>,
) -> H2Response {
    let bodyless = status == 204 || status == 304;
    let mut out = vec![
        (b"server".to_vec(), b"Vajra".to_vec()),
        (b"date".to_vec(), date.to_vec()),
    ];
    push_alt_svc_h2(&mut out);
    for (n, v) in headers {
        if is_hop_by_hop(n)
            || n.eq_ignore_ascii_case(b"date")
            || n.eq_ignore_ascii_case(b"server")
            || n.eq_ignore_ascii_case(b"x-cache")
            || (n.eq_ignore_ascii_case(b"content-length") && !head_req)
        {
            continue;
        }
        out.push((n.to_ascii_lowercase(), v.clone()));
    }
    if let Some(x) = xcache {
        out.push((b"x-cache".to_vec(), x.as_bytes().to_vec()));
    }
    if !head_req && !bodyless {
        out.push((b"content-length".to_vec(), body.len().to_string().into_bytes()));
    }
    let body = if head_req || bodyless || body.is_empty() { H2Body::Empty } else { H2Body::Mem(body) };
    H2Response { status, headers: out, body }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachedResponse;
    use crate::config::{CacheSettings, ProxySettings};

    const DATE: &[u8; DATE_LEN] = b"Thu, 01 Jan 1970 00:00:00 GMT";

    fn table(cached: bool) -> ProxyTable {
        let mut p = ProxySettings::simple("/api/", "127.0.0.1:9000".parse().unwrap(), false, 5);
        p.cache = cached;
        p.cache_default_ttl_secs = 60;
        ProxyTable::new(&[p], 1 << 20)
    }

    struct Env {
        cache: Cache,
        obs: Observer,
    }

    fn env() -> Env {
        Env { cache: Cache::new(&CacheSettings::default()), obs: Observer::new() }
    }

    fn run_in(input: &str, t: &ProxyTable, e: &mut Env) -> (Outcome, String) {
        let mut out = Vec::new();
        let mut ctx = Ctx {
            files: None,
            proxies: t,
            cache: &mut e.cache,
            obs: &mut e.obs,
            now: 0,
            max_body: 1024,
            secure: false,
            client_ip: Some("192.0.2.7".parse().unwrap()),
        };
        let o = process(input.as_bytes(), &mut out, DATE, &mut ctx);
        (o, String::from_utf8(out).unwrap())
    }

    fn run_with(input: &str, t: &ProxyTable) -> (Outcome, String) {
        run_in(input, t, &mut env())
    }

    fn run(input: &str) -> (Outcome, String) {
        run_with(input, &ProxyTable::empty())
    }

    #[test]
    fn simple_get_keepalive() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (o, resp) = run(req);
        assert_eq!(o.consumed, req.len());
        assert!(!o.close && matches!(o.action, Action::None));
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Connection: keep-alive\r\n"));
        assert!(resp.contains("Content-Length: 27\r\n"));
        assert!(resp.ends_with("Vajra: hello from io_uring\n"));
    }

    #[test]
    fn pipelined_and_partial() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n";
        let (o, resp) = run(req);
        assert_eq!(o.consumed, req.len());
        assert_eq!(resp.matches("HTTP/1.1 200 OK").count(), 2);

        let (o, resp) = run("GET / HTTP/1.1\r\nHost: x");
        assert_eq!(o.consumed, 0);
        assert!(resp.is_empty());

        let first = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (o, resp) = run(&format!("{first}GET /hea"));
        assert_eq!(o.consumed, first.len());
        assert_eq!(resp.matches("200 OK").count(), 1);
    }

    #[test]
    fn head_not_found_405() {
        let (_, resp) = run("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(resp.contains("Content-Length: 27") && resp.ends_with("\r\n\r\n"));
        let (o, resp) = run("GET /nope?x=1 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(!o.close && resp.starts_with("HTTP/1.1 404 Not Found"));
        let (o, resp) = run("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc");
        assert!(o.close && resp.starts_with("HTTP/1.1 405") && resp.contains("Allow: GET, HEAD"));
    }

    #[test]
    fn connection_semantics() {
        let (o, resp) = run("GET / HTTP/1.0\r\n\r\n");
        assert!(o.close && resp.contains("Connection: close"));
        assert!(!run("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").0.close);
        assert!(run("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").0.close);
        assert!(run("GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd").0.close);
    }

    #[test]
    fn malformed_requests() {
        let (o, resp) = run("\x00\x01\x02 nonsense\r\n\r\n");
        assert!(o.close && resp.starts_with("HTTP/1.1 400"));
        let (o, resp) = run("GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n");
        assert!(o.close && resp.starts_with("HTTP/1.1 400"));

        let mut req = String::from("GET / HTTP/1.1\r\n");
        for i in 0..(MAX_HEADERS + 1) {
            req.push_str(&format!("X-H{i}: v\r\n"));
        }
        req.push_str("\r\n");
        let (o, resp) = run(&req);
        assert!(o.close && resp.starts_with("HTTP/1.1 431"));
    }

    #[test]
    fn responses_are_reported_to_the_observer() {
        let mut e = env();
        e.obs.log_enabled = true;
        e.obs.now = 784_111_777;
        run_in("GET /health HTTP/1.1\r\nHost: x\r\n\r\nGET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", &ProxyTable::empty(), &mut e);
        run_in("garbage\r\n\r\n", &ProxyTable::empty(), &mut e);
        assert_eq!(e.obs.m.requests_h1, 3);
        assert_eq!((e.obs.m.status[2], e.obs.m.status[4]), (1, 2));
        let log = String::from_utf8(e.obs.log.clone()).unwrap();
        let lines: Vec<_> = log.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("192.0.2.7 - - [06/Nov/1994:08:49:37 +0000] \"GET /health HTTP/1.1\" 200 3"), "{}", lines[0]);
        assert!(lines[1].ends_with("\"GET /nope HTTP/1.1\" 404 10"), "{}", lines[1]);
        assert!(lines[2].contains("\"- - HTTP/1.1\" 400 12"), "{}", lines[2]);
    }

    #[test]
    fn websocket_handshake_becomes_an_upgrade_proxy_action() {
        let t = table(true);
        let req = "GET /api/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\nEXTRA";
        let (o, resp) = run_with(req, &t);
        assert!(resp.is_empty());
        assert!(!o.close);
        assert_eq!(o.consumed, req.len() - "EXTRA".len(), "early client bytes stay in the input");
        let Action::Proxy(spec) = o.action else { panic!("expected proxy action") };
        assert!(spec.upgrade && !spec.idempotent);
        assert_eq!(spec.cache, CacheMode::None, "upgrades never touch the cache");
        let up = String::from_utf8(spec.request).unwrap();
        assert!(up.contains("Sec-WebSocket-Key: abc\r\n") && up.contains("Upgrade: websocket\r\n"));

        // A plain `Upgrade: h2c` request is an ordinary proxied request.
        let (o, _) = run_with("GET /api/x HTTP/1.1\r\nHost: e\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n", &t);
        let Action::Proxy(spec) = o.action else { panic!() };
        assert!(!spec.upgrade);
    }

    #[test]
    fn proxy_get_builds_upstream_request() {
        let t = table(false);
        let req = "GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let (o, resp) = run_with(req, &t);
        assert!(resp.is_empty(), "nothing is written until the upstream answers");
        assert_eq!(o.consumed, req.len());
        assert!(!o.close);
        let Action::Proxy(spec) = o.action else { panic!("expected proxy action") };
        let up = String::from_utf8(spec.request.clone()).unwrap();
        assert!(up.starts_with("GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(up.contains("X-Forwarded-For: 192.0.2.7\r\n"));
        assert!(spec.idempotent && !spec.head);
        assert_eq!(spec.cache, CacheMode::None, "route has caching disabled");
    }

    #[test]
    fn proxy_post_waits_for_full_body() {
        let t = table(false);
        let head = "POST /api/x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        let (o, _) = run_with(&format!("{head}he"), &t);
        assert_eq!(o.consumed, 0);
        assert!(matches!(o.action, Action::NeedBody));

        let full = format!("{head}hello");
        let (o, _) = run_with(&full, &t);
        assert_eq!(o.consumed, full.len());
        let Action::Proxy(spec) = o.action else { panic!() };
        assert!(!spec.idempotent);
        assert!(String::from_utf8(spec.request).unwrap().ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn proxy_body_limits() {
        let t = table(false);
        let (o, resp) = run_with("POST /api/x HTTP/1.1\r\nContent-Length: 999999\r\n\r\n", &t);
        assert!(o.close && resp.starts_with("HTTP/1.1 413"));
        let (o, resp) = run_with("POST /api/x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &t);
        assert!(o.close && resp.starts_with("HTTP/1.1 411"));
    }

    #[test]
    fn cache_miss_then_hit_then_invalidate() {
        let t = table(true);
        let mut e = env();
        let get = "GET /api/users?id=1 HTTP/1.1\r\nHost: Example.com\r\n\r\n";

        // Miss: the proxy is asked to store under a normalised key.
        let (o, resp) = run_in(get, &t, &mut e);
        assert!(resp.is_empty());
        let Action::Proxy(spec) = o.action else { panic!("miss should proxy") };
        assert_eq!(spec.cache, CacheMode::Store("example.com/api/users?id=1".into()));

        // Simulate the worker storing the upstream answer.
        e.cache.put(
            "example.com/api/users?id=1".into(),
            CachedResponse {
                status: 200,
                headers: vec![(b"Content-Type".to_vec(), b"text/plain".to_vec())],
                body: Rc::new(b"cached!".to_vec()),
                stored_at: 0,
                expires_at: 1000,
            },
        );

        // Hit: answered locally, no action, X-Cache header, body intact.
        let (o, resp) = run_in(get, &t, &mut e);
        assert!(matches!(o.action, Action::None) && !o.close);
        assert_eq!(o.consumed, get.len());
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("X-Cache: HIT\r\n") && resp.contains("Content-Length: 7\r\n"));
        assert!(resp.ends_with("\r\n\r\ncached!"));
        assert_eq!(e.cache.stats.hits, 1);
        assert_eq!(e.obs.m.requests_h1, 1, "hits are counted as responses");

        // A hit followed by a pipelined proxied request keeps parsing.
        let both = format!("{get}GET /api/other HTTP/1.1\r\nHost: Example.com\r\n\r\n");
        let (o, resp) = run_in(&both, &t, &mut e);
        assert_eq!(resp.matches("X-Cache: HIT").count(), 1);
        assert!(matches!(o.action, Action::Proxy(_)));
        assert_eq!(o.consumed, both.len());

        // Unsafe methods ask for invalidation.
        let (o, _) = run_in("POST /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n", &t, &mut e);
        let Action::Proxy(spec) = o.action else { panic!() };
        assert_eq!(spec.cache, CacheMode::Invalidate("example.com/api/users?id=1".into()));

        // Authorization bypasses the cache in both directions.
        let (o, resp) = run_in("GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer t\r\n\r\n", &t, &mut e);
        assert!(resp.is_empty());
        let Action::Proxy(spec) = o.action else { panic!() };
        assert_eq!(spec.cache, CacheMode::None);
    }

    #[test]
    fn expired_cache_entries_are_not_served() {
        let t = table(true);
        let mut e = env();
        e.cache.put(
            "h/api/x".into(),
            CachedResponse { status: 200, headers: vec![], body: Rc::new(b"old".to_vec()), stored_at: 0, expires_at: 0 },
        );
        let (o, resp) = run_in("GET /api/x HTTP/1.1\r\nHost: h\r\n\r\n", &t, &mut e);
        assert!(resp.is_empty() && matches!(o.action, Action::Proxy(_)));
    }

    #[test]
    fn proxy_response_rendering() {
        let hdrs = vec![
            (b"Content-Type".to_vec(), b"text/plain".to_vec()),
            (b"Connection".to_vec(), b"close".to_vec()),
            (b"Content-Length".to_vec(), b"99".to_vec()),
            (b"X-Custom".to_vec(), b"1".to_vec()),
            (b"X-Cache".to_vec(), b"spoofed".to_vec()),
        ];
        let mut out = Vec::new();
        write_proxy_response(&mut out, 201, &hdrs, b"abc", false, true, DATE, Some("MISS"));
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 201 Created\r\n"));
        assert!(s.contains("X-Custom: 1\r\n") && s.contains("Content-Length: 3\r\n"));
        assert!(s.contains("X-Cache: MISS\r\n") && !s.contains("spoofed"));
        assert!(!s.contains("99") && s.contains("Connection: keep-alive"));
        assert!(s.ends_with("\r\n\r\nabc"));

        let mut out = Vec::new();
        write_proxy_response(&mut out, 200, &hdrs, b"", true, false, DATE, None);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Content-Length: 99\r\n"), "HEAD passes the upstream length through");
        assert!(s.ends_with("\r\n\r\n") && s.contains("Connection: close") && !s.contains("X-Cache"));
    }

    #[test]
    fn h2_renderers() {
        let r = h2_proxy_response(200, &[(b"X-A".to_vec(), b"1".to_vec())], b"hi".to_vec(), false, DATE, Some("HIT"));
        assert!(r.headers.iter().any(|(n, v)| n == b"x-a" && v == b"1"));
        assert!(r.headers.iter().any(|(n, v)| n == b"content-length" && v == b"2"));
        assert!(r.headers.iter().any(|(n, v)| n == b"x-cache" && v == b"HIT"));
        assert!(matches!(r.body, H2Body::Mem(_)));
        assert_eq!(h2_error(502, DATE).status, 502);
    }
}
