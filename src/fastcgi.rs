//! FastCGI (PHP-FPM) wire protocol. Pure and I/O-free: the worker moves bytes,
//! this module turns a request into FastCGI records and a stream of FastCGI
//! records back into an HTTP/1.1 response that the ordinary proxy pipeline
//! (response parsing, caching rules, header filtering, access log) consumes.
//!
//! ## Model
//! * Role RESPONDER, one request per connection, request id 1, `KEEP_CONN`
//!   **not** set: the application closes the connection after `END_REQUEST`
//!   (so there is no multiplexing and no connection pool to get wrong).
//! * Request = `BEGIN_REQUEST`, `PARAMS`* + empty `PARAMS`, `STDIN`* + empty
//!   `STDIN`. Records carry at most 65528 content bytes (a multiple of 8, so no
//!   padding is ever needed on the way out).
//! * Response = `STDOUT` records holding a CGI response (`Status:` and other
//!   headers, blank line, body), optional `STDERR` records (kept, capped),
//!   then `END_REQUEST`. The decoder buffers the whole CGI output (bounded by
//!   the caller's limit) and [`Decoder::take_http`] rewrites it as
//!   `HTTP/1.1 <status> <reason>` with a recomputed `Content-Length` and
//!   `Connection: close`.
//!
//! ## CGI environment
//! [`build_request`] sends the variables PHP and WordPress expect
//! (`SCRIPT_FILENAME`, `SCRIPT_NAME`, `PATH_INFO`, `REQUEST_URI`, `QUERY_STRING`,
//! `DOCUMENT_ROOT`, `HTTPS`, `HTTP_*`, ...). Client-supplied `Proxy`
//! (httpoxy) and `X-Forwarded-*` headers are never forwarded, and header names
//! containing `_` are dropped so they cannot alias a `-` header.

use std::net::IpAddr;

pub const VERSION: u8 = 1;
pub const REQUEST_ID: u16 = 1;

pub const BEGIN_REQUEST: u8 = 1;
pub const ABORT_REQUEST: u8 = 2;
pub const END_REQUEST: u8 = 3;
pub const PARAMS: u8 = 4;
pub const STDIN: u8 = 5;
pub const STDOUT: u8 = 6;
pub const STDERR: u8 = 7;

const ROLE_RESPONDER: u16 = 1;
/// Largest content length written per record (multiple of 8: no padding).
pub const MAX_CHUNK: usize = 65528;
/// Cap on retained `STDERR` bytes per request.
pub const MAX_STDERR: usize = 8192;
/// Cap on the CGI header block (before the blank line).
pub const MAX_CGI_HEAD: usize = 64 * 1024;

// ───────────────────────── encoding ─────────────────────────

fn record_header(out: &mut Vec<u8>, ty: u8, len: usize) {
    debug_assert!(len <= u16::MAX as usize);
    out.push(VERSION);
    out.push(ty);
    out.extend_from_slice(&REQUEST_ID.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.push(0); // padding
    out.push(0); // reserved
}

/// One record. `content` must fit a record (`<= 65535`).
pub fn write_record(out: &mut Vec<u8>, ty: u8, content: &[u8]) {
    record_header(out, ty, content.len());
    out.extend_from_slice(content);
}

/// A whole stream: `data` split into records, then the empty terminator record.
pub fn write_stream(out: &mut Vec<u8>, ty: u8, data: &[u8]) {
    for chunk in data.chunks(MAX_CHUNK) {
        write_record(out, ty, chunk);
    }
    write_record(out, ty, &[]);
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    }
}

/// Builder for the `PARAMS` name/value block.
#[derive(Default)]
pub struct Params {
    buf: Vec<u8>,
}

impl Params {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: &[u8], value: &[u8]) {
        put_len(&mut self.buf, name.len());
        put_len(&mut self.buf, value.len());
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(value);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

/// Decode a `PARAMS` block (used by tests and by mock application servers).
pub fn decode_params(mut b: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    fn len(b: &mut &[u8]) -> Option<usize> {
        let first = *b.first()?;
        if first < 128 {
            *b = &b[1..];
            Some(first as usize)
        } else {
            if b.len() < 4 {
                return None;
            }
            let n = u32::from_be_bytes([b[0] & 0x7f, b[1], b[2], b[3]]) as usize;
            *b = &b[4..];
            Some(n)
        }
    }
    let mut out = Vec::new();
    while !b.is_empty() {
        let nl = len(&mut b)?;
        let vl = len(&mut b)?;
        if b.len() < nl.checked_add(vl)? {
            return None;
        }
        out.push((b[..nl].to_vec(), b[nl..nl + vl].to_vec()));
        b = &b[nl + vl..];
    }
    Some(out)
}

/// What the application needs to know about one request.
pub struct CgiRequest<'a> {
    pub method: &'a str,
    /// The request target exactly as received (`/path?query`).
    pub request_uri: &'a str,
    pub query: &'a str,
    /// Decoded script path relative to the document root, e.g. `/index.php`.
    pub script_name: &'a str,
    pub path_info: &'a str,
    /// Document root as the application sees it.
    pub document_root: &'a str,
    pub host: Option<&'a [u8]>,
    pub headers: &'a [(&'a [u8], &'a [u8])],
    pub body: &'a [u8],
    pub remote_addr: Option<IpAddr>,
    pub https: bool,
}

/// Headers that never become `HTTP_*` variables.
const DROP_HEADERS: &[&str] = &[
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "expect", "host", "content-length",
    "content-type", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
    "x-forwarded-port", "x-real-ip", "forwarded",
    // httpoxy: a `Proxy` header would become HTTP_PROXY, which many HTTP clients trust.
    "proxy",
];

/// `Host` header -> (server name, port), IPv6 literals kept bracketed.
pub fn split_host(host: &[u8]) -> (String, Option<u16>) {
    let s = String::from_utf8_lossy(host).into_owned();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let port = rest[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
            return (format!("[{}]", &rest[..end]), port);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => match p.parse() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => (s, None),
        },
        _ => (s, None),
    }
}

/// `HTTP_FOO_BAR` for `Foo-Bar`; `None` for names that must not be forwarded.
pub fn http_var_name(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 256 {
        return None;
    }
    let lname = name.to_ascii_lowercase();
    if DROP_HEADERS.iter().any(|d| lname == d.as_bytes()) {
        return None;
    }
    let mut v = b"HTTP_".to_vec();
    for &b in name {
        match b {
            b'-' => v.push(b'_'),
            b'_' => return None, // would alias a `-` header (nginx drops these too)
            b if b.is_ascii_alphanumeric() => v.push(b.to_ascii_uppercase()),
            _ => return None,
        }
    }
    Some(v)
}

/// Serialise the complete FastCGI request (all records, ready to send).
pub fn build_request(r: &CgiRequest) -> Vec<u8> {
    let mut p = Params::new();
    let (server_name, host_port) = match r.host {
        Some(h) => split_host(h),
        None => ("localhost".to_string(), None),
    };
    let port = host_port.unwrap_or(if r.https { 443 } else { 80 });

    p.add(b"GATEWAY_INTERFACE", b"CGI/1.1");
    let software = format!("vajra/{}", option_env!("CARGO_PKG_VERSION").unwrap_or("0"));
    p.add(b"SERVER_SOFTWARE", software.as_bytes());
    p.add(b"SERVER_PROTOCOL", b"HTTP/1.1");
    p.add(b"REQUEST_SCHEME", if r.https { b"https" } else { b"http" });
    if r.https {
        p.add(b"HTTPS", b"on");
    }
    p.add(b"SERVER_NAME", server_name.as_bytes());
    p.add(b"SERVER_PORT", port.to_string().as_bytes());
    p.add(b"REQUEST_METHOD", r.method.as_bytes());
    p.add(b"REQUEST_URI", r.request_uri.as_bytes());
    p.add(b"DOCUMENT_URI", r.script_name.as_bytes());
    p.add(b"SCRIPT_NAME", r.script_name.as_bytes());
    p.add(b"QUERY_STRING", r.query.as_bytes());
    p.add(b"DOCUMENT_ROOT", r.document_root.as_bytes());
    let root = r.document_root.trim_end_matches('/');
    p.add(b"SCRIPT_FILENAME", format!("{root}{}", r.script_name).as_bytes());
    if !r.path_info.is_empty() {
        p.add(b"PATH_INFO", r.path_info.as_bytes());
        p.add(b"PATH_TRANSLATED", format!("{root}{}", r.path_info).as_bytes());
    }
    if let Some(ip) = r.remote_addr {
        p.add(b"REMOTE_ADDR", ip.to_string().as_bytes());
    }
    // Needed by php-cgi builds with cgi.force_redirect; harmless for FPM.
    p.add(b"REDIRECT_STATUS", b"200");

    if !r.body.is_empty() || matches!(r.method, "POST" | "PUT" | "PATCH") {
        p.add(b"CONTENT_LENGTH", r.body.len().to_string().as_bytes());
    }
    let mut ctype: Option<&[u8]> = None;
    for (n, v) in r.headers {
        if n.eq_ignore_ascii_case(b"content-type") && ctype.is_none() {
            ctype = Some(v);
        }
    }
    if let Some(c) = ctype {
        p.add(b"CONTENT_TYPE", c);
    }
    if let Some(h) = r.host {
        p.add(b"HTTP_HOST", h);
    }

    // HTTP_*: duplicates are folded (HTTP/2 and HTTP/3 split `cookie` into several fields).
    let mut vars: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (n, v) in r.headers {
        let Some(var) = http_var_name(n) else { continue };
        match vars.iter_mut().find(|(k, _)| *k == var) {
            Some((k, val)) => {
                val.extend_from_slice(if k == b"HTTP_COOKIE" { b"; " } else { b", " });
                val.extend_from_slice(v);
            }
            None => vars.push((var, v.to_vec())),
        }
    }
    for (k, v) in &vars {
        p.add(k, v);
    }

    let mut out = Vec::with_capacity(256 + p.as_bytes().len() + r.body.len());
    let mut begin = [0u8; 8];
    begin[..2].copy_from_slice(&ROLE_RESPONDER.to_be_bytes());
    // flags = 0: the application closes the connection when done.
    write_record(&mut out, BEGIN_REQUEST, &begin);
    write_stream(&mut out, PARAMS, p.as_bytes());
    write_stream(&mut out, STDIN, r.body);
    out
}

// ───────────────────────── decoding ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErr {
    BadVersion,
    BadRecord,
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct End {
    pub app_status: u32,
    /// 0 = request complete; 1 can't multiplex; 2 overloaded; 3 unknown role.
    pub protocol_status: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgiErr {
    /// No output at all.
    Empty,
    /// Header block not terminated / not parseable / bad `Status`.
    Malformed,
    /// Application ended the request abnormally (`protocol_status != 0`).
    Aborted(u8),
}

#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    end: Option<End>,
    seen: usize,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.stdout.clear();
        self.stderr.clear();
        self.end = None;
        self.seen = 0;
    }

    /// Bytes received so far (any byte means the application may have started working).
    pub fn bytes_seen(&self) -> usize {
        self.seen
    }

    pub fn is_done(&self) -> bool {
        self.end.is_some()
    }

    pub fn end(&self) -> Option<End> {
        self.end
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Feed bytes from the socket. `max_stdout` bounds the buffered CGI output.
    pub fn feed(&mut self, data: &[u8], max_stdout: usize) -> Result<(), DecodeErr> {
        self.seen = self.seen.saturating_add(data.len());
        if self.end.is_some() {
            return Ok(()); // trailing bytes after END_REQUEST are ignored
        }
        self.buf.extend_from_slice(data);
        let mut off = 0usize;
        let res = loop {
            let rest = &self.buf[off..];
            if rest.len() < 8 {
                break Ok(());
            }
            if rest[0] != VERSION {
                break Err(DecodeErr::BadVersion);
            }
            let ty = rest[1];
            let id = u16::from_be_bytes([rest[2], rest[3]]);
            let clen = u16::from_be_bytes([rest[4], rest[5]]) as usize;
            let plen = rest[6] as usize;
            let total = 8 + clen + plen;
            if rest.len() < total {
                break Ok(());
            }
            let content = &rest[8..8 + clen];
            off += total;
            if id != REQUEST_ID && id != 0 {
                continue; // not ours
            }
            match ty {
                STDOUT => {
                    if self.stdout.len() + content.len() > max_stdout {
                        break Err(DecodeErr::TooLarge);
                    }
                    self.stdout.extend_from_slice(content);
                }
                STDERR => {
                    let room = MAX_STDERR.saturating_sub(self.stderr.len());
                    self.stderr.extend_from_slice(&content[..content.len().min(room)]);
                }
                END_REQUEST => {
                    if clen < 8 {
                        break Err(DecodeErr::BadRecord);
                    }
                    self.end = Some(End {
                        app_status: u32::from_be_bytes([content[0], content[1], content[2], content[3]]),
                        protocol_status: content[4],
                    });
                    break Ok(());
                }
                _ => {} // GET_VALUES_RESULT, UNKNOWN_TYPE, ...: ignored
            }
        };
        self.buf.drain(..off);
        if self.end.is_some() {
            self.buf = Vec::new();
        }
        res
    }

    /// Convert the buffered CGI output into an `HTTP/1.1` response
    /// (`Content-Length` framed, `Connection: close`).
    pub fn take_http(&mut self, head_request: bool) -> Result<Vec<u8>, CgiErr> {
        let end = self.end.ok_or(CgiErr::Malformed)?;
        if end.protocol_status != 0 {
            return Err(CgiErr::Aborted(end.protocol_status));
        }
        let out = std::mem::take(&mut self.stdout);
        cgi_to_http(&out, head_request)
    }
}

/// Position of the blank line and the length of its terminator.
fn find_head_end(b: &[u8]) -> Option<(usize, usize)> {
    let limit = b.len().min(MAX_CGI_HEAD + 4);
    let mut i = 0;
    while i < limit {
        if b[i] == b'\n' {
            if i + 1 < b.len() && b[i + 1] == b'\n' {
                return Some((i + 1, 1));
            }
            if i + 2 < b.len() && b[i + 1] == b'\r' && b[i + 2] == b'\n' {
                return Some((i + 1, 2));
            }
        }
        i += 1;
    }
    None
}

fn is_token(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|&b| {
            b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
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
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        s if s < 200 => "Informational",
        s if s < 300 => "Success",
        s if s < 400 => "Redirection",
        s if s < 500 => "Client Error",
        _ => "Server Error",
    }
}

/// CGI response -> HTTP/1.1 response bytes.
pub fn cgi_to_http(out: &[u8], head_request: bool) -> Result<Vec<u8>, CgiErr> {
    if out.is_empty() {
        return Err(CgiErr::Empty);
    }
    let (head_len, term) = find_head_end(out).ok_or(CgiErr::Malformed)?;
    let head = &out[..head_len];
    let body = &out[head_len + term..];

    let mut status: Option<u16> = None;
    let mut status_reason: Option<String> = None;
    let mut has_location = false;
    let mut headers: Vec<u8> = Vec::with_capacity(head.len() + 64);

    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|&b| b == b':').ok_or(CgiErr::Malformed)?;
        let (name, rest) = (&line[..colon], &line[colon + 1..]);
        if !is_token(name) {
            return Err(CgiErr::Malformed);
        }
        let value = rest.trim_ascii();
        if value.contains(&0) || value.contains(&b'\r') {
            return Err(CgiErr::Malformed);
        }
        let lname = name.to_ascii_lowercase();
        match lname.as_slice() {
            b"status" => {
                let s = std::str::from_utf8(value).map_err(|_| CgiErr::Malformed)?;
                let (code, text) = s.split_once(' ').unwrap_or((s, ""));
                let code: u16 = code.parse().map_err(|_| CgiErr::Malformed)?;
                if !(100..=599).contains(&code) {
                    return Err(CgiErr::Malformed);
                }
                status = Some(code);
                let text = text.trim();
                if !text.is_empty() && text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
                    status_reason = Some(text.to_string());
                }
            }
            // Framing and connection management are ours, not the application's.
            b"content-length" | b"connection" | b"keep-alive" | b"transfer-encoding"
            | b"upgrade" | b"proxy-connection" | b"te" | b"trailer" => {}
            _ => {
                if lname == b"location" {
                    has_location = true;
                }
                headers.extend_from_slice(name);
                headers.extend_from_slice(b": ");
                headers.extend_from_slice(value);
                headers.extend_from_slice(b"\r\n");
            }
        }
    }

    let code = status.unwrap_or(if has_location { 302 } else { 200 });
    let text = status_reason.as_deref().unwrap_or_else(|| reason(code));
    let bodyless = code == 204 || code == 304 || code < 200;

    let mut resp = Vec::with_capacity(headers.len() + body.len() + 128);
    resp.extend_from_slice(format!("HTTP/1.1 {code} {text}\r\n").as_bytes());
    resp.extend_from_slice(&headers);
    if !bodyless {
        resp.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    resp.extend_from_slice(b"Connection: close\r\n\r\n");
    if !bodyless && !head_request {
        resp.extend_from_slice(body);
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(headers: &'a [(&'a [u8], &'a [u8])], body: &'a [u8]) -> CgiRequest<'a> {
        CgiRequest {
            method: "POST",
            request_uri: "/blog/index.php/x?a=1",
            query: "a=1",
            script_name: "/blog/index.php",
            path_info: "/x",
            document_root: "/var/www/html",
            host: Some(b"example.com:8443"),
            headers,
            body,
            remote_addr: Some("192.0.2.7".parse().unwrap()),
            https: true,
        }
    }

    /// Split a request into (type, content) records.
    fn records(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut v = Vec::new();
        while !b.is_empty() {
            assert_eq!(b[0], 1);
            let len = u16::from_be_bytes([b[4], b[5]]) as usize;
            let pad = b[6] as usize;
            v.push((b[1], b[8..8 + len].to_vec()));
            b = &b[8 + len + pad..];
        }
        v
    }

    fn params_of(wire: &[u8]) -> Vec<(String, String)> {
        let mut blob = Vec::new();
        for (t, c) in records(wire) {
            if t == PARAMS {
                blob.extend(c);
            }
        }
        decode_params(&blob)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (String::from_utf8(k).unwrap(), String::from_utf8_lossy(&v).into_owned()))
            .collect()
    }

    fn get<'a>(p: &'a [(String, String)], k: &str) -> Option<&'a str> {
        p.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn length_encoding_roundtrip() {
        let mut p = Params::new();
        let long = vec![b'x'; 300];
        p.add(b"A", b"");
        p.add(b"LONG", &long);
        p.add(&long, b"v");
        let d = decode_params(p.as_bytes()).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d[1].1.len(), 300);
        assert_eq!(d[2].0.len(), 300);
        assert!(decode_params(&[5, 1, b'a']).is_none(), "truncated");
        assert!(decode_params(&[0x80, 0, 0]).is_none());
    }

    #[test]
    fn request_structure() {
        let wire = build_request(&req(&[], b"hello"));
        let r = records(&wire);
        assert_eq!(r[0].0, BEGIN_REQUEST);
        assert_eq!(&r[0].1[..3], &[0, 1, 0], "responder, no keep-conn");
        assert!(r.iter().any(|(t, c)| *t == PARAMS && c.is_empty()), "empty PARAMS terminator");
        let stdin: Vec<_> = r.iter().filter(|(t, _)| *t == STDIN).collect();
        assert_eq!(stdin.len(), 2);
        assert_eq!(stdin[0].1, b"hello");
        assert!(stdin[1].1.is_empty());
    }

    #[test]
    fn large_body_is_chunked_without_padding() {
        let body = vec![7u8; MAX_CHUNK * 2 + 5];
        let wire = build_request(&req(&[], &body));
        let sizes: Vec<usize> =
            records(&wire).into_iter().filter(|(t, _)| *t == STDIN).map(|(_, c)| c.len()).collect();
        assert_eq!(sizes, [MAX_CHUNK, MAX_CHUNK, 5, 0]);
    }

    #[test]
    fn cgi_environment() {
        let hdrs: &[(&[u8], &[u8])] = &[
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"cookie", b"a=1"),
            (b"cookie", b"b=2"),
            (b"accept", b"x"),
            (b"accept", b"y"),
            (b"x-custom-thing", b"1"),
            (b"x_under", b"evil"),
            (b"proxy", b"http://evil"),
            (b"x-forwarded-for", b"6.6.6.6"),
            (b"connection", b"keep-alive"),
        ];
        let p = params_of(&build_request(&req(hdrs, b"a=b")));
        assert_eq!(get(&p, "SCRIPT_FILENAME"), Some("/var/www/html/blog/index.php"));
        assert_eq!(get(&p, "SCRIPT_NAME"), Some("/blog/index.php"));
        assert_eq!(get(&p, "PATH_INFO"), Some("/x"));
        assert_eq!(get(&p, "PATH_TRANSLATED"), Some("/var/www/html/x"));
        assert_eq!(get(&p, "REQUEST_URI"), Some("/blog/index.php/x?a=1"));
        assert_eq!(get(&p, "QUERY_STRING"), Some("a=1"));
        assert_eq!(get(&p, "DOCUMENT_ROOT"), Some("/var/www/html"));
        assert_eq!(get(&p, "REQUEST_METHOD"), Some("POST"));
        assert_eq!(get(&p, "HTTPS"), Some("on"));
        assert_eq!(get(&p, "SERVER_NAME"), Some("example.com"));
        assert_eq!(get(&p, "SERVER_PORT"), Some("8443"));
        assert_eq!(get(&p, "REMOTE_ADDR"), Some("192.0.2.7"));
        assert_eq!(get(&p, "CONTENT_LENGTH"), Some("3"));
        assert_eq!(get(&p, "CONTENT_TYPE"), Some("application/x-www-form-urlencoded"));
        assert_eq!(get(&p, "HTTP_HOST"), Some("example.com:8443"));
        assert_eq!(get(&p, "HTTP_COOKIE"), Some("a=1; b=2"));
        assert_eq!(get(&p, "HTTP_ACCEPT"), Some("x, y"));
        assert_eq!(get(&p, "HTTP_X_CUSTOM_THING"), Some("1"));
        for bad in ["HTTP_PROXY", "HTTP_X_UNDER", "HTTP_X_FORWARDED_FOR", "HTTP_CONNECTION", "HTTP_CONTENT_TYPE"] {
            assert!(get(&p, bad).is_none(), "{bad} must not be forwarded");
        }
    }

    #[test]
    fn no_path_info_and_plain_http() {
        let mut r = req(&[], b"");
        r.path_info = "";
        r.method = "GET";
        r.https = false;
        r.host = None;
        let p = params_of(&build_request(&r));
        assert!(get(&p, "PATH_INFO").is_none() && get(&p, "HTTPS").is_none());
        assert!(get(&p, "CONTENT_LENGTH").is_none());
        assert_eq!(get(&p, "SERVER_PORT"), Some("80"));
    }

    #[test]
    fn host_splitting() {
        assert_eq!(split_host(b"a.b"), ("a.b".into(), None));
        assert_eq!(split_host(b"a.b:81"), ("a.b".into(), Some(81)));
        assert_eq!(split_host(b"[::1]:9000"), ("[::1]".into(), Some(9000)));
        assert_eq!(split_host(b"[::1]"), ("[::1]".into(), None));
        assert_eq!(split_host(b"a.b:xx").1, None);
    }

    // ---- decoding -------------------------------------------------------

    fn rec(ty: u8, content: &[u8], pad: u8) -> Vec<u8> {
        let mut v = vec![1, ty, 0, 1];
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        v.push(pad);
        v.push(0);
        v.extend_from_slice(content);
        v.extend(std::iter::repeat(0).take(pad as usize));
        v
    }

    fn end_rec(proto: u8) -> Vec<u8> {
        rec(END_REQUEST, &[0, 0, 0, 0, proto, 0, 0, 0], 0)
    }

    #[test]
    fn decodes_split_records_with_padding() {
        let mut wire = rec(STDOUT, b"Content-type: text/html\r\n\r\nhel", 5);
        wire.extend(rec(STDOUT, b"lo", 0));
        wire.extend(rec(STDERR, b"PHP Warning: x", 2));
        wire.extend(rec(STDOUT, b"", 0));
        wire.extend(end_rec(0));
        // Feed one byte at a time: every split point must work.
        let mut d = Decoder::new();
        for b in &wire {
            d.feed(std::slice::from_ref(b), 1 << 20).unwrap();
        }
        assert!(d.is_done());
        assert_eq!(d.stderr(), b"PHP Warning: x");
        let http = d.take_http(false).unwrap();
        let s = String::from_utf8(http).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-type: text/html\r\n"));
        assert!(s.contains("Content-Length: 5\r\nConnection: close\r\n\r\nhello"));
    }

    #[test]
    fn status_location_and_cookies() {
        let out = b"Status: 404 Not Here\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Pingback: y\r\nContent-Length: 999\r\n\r\nnope";
        let s = String::from_utf8(cgi_to_http(out, false).unwrap()).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Here\r\n"));
        assert!(s.contains("Set-Cookie: a=1\r\n") && s.contains("Set-Cookie: b=2\r\n"));
        assert!(s.contains("Content-Length: 4\r\n") && !s.contains("999"));
        assert!(!s.contains("Status:"));

        let s = String::from_utf8(cgi_to_http(b"Location: /wp-admin/\r\n\r\n", false).unwrap()).unwrap();
        assert!(s.starts_with("HTTP/1.1 302 Found\r\n") && s.contains("Location: /wp-admin/"));

        let s = String::from_utf8(cgi_to_http(b"Status: 304\n\n", false).unwrap()).unwrap();
        assert!(s.starts_with("HTTP/1.1 304 Not Modified\r\n") && !s.contains("Content-Length"));

        // Bare-LF CGI output is accepted.
        let s = String::from_utf8(cgi_to_http(b"Content-Type: text/plain\n\nbody", false).unwrap()).unwrap();
        assert!(s.ends_with("\r\n\r\nbody"));
    }

    #[test]
    fn head_request_drops_body_keeps_length() {
        let s = String::from_utf8(cgi_to_http(b"Content-Type: text/plain\r\n\r\nabcdef", true).unwrap()).unwrap();
        assert!(s.contains("Content-Length: 6\r\n") && s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn hop_by_hop_headers_from_the_app_are_dropped() {
        let s = String::from_utf8(
            cgi_to_http(b"Transfer-Encoding: chunked\r\nConnection: upgrade\r\nUpgrade: x\r\nX-A: 1\r\n\r\nz", false).unwrap(),
        )
        .unwrap();
        assert!(!s.to_ascii_lowercase().contains("chunked") && !s.contains("Upgrade"));
        assert!(s.contains("X-A: 1\r\n") && s.contains("Connection: close"));
    }

    #[test]
    fn malformed_cgi_output() {
        assert_eq!(cgi_to_http(b"", false), Err(CgiErr::Empty));
        assert_eq!(cgi_to_http(b"no blank line", false), Err(CgiErr::Malformed));
        assert_eq!(cgi_to_http(b"Status: 99\r\n\r\n", false), Err(CgiErr::Malformed));
        assert_eq!(cgi_to_http(b"Status: abc\r\n\r\n", false), Err(CgiErr::Malformed));
        assert_eq!(cgi_to_http(b"bad header\r\n\r\n", false), Err(CgiErr::Malformed));
        assert_eq!(cgi_to_http(b"Bad Name: x\r\n\r\n", false), Err(CgiErr::Malformed));
        assert_eq!(cgi_to_http(b"X: a\0b\r\n\r\n", false), Err(CgiErr::Malformed));
        let big = vec![b'a'; MAX_CGI_HEAD + 100];
        assert_eq!(cgi_to_http(&big, false), Err(CgiErr::Malformed));
    }

    #[test]
    fn decoder_errors_and_limits() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[2, 6, 0, 1, 0, 0, 0, 0], 100), Err(DecodeErr::BadVersion));

        let mut d = Decoder::new();
        assert_eq!(d.feed(&rec(STDOUT, &[b'a'; 50], 0), 40), Err(DecodeErr::TooLarge));

        let mut d = Decoder::new();
        assert_eq!(d.feed(&rec(END_REQUEST, &[0, 0], 0), 40), Err(DecodeErr::BadRecord));

        let mut d = Decoder::new();
        d.feed(&rec(STDOUT, b"Content-type: x\r\n\r\n", 0), 100).unwrap();
        d.feed(&end_rec(2), 100).unwrap();
        assert_eq!(d.end().unwrap().protocol_status, 2);
        assert_eq!(d.take_http(false), Err(CgiErr::Aborted(2)));

        // Records for another request id and unknown types are ignored.
        let mut d = Decoder::new();
        let mut other = rec(STDOUT, b"junk", 0);
        other[3] = 9;
        d.feed(&other, 100).unwrap();
        d.feed(&rec(99, b"?", 0), 100).unwrap();
        d.feed(&rec(STDOUT, b"Content-type: x\r\n\r\nok", 0), 100).unwrap();
        d.feed(&end_rec(0), 100).unwrap();
        let s = String::from_utf8(d.take_http(false).unwrap()).unwrap();
        assert!(s.ends_with("\r\n\r\nok"));

        // Ending without END_REQUEST is not "done"; reset clears everything.
        let mut d = Decoder::new();
        d.feed(&rec(STDOUT, b"x", 0), 100).unwrap();
        assert!(!d.is_done() && d.bytes_seen() > 0);
        d.reset();
        assert_eq!(d.bytes_seen(), 0);
    }

    #[test]
    fn stderr_is_capped() {
        let mut d = Decoder::new();
        for _ in 0..10 {
            d.feed(&rec(STDERR, &[b'e'; 4000], 0), 100).unwrap();
        }
        assert_eq!(d.stderr().len(), MAX_STDERR);
    }

    #[test]
    fn mutation_fuzz_never_panics() {
        let mut wire = rec(STDOUT, b"Status: 200 OK\r\nSet-Cookie: a=b\r\n\r\nbody", 3);
        wire.extend(rec(STDERR, b"warn", 0));
        wire.extend(end_rec(0));
        let mut x = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let mut m = wire.clone();
            for _ in 0..(next() % 4 + 1) {
                let i = (next() as usize) % m.len();
                m[i] = next() as u8;
            }
            if next() % 4 == 0 {
                m.truncate((next() as usize) % m.len());
            }
            let mut d = Decoder::new();
            let cut = (next() as usize) % (m.len() + 1);
            let _ = d.feed(&m[..cut], 1 << 16);
            let _ = d.feed(&m[cut..], 1 << 16);
            let _ = d.take_http(next() % 2 == 0);
            let _ = cgi_to_http(&m, false);
            let _ = decode_params(&m);
        }
    }
}
