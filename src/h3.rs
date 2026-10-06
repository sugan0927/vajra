//! HTTP/3 (RFC 9114) framing and QPACK (RFC 9204), without any I/O.
//!
//! This module is deliberately independent of the QUIC stack: it turns bytes
//! read from QUIC streams into requests and responses into bytes, and nothing
//! else. [`crate::quic`] owns the transport.
//!
//! # QPACK scope
//!
//! Vajra advertises `QPACK_MAX_TABLE_CAPACITY = 0` and
//! `QPACK_BLOCKED_STREAMS = 0`, so the peer can never reference a dynamic
//! table entry. That makes QPACK stateless:
//!
//! * decoding handles the 99-entry static table and literals (with Huffman
//!   strings, decoded through the `hpack` crate: the Huffman code is shared
//!   with HPACK); any dynamic reference is `QPACK_DECOMPRESSION_FAILED`;
//! * encoding emits static-table indexes and plain literals (never Huffman,
//!   never the dynamic table), the same strategy as the HTTP/2 encoder.
//!
//! The cost is slightly larger header blocks than a full QPACK implementation
//! would produce; the benefit is no per-connection compression state and no
//! head-of-line blocking on the encoder stream.
//!
//! # Request handling
//!
//! A request is buffered completely (like HTTP/2 requests in this server): the
//! [`RequestStream`] assembler validates frames and field sections as they
//! arrive and yields an [`H3Request`] when the stream finishes.

// ───────────────────────── error codes (RFC 9114 §8.1, RFC 9204 §6) ─────────────────────────

pub const H3_NO_ERROR: u64 = 0x100;
pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
pub const H3_INTERNAL_ERROR: u64 = 0x102;
pub const H3_STREAM_CREATION_ERROR: u64 = 0x103;
pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
pub const H3_FRAME_UNEXPECTED: u64 = 0x105;
pub const H3_FRAME_ERROR: u64 = 0x106;
pub const H3_EXCESSIVE_LOAD: u64 = 0x107;
pub const H3_ID_ERROR: u64 = 0x108;
pub const H3_SETTINGS_ERROR: u64 = 0x109;
pub const H3_MISSING_SETTINGS: u64 = 0x10a;
pub const H3_REQUEST_REJECTED: u64 = 0x10b;
pub const H3_REQUEST_CANCELLED: u64 = 0x10c;
pub const H3_REQUEST_INCOMPLETE: u64 = 0x10d;
pub const H3_MESSAGE_ERROR: u64 = 0x10e;
pub const H3_CONNECT_ERROR: u64 = 0x10f;
pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;

// Frame types.
const F_DATA: u64 = 0x0;
const F_HEADERS: u64 = 0x1;
const F_CANCEL_PUSH: u64 = 0x3;
const F_SETTINGS: u64 = 0x4;
const F_PUSH_PROMISE: u64 = 0x5;
const F_GOAWAY: u64 = 0x7;
const F_MAX_PUSH_ID: u64 = 0xd;

// Settings identifiers.
const S_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const S_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const S_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Largest header section Vajra accepts (and advertises).
pub const MAX_FIELD_SECTION: usize = 16 * 1024;
const MAX_FIELDS: usize = 128;

/// HTTP/2 frame types that must never appear in HTTP/3 (RFC 9114 §7.2.8).
fn is_reserved_h2_frame(t: u64) -> bool {
    matches!(t, 0x2 | 0x6 | 0x8 | 0x9)
}

// ───────────────────────── variable-length integers (RFC 9000 §16) ─────────────────────────

/// Decode a QUIC varint. `None` if `b` is too short.
pub fn varint_decode(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &x in &b[1..len] {
        v = (v << 8) | x as u64;
    }
    Some((v, len))
}

/// Encode a QUIC varint (values are clamped to the 62-bit maximum).
pub fn varint_encode(v: u64, out: &mut Vec<u8>) {
    let v = v.min((1 << 62) - 1);
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

// ───────────────────────── frames ─────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum FrameParse<'a> {
    /// More bytes are needed for the type, length or payload.
    Incomplete,
    Frame { ty: u64, payload: &'a [u8], total: usize },
    /// The declared payload exceeds the caller's limit.
    TooLarge,
}

/// Parse one frame from the front of `buf`. Frames are only returned complete.
pub fn parse_frame(buf: &[u8], max_payload: usize) -> FrameParse<'_> {
    let Some((ty, n1)) = varint_decode(buf) else { return FrameParse::Incomplete };
    let Some((len, n2)) = varint_decode(&buf[n1..]) else { return FrameParse::Incomplete };
    if len > max_payload as u64 {
        return FrameParse::TooLarge;
    }
    let len = len as usize;
    let start = n1 + n2;
    if buf.len() - start < len {
        return FrameParse::Incomplete;
    }
    FrameParse::Frame { ty, payload: &buf[start..start + len], total: start + len }
}

fn frame(ty: u64, payload: &[u8], out: &mut Vec<u8>) {
    varint_encode(ty, out);
    varint_encode(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

/// The 1-to-9 byte header of a DATA frame carrying `len` bytes.
pub fn data_frame_header(len: u64, out: &mut Vec<u8>) {
    varint_encode(F_DATA, out);
    varint_encode(len, out);
}

/// A complete HEADERS frame for a response.
pub fn response_headers_frame(status: u16, headers: &[(Vec<u8>, Vec<u8>)], out: &mut Vec<u8>) {
    let mut block = Vec::with_capacity(128);
    qpack::encode_response(status, headers, &mut block);
    frame(F_HEADERS, &block, out);
}

pub fn goaway_frame(id: u64, out: &mut Vec<u8>) {
    let mut p = Vec::new();
    varint_encode(id, &mut p);
    frame(F_GOAWAY, &p, out);
}

/// Bytes to write on the server's control stream right after opening it:
/// the stream type (`0x00`) and a SETTINGS frame that disables the QPACK
/// dynamic table and bounds the field section size.
pub fn control_stream_preface() -> Vec<u8> {
    let mut p = Vec::new();
    for (id, v) in [
        (S_QPACK_MAX_TABLE_CAPACITY, 0),
        (S_MAX_FIELD_SECTION_SIZE, MAX_FIELD_SECTION as u64),
        (S_QPACK_BLOCKED_STREAMS, 0),
    ] {
        varint_encode(id, &mut p);
        varint_encode(v, &mut p);
    }
    let mut out = vec![0x00];
    frame(F_SETTINGS, &p, &mut out);
    out
}

// ───────────────────────── QPACK ─────────────────────────

pub mod qpack {
    //! Stateless QPACK (static table + literals); see the module docs above.

    use super::MAX_FIELDS;

    /// RFC 9204 Appendix A.
    pub const STATIC_TABLE: [(&str, &str); 99] = [
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"),
        ("access-control-request-method", "post"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin"),
    ];

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum QErr {
        /// Truncated or syntactically invalid field section.
        Malformed,
        /// The section references the dynamic table (never advertised).
        Dynamic,
        /// More fields or bytes than the configured limits.
        TooLarge,
    }

    // ---- prefix integers (RFC 7541 §5.1, identical in QPACK) ----

    pub fn int_encode(mut v: u64, prefix: u8, flags: u8, out: &mut Vec<u8>) {
        let max = (1u64 << prefix) - 1;
        if v < max {
            out.push(flags | v as u8);
            return;
        }
        out.push(flags | max as u8);
        v -= max;
        while v >= 128 {
            out.push((v & 127) as u8 | 128);
            v >>= 7;
        }
        out.push(v as u8);
    }

    /// Decode a prefix integer whose first byte is `b[*pos]`.
    pub fn int_decode(b: &[u8], pos: &mut usize, prefix: u8) -> Option<u64> {
        let first = *b.get(*pos)?;
        *pos += 1;
        let max = (1u64 << prefix) - 1;
        let mut v = (first as u64) & max;
        if v < max {
            return Some(v);
        }
        let mut shift = 0u32;
        loop {
            let byte = *b.get(*pos)?;
            *pos += 1;
            if shift > 56 {
                return None;
            }
            v = v.checked_add(((byte & 0x7f) as u64) << shift)?;
            if byte & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
        }
    }

    pub struct Decoder {
        huff: hpack::Decoder<'static>,
        max_bytes: usize,
    }

    type Field = (Vec<u8>, Vec<u8>);

    impl Decoder {
        pub fn new(max_bytes: usize) -> Self {
            Self { huff: hpack::Decoder::new(), max_bytes }
        }

        /// Huffman-decode `data` by wrapping it in an HPACK literal and letting
        /// the `hpack` crate do the work (both formats share one Huffman code).
        fn huffman(&mut self, data: &[u8]) -> Result<Vec<u8>, QErr> {
            let mut blk = Vec::with_capacity(data.len() + 6);
            blk.extend_from_slice(&[0x00, 0x01, b'a']); // literal, new name "a"
            int_encode(data.len() as u64, 7, 0x80, &mut blk); // H=1 value
            blk.extend_from_slice(data);
            let mut fields = self.huff.decode(&blk).map_err(|_| QErr::Malformed)?;
            match (fields.pop(), fields.is_empty()) {
                (Some((_, v)), true) => Ok(v),
                _ => Err(QErr::Malformed),
            }
        }

        /// A string literal whose first byte holds the Huffman flag at
        /// `h_mask` followed by a `prefix`-bit length.
        fn string(&mut self, b: &[u8], pos: &mut usize, h_mask: u8, prefix: u8) -> Result<Vec<u8>, QErr> {
            let first = *b.get(*pos).ok_or(QErr::Malformed)?;
            let huff = first & h_mask != 0;
            let len = int_decode(b, pos, prefix).ok_or(QErr::Malformed)?;
            if len > self.max_bytes as u64 {
                return Err(QErr::TooLarge);
            }
            let len = len as usize;
            let end = pos.checked_add(len).ok_or(QErr::Malformed)?;
            let raw = b.get(*pos..end).ok_or(QErr::Malformed)?;
            *pos = end;
            if huff {
                let v = self.huffman(raw)?;
                if v.len() > self.max_bytes {
                    return Err(QErr::TooLarge);
                }
                Ok(v)
            } else {
                Ok(raw.to_vec())
            }
        }

        /// Decode one encoded field section.
        pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Field>, QErr> {
            let mut pos = 0;
            let ric = int_decode(block, &mut pos, 8).ok_or(QErr::Malformed)?;
            if ric != 0 {
                return Err(QErr::Dynamic);
            }
            let _delta_base = int_decode(block, &mut pos, 7).ok_or(QErr::Malformed)?;

            let mut out: Vec<Field> = Vec::new();
            let mut total = 0usize;
            while pos < block.len() {
                let b = block[pos];
                let (name, value) = if b & 0x80 != 0 {
                    // Indexed field line: 1 T index(6)
                    if b & 0x40 == 0 {
                        return Err(QErr::Dynamic);
                    }
                    let i = int_decode(block, &mut pos, 6).ok_or(QErr::Malformed)? as usize;
                    let (n, v) = STATIC_TABLE.get(i).ok_or(QErr::Malformed)?;
                    (n.as_bytes().to_vec(), v.as_bytes().to_vec())
                } else if b & 0xC0 == 0x40 {
                    // Literal with name reference: 01 N T index(4), then value
                    if b & 0x10 == 0 {
                        return Err(QErr::Dynamic);
                    }
                    let i = int_decode(block, &mut pos, 4).ok_or(QErr::Malformed)? as usize;
                    let (n, _) = STATIC_TABLE.get(i).ok_or(QErr::Malformed)?;
                    let v = self.string(block, &mut pos, 0x80, 7)?;
                    (n.as_bytes().to_vec(), v)
                } else if b & 0xE0 == 0x20 {
                    // Literal with literal name: 001 N H namelen(3), name, value
                    let n = self.string(block, &mut pos, 0x08, 3)?;
                    let v = self.string(block, &mut pos, 0x80, 7)?;
                    (n, v)
                } else {
                    // 0001xxxx indexed post-base, 0000xxxx literal post-base name reference
                    return Err(QErr::Dynamic);
                };
                total += name.len() + value.len() + 32;
                if total > self.max_bytes || out.len() >= MAX_FIELDS {
                    return Err(QErr::TooLarge);
                }
                out.push((name, value));
            }
            Ok(out)
        }
    }

    fn find(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let mut name_only = None;
        for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
            if n.as_bytes() == name {
                if v.as_bytes() == value {
                    return (Some(i), Some(i));
                }
                name_only.get_or_insert(i);
            }
        }
        (None, name_only)
    }

    fn put_value(value: &[u8], out: &mut Vec<u8>) {
        int_encode(value.len() as u64, 7, 0x00, out);
        out.extend_from_slice(value);
    }

    /// Encode one field (names must already be lowercase).
    pub fn encode_field(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
        let sensitive = matches!(name, b"set-cookie" | b"authorization" | b"cookie");
        let (full, name_idx) = find(name, value);
        if let (Some(i), false) = (full, sensitive) {
            int_encode(i as u64, 6, 0xC0, out); // indexed, static
        } else if let Some(i) = name_idx {
            // literal with static name reference; N=1 for sensitive values
            int_encode(i as u64, 4, if sensitive { 0x70 } else { 0x50 }, out);
            put_value(value, out);
        } else {
            int_encode(name.len() as u64, 3, if sensitive { 0x30 } else { 0x20 }, out);
            out.extend_from_slice(name);
            put_value(value, out);
        }
    }

    /// A response field section: prefix (RIC 0, base 0), `:status`, headers.
    pub fn encode_response(status: u16, headers: &[(Vec<u8>, Vec<u8>)], out: &mut Vec<u8>) {
        out.extend_from_slice(&[0x00, 0x00]);
        encode_field(b":status", status.to_string().as_bytes(), out);
        for (n, v) in headers {
            encode_field(n, v, out);
        }
    }

    /// A request field section (used by tests and tools).
    pub fn encode_request(
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(&str, &str)],
        out: &mut Vec<u8>,
    ) {
        out.extend_from_slice(&[0x00, 0x00]);
        encode_field(b":method", method.as_bytes(), out);
        encode_field(b":scheme", scheme.as_bytes(), out);
        encode_field(b":authority", authority.as_bytes(), out);
        encode_field(b":path", path.as_bytes(), out);
        for (n, v) in headers {
            encode_field(n.as_bytes(), v.as_bytes(), out);
        }
    }
}

/// A complete HEADERS frame for a request (client side; tests and tools).
pub fn request_headers_frame(
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(&str, &str)],
    out: &mut Vec<u8>,
) {
    let mut block = Vec::new();
    qpack::encode_request(method, "https", authority, path, headers, &mut block);
    frame(F_HEADERS, &block, out);
}

pub fn data_frame(payload: &[u8], out: &mut Vec<u8>) {
    frame(F_DATA, payload, out);
}

// ───────────────────────── request assembly ─────────────────────────

/// How an HTTP/3 error must be reported.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum H3Err {
    /// Close the whole connection with this application error code.
    Conn(u64),
    /// Reset only this stream with this application error code.
    Stream(u64),
    /// The request body or header section exceeded a limit: answer 413/431.
    TooLarge,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct H3Request {
    pub method: String,
    /// Path plus optional `?query`.
    pub path: String,
    pub authority: Vec<u8>,
    /// Regular headers, lowercase names; cookies are merged.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

/// Validate a decoded field section as a request header block (RFC 9114 §4.3.1, 4.2).
fn build_request(fields: Vec<(Vec<u8>, Vec<u8>)>) -> Result<H3Request, H3Err> {
    let bad = H3Err::Stream(H3_MESSAGE_ERROR);
    let mut req = H3Request::default();
    let (mut method, mut scheme, mut path, mut authority) = (None, None, None, None);
    let mut seen_regular = false;
    let mut cookie: Option<Vec<u8>> = None;
    let mut host: Option<Vec<u8>> = None;

    for (name, value) in fields {
        if value.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(bad);
        }
        if name.first() == Some(&b':') {
            if seen_regular {
                return Err(bad);
            }
            let slot = match name.as_slice() {
                b":method" => &mut method,
                b":scheme" => &mut scheme,
                b":path" => &mut path,
                b":authority" => &mut authority,
                _ => return Err(bad),
            };
            if slot.is_some() {
                return Err(bad);
            }
            *slot = Some(value);
            continue;
        }
        seen_regular = true;
        if name.is_empty() || name.iter().any(|b| b.is_ascii_uppercase() || *b <= b' ' || *b == b':') {
            return Err(bad);
        }
        match name.as_slice() {
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade" => {
                return Err(bad)
            }
            b"te" if value != b"trailers" => return Err(bad),
            b"cookie" => match &mut cookie {
                Some(c) => {
                    c.extend_from_slice(b"; ");
                    c.extend_from_slice(&value);
                }
                None => cookie = Some(value),
            },
            b"host" => host = Some(value),
            _ => req.headers.push((name, value)),
        }
    }

    let method = String::from_utf8(method.ok_or(bad)?).map_err(|_| bad)?;
    if method == "CONNECT" {
        return Err(H3Err::Stream(H3_CONNECT_ERROR)); // tunnelling is not supported
    }
    if !is_token(&method) {
        return Err(bad);
    }
    let scheme = scheme.ok_or(bad)?;
    if scheme != b"https" && scheme != b"http" {
        return Err(bad);
    }
    let path = String::from_utf8(path.ok_or(bad)?).map_err(|_| bad)?;
    if !(path.starts_with('/') || (path == "*" && method == "OPTIONS")) {
        return Err(bad);
    }
    req.method = method;
    req.path = path;
    req.authority = authority.or(host).unwrap_or_default();
    if let Some(c) = cookie {
        req.headers.push((b"cookie".to_vec(), c));
    }
    Ok(req)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum RState {
    /// Waiting for the first HEADERS frame.
    Start,
    /// HEADERS received; DATA and trailers allowed.
    Body,
    /// Trailers received; only unknown frames may follow.
    Trailers,
}

/// Incremental parser for one request (bidirectional client) stream.
pub struct RequestStream {
    buf: Vec<u8>,
    state: RState,
    req: Option<H3Request>,
    body: Vec<u8>,
    max_body: usize,
}

impl RequestStream {
    pub fn new(max_body: usize) -> Self {
        Self { buf: Vec::new(), state: RState::Start, req: None, body: Vec::new(), max_body }
    }

    /// Feed bytes read from the stream (`fin` = the peer finished the stream).
    /// `Ok(Some(_))` is returned exactly once, when the message is complete.
    pub fn feed(
        &mut self,
        data: &[u8],
        fin: bool,
        dec: &mut qpack::Decoder,
    ) -> Result<Option<H3Request>, H3Err> {
        self.buf.extend_from_slice(data);
        let max_frame = self.max_body.max(MAX_FIELD_SECTION) + 16;
        // Take the buffer so frame payloads can borrow it while `self` is updated.
        let buf = std::mem::take(&mut self.buf);
        let mut pos = 0;
        let result = loop {
            match parse_frame(&buf[pos..], max_frame) {
                FrameParse::Incomplete => break Ok(()),
                FrameParse::TooLarge => break Err(H3Err::TooLarge),
                FrameParse::Frame { ty, payload, total } => {
                    if let Err(e) = self.on_frame(ty, payload, dec) {
                        break Err(e);
                    }
                    pos += total;
                }
            }
        };
        self.buf = buf;
        self.buf.drain(..pos);
        result?;

        if !fin {
            return Ok(None);
        }
        if !self.buf.is_empty() {
            return Err(H3Err::Conn(H3_FRAME_ERROR)); // truncated frame at end of stream
        }
        let Some(mut req) = self.req.take() else {
            return Err(H3Err::Stream(H3_REQUEST_INCOMPLETE));
        };
        if let Some((_, v)) = req.headers.iter().find(|(n, _)| n == b"content-length") {
            let declared = std::str::from_utf8(v).ok().and_then(|s| s.trim().parse::<usize>().ok());
            if declared != Some(self.body.len()) {
                return Err(H3Err::Stream(H3_MESSAGE_ERROR));
            }
        }
        req.body = std::mem::take(&mut self.body);
        Ok(Some(req))
    }

    fn on_frame(&mut self, ty: u64, payload: &[u8], dec: &mut qpack::Decoder) -> Result<(), H3Err> {
        match ty {
            F_DATA => {
                if self.state != RState::Body {
                    return Err(H3Err::Conn(H3_FRAME_UNEXPECTED));
                }
                if self.body.len() + payload.len() > self.max_body {
                    return Err(H3Err::TooLarge);
                }
                self.body.extend_from_slice(payload);
                Ok(())
            }
            F_HEADERS => {
                if payload.len() > MAX_FIELD_SECTION {
                    return Err(H3Err::TooLarge);
                }
                let fields = dec.decode(payload).map_err(|e| match e {
                    qpack::QErr::TooLarge => H3Err::TooLarge,
                    _ => H3Err::Conn(QPACK_DECOMPRESSION_FAILED),
                })?;
                match self.state {
                    RState::Start => {
                        self.req = Some(build_request(fields)?);
                        self.state = RState::Body;
                        Ok(())
                    }
                    RState::Body => {
                        // Trailers: validated by the decoder, otherwise ignored.
                        self.state = RState::Trailers;
                        Ok(())
                    }
                    RState::Trailers => Err(H3Err::Conn(H3_FRAME_UNEXPECTED)),
                }
            }
            F_CANCEL_PUSH | F_SETTINGS | F_PUSH_PROMISE | F_GOAWAY | F_MAX_PUSH_ID => {
                Err(H3Err::Conn(H3_FRAME_UNEXPECTED))
            }
            t if is_reserved_h2_frame(t) => Err(H3Err::Conn(H3_FRAME_UNEXPECTED)),
            _ => Ok(()), // unknown and GREASE frames are ignored
        }
    }
}

// ───────────────────────── unidirectional streams ─────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UniKind {
    Control,
    QpackEncoder,
    QpackDecoder,
    /// Unknown stream type: ignore its contents.
    Ignored,
}

/// Parser for a client-initiated unidirectional stream.
pub struct UniStream {
    buf: Vec<u8>,
    kind: Option<UniKind>,
    got_settings: bool,
    /// Bytes consumed on a QPACK stream (they carry nothing we need).
    discarded: usize,
}

const MAX_QPACK_STREAM_BYTES: usize = 16 * 1024;

impl Default for UniStream {
    fn default() -> Self {
        Self::new()
    }
}

impl UniStream {
    pub fn new() -> Self {
        Self { buf: Vec::new(), kind: None, got_settings: false, discarded: 0 }
    }

    pub fn kind(&self) -> Option<UniKind> {
        self.kind
    }

    /// `Err(code)` is a connection error to close with.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), u64> {
        if self.kind == Some(UniKind::Ignored) {
            return Ok(());
        }
        self.buf.extend_from_slice(data);

        if self.kind.is_none() {
            let Some((t, n)) = varint_decode(&self.buf) else { return Ok(()) };
            self.buf.drain(..n);
            self.kind = Some(match t {
                0x00 => UniKind::Control,
                0x01 => return Err(H3_STREAM_CREATION_ERROR), // clients may not push
                0x02 => UniKind::QpackEncoder,
                0x03 => UniKind::QpackDecoder,
                _ => {
                    self.buf = Vec::new();
                    UniKind::Ignored
                }
            });
        }

        match self.kind {
            Some(UniKind::QpackEncoder) | Some(UniKind::QpackDecoder) => {
                self.discarded += self.buf.len();
                self.buf.clear();
                if self.discarded > MAX_QPACK_STREAM_BYTES {
                    return Err(H3_EXCESSIVE_LOAD);
                }
                Ok(())
            }
            Some(UniKind::Control) => self.control_frames(),
            _ => Ok(()),
        }
    }

    fn control_frames(&mut self) -> Result<(), u64> {
        let buf = std::mem::take(&mut self.buf);
        let mut pos = 0;
        let r = loop {
            match parse_frame(&buf[pos..], MAX_FIELD_SECTION) {
                FrameParse::Incomplete => break Ok(()),
                FrameParse::TooLarge => break Err(H3_EXCESSIVE_LOAD),
                FrameParse::Frame { ty, payload, total } => {
                    if !self.got_settings && ty != F_SETTINGS {
                        break Err(H3_MISSING_SETTINGS);
                    }
                    let r = match ty {
                        F_SETTINGS => {
                            if self.got_settings {
                                Err(H3_FRAME_UNEXPECTED)
                            } else {
                                self.got_settings = true;
                                check_settings(payload)
                            }
                        }
                        F_GOAWAY | F_MAX_PUSH_ID | F_CANCEL_PUSH => {
                            // Single varint payloads; contents are not needed.
                            match varint_decode(payload) {
                                Some((_, n)) if n == payload.len() => Ok(()),
                                _ => Err(H3_FRAME_ERROR),
                            }
                        }
                        F_DATA | F_HEADERS | F_PUSH_PROMISE => Err(H3_FRAME_UNEXPECTED),
                        t if is_reserved_h2_frame(t) => Err(H3_FRAME_UNEXPECTED),
                        _ => Ok(()),
                    };
                    if let Err(e) = r {
                        break Err(e);
                    }
                    pos += total;
                }
            }
        };
        self.buf = buf;
        self.buf.drain(..pos);
        r
    }
}

fn check_settings(mut p: &[u8]) -> Result<(), u64> {
    let mut seen: Vec<u64> = Vec::new();
    while !p.is_empty() {
        let (id, n) = varint_decode(p).ok_or(H3_FRAME_ERROR)?;
        p = &p[n..];
        let (_, n) = varint_decode(p).ok_or(H3_FRAME_ERROR)?;
        p = &p[n..];
        if matches!(id, 0x0 | 0x2 | 0x3 | 0x4 | 0x5) {
            return Err(H3_SETTINGS_ERROR); // HTTP/2 settings reused as HTTP/3 identifiers
        }
        if seen.contains(&id) {
            return Err(H3_SETTINGS_ERROR);
        }
        seen.push(id);
    }
    Ok(())
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> qpack::Decoder {
        qpack::Decoder::new(MAX_FIELD_SECTION)
    }

    #[test]
    fn varint_roundtrip_and_boundaries() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, (1 << 62) - 1] {
            let mut b = Vec::new();
            varint_encode(v, &mut b);
            assert_eq!(varint_decode(&b), Some((v, b.len())), "{v}");
        }
        // RFC 9000 Appendix A examples.
        assert_eq!(varint_decode(&[0x25]), Some((37, 1)));
        assert_eq!(varint_decode(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(varint_decode(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(
            varint_decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(varint_decode(&[0x7b]), None, "truncated");
        assert_eq!(varint_decode(&[]), None);
    }

    #[test]
    fn prefix_integers_match_rfc7541_examples() {
        let mut o = Vec::new();
        qpack::int_encode(10, 5, 0, &mut o);
        assert_eq!(o, [0x0a]);
        o.clear();
        qpack::int_encode(1337, 5, 0, &mut o);
        assert_eq!(o, [0x1f, 0x9a, 0x0a]);
        let mut p = 0;
        assert_eq!(qpack::int_decode(&o, &mut p, 5), Some(1337));
        assert_eq!(p, 3);
        // Overlong continuation must not overflow.
        let evil = [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        let mut p = 0;
        assert_eq!(qpack::int_decode(&evil, &mut p, 5), None);
    }

    #[test]
    fn static_table_pins() {
        use qpack::STATIC_TABLE as T;
        assert_eq!(T.len(), 99);
        assert_eq!(T[0], (":authority", ""));
        assert_eq!(T[1], (":path", "/"));
        assert_eq!(T[4], ("content-length", "0"));
        assert_eq!(T[15], (":method", "CONNECT"));
        assert_eq!(T[17], (":method", "GET"));
        assert_eq!(T[20], (":method", "POST"));
        assert_eq!(T[23], (":scheme", "https"));
        assert_eq!(T[25], (":status", "200"));
        assert_eq!(T[27], (":status", "404"));
        assert_eq!(T[31], ("accept-encoding", "gzip, deflate, br"));
        assert_eq!(T[52], ("content-type", "text/html; charset=utf-8"));
        assert_eq!(T[63], (":status", "100"));
        assert_eq!(T[71], (":status", "500"));
        assert_eq!(T[95], ("user-agent", ""));
        assert_eq!(T[98], ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn request_roundtrip() {
        let mut wire = Vec::new();
        request_headers_frame(
            "GET",
            "example.com",
            "/a/b?x=1",
            &[("accept", "*/*"), ("user-agent", "t/1"), ("x-custom", "v"), ("cookie", "a=1"), ("cookie", "b=2")],
            &mut wire,
        );
        let mut rs = RequestStream::new(1 << 20);
        let req = rs.feed(&wire, true, &mut dec()).unwrap().expect("complete");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/a/b?x=1");
        assert_eq!(req.authority, b"example.com");
        assert!(req.headers.contains(&(b"accept".to_vec(), b"*/*".to_vec())));
        assert!(req.headers.contains(&(b"cookie".to_vec(), b"a=1; b=2".to_vec())));
        assert!(req.body.is_empty());
    }

    #[test]
    fn request_with_body_arriving_in_pieces() {
        let mut wire = Vec::new();
        request_headers_frame("POST", "h", "/up", &[("content-length", "10")], &mut wire);
        data_frame(b"hello", &mut wire);
        data_frame(b"world", &mut wire);
        let mut rs = RequestStream::new(1 << 20);
        let mut d = dec();
        let mut got = None;
        for (i, chunk) in wire.chunks(3).enumerate() {
            let last = (i + 1) * 3 >= wire.len();
            if let Some(r) = rs.feed(chunk, last, &mut d).unwrap() {
                got = Some(r);
            }
        }
        let r = got.expect("request");
        assert_eq!(r.body, b"helloworld");
    }

    #[test]
    fn content_length_mismatch_is_a_message_error() {
        let mut wire = Vec::new();
        request_headers_frame("POST", "h", "/", &[("content-length", "3")], &mut wire);
        data_frame(b"toolong", &mut wire);
        let e = RequestStream::new(1 << 20).feed(&wire, true, &mut dec()).unwrap_err();
        assert_eq!(e, H3Err::Stream(H3_MESSAGE_ERROR));
    }

    #[test]
    fn body_limit_is_enforced() {
        let mut wire = Vec::new();
        request_headers_frame("POST", "h", "/", &[], &mut wire);
        data_frame(&vec![0u8; 2000], &mut wire);
        let e = RequestStream::new(1000).feed(&wire, true, &mut dec()).unwrap_err();
        assert_eq!(e, H3Err::TooLarge);
    }

    #[test]
    fn frame_ordering_rules() {
        // DATA before HEADERS.
        let mut w = Vec::new();
        data_frame(b"x", &mut w);
        assert_eq!(
            RequestStream::new(100).feed(&w, true, &mut dec()).unwrap_err(),
            H3Err::Conn(H3_FRAME_UNEXPECTED)
        );
        // SETTINGS on a request stream.
        let mut w = Vec::new();
        frame(F_SETTINGS, &[], &mut w);
        assert_eq!(
            RequestStream::new(100).feed(&w, false, &mut dec()).unwrap_err(),
            H3Err::Conn(H3_FRAME_UNEXPECTED)
        );
        // Reserved HTTP/2 frame types.
        for t in [0x2u64, 0x6, 0x8, 0x9] {
            let mut w = Vec::new();
            frame(t, &[], &mut w);
            assert_eq!(
                RequestStream::new(100).feed(&w, false, &mut dec()).unwrap_err(),
                H3Err::Conn(H3_FRAME_UNEXPECTED)
            );
        }
        // Unknown (GREASE) frames are skipped.
        let mut w = Vec::new();
        frame(0x21, b"grease", &mut w);
        request_headers_frame("GET", "h", "/", &[], &mut w);
        frame(0x40, b"more", &mut w);
        assert!(RequestStream::new(100).feed(&w, true, &mut dec()).unwrap().is_some());
        // Stream ended before any HEADERS.
        assert_eq!(
            RequestStream::new(100).feed(&[], true, &mut dec()).unwrap_err(),
            H3Err::Stream(H3_REQUEST_INCOMPLETE)
        );
        // Truncated frame at FIN.
        let mut w = Vec::new();
        request_headers_frame("GET", "h", "/", &[], &mut w);
        w.truncate(w.len() - 1);
        assert_eq!(
            RequestStream::new(100).feed(&w, true, &mut dec()).unwrap_err(),
            H3Err::Conn(H3_FRAME_ERROR)
        );
    }

    #[test]
    fn trailers_are_accepted_once() {
        let mut w = Vec::new();
        request_headers_frame("POST", "h", "/", &[], &mut w);
        data_frame(b"abc", &mut w);
        let mut tr = Vec::new();
        qpack::encode_response(200, &[(b"x-trailer".to_vec(), b"1".to_vec())], &mut tr);
        frame(F_HEADERS, &tr, &mut w);
        assert!(RequestStream::new(100).feed(&w, true, &mut dec()).unwrap().is_some());
        frame(F_HEADERS, &tr, &mut w); // a third field section
        assert_eq!(
            RequestStream::new(100).feed(&w, true, &mut dec()).unwrap_err(),
            H3Err::Conn(H3_FRAME_UNEXPECTED)
        );
    }

    fn block(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut b = vec![0x00, 0x00];
        f(&mut b);
        b
    }

    #[test]
    fn header_validation() {
        let run = |fields: Vec<(&str, &str)>| {
            let b = block(|b| {
                for (n, v) in &fields {
                    qpack::encode_field(n.as_bytes(), v.as_bytes(), b);
                }
            });
            let mut w = Vec::new();
            frame(F_HEADERS, &b, &mut w);
            RequestStream::new(100).feed(&w, true, &mut dec())
        };
        let ok = vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")];
        assert!(run(ok.clone()).unwrap().is_some());

        let msg = Err(H3Err::Stream(H3_MESSAGE_ERROR));
        // Missing pseudo-headers.
        for skip in 0..4 {
            let f: Vec<_> = ok.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, x)| *x).collect();
            if skip == 3 {
                assert!(run(f).unwrap().is_some(), "authority may be absent");
            } else {
                assert_eq!(run(f), msg, "missing pseudo {skip}");
            }
        }
        // Pseudo-header after a regular one; duplicate; unknown; uppercase; connection-specific.
        let mut f = ok.clone();
        f.insert(1, ("accept", "*/*"));
        assert_eq!(run(f), msg);
        let mut f = ok.clone();
        f.push((":path", "/again"));
        assert_eq!(run(f), msg);
        let mut f = ok.clone();
        f.push((":bogus", "x"));
        assert_eq!(run(f), msg);
        let mut f = ok.clone();
        f.push(("X-Upper", "x"));
        assert_eq!(run(f), msg);
        for h in ["connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"] {
            let mut f = ok.clone();
            f.push((h, "x"));
            assert_eq!(run(f), msg, "{h}");
        }
        let mut f = ok.clone();
        f.push(("te", "trailers"));
        assert!(run(f).unwrap().is_some());
        let mut f = ok.clone();
        f.push(("te", "gzip"));
        assert_eq!(run(f), msg);
        // Control characters in values; bad path; bad method; CONNECT.
        let mut f = ok.clone();
        f.push(("x", "a\r\nb: c"));
        assert_eq!(run(f), msg);
        let mut f = ok.clone();
        f[2] = (":path", "no-slash");
        assert_eq!(run(f), msg);
        let mut f = ok.clone();
        f[0] = (":method", "G ET");
        assert_eq!(run(f), msg);
        let mut f = ok.clone();
        f[0] = (":method", "CONNECT");
        assert_eq!(run(f), Err(H3Err::Stream(H3_CONNECT_ERROR)));
        // :scheme must be http(s).
        let mut f = ok.clone();
        f[1] = (":scheme", "ftp");
        assert_eq!(run(f), msg);
        // Host substitutes for :authority.
        let r = run(vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), ("host", "h.example")])
            .unwrap()
            .unwrap();
        assert_eq!(r.authority, b"h.example");
    }

    #[test]
    fn dynamic_table_references_are_rejected() {
        let mut w = Vec::new();
        // Required Insert Count = 1.
        frame(F_HEADERS, &[0x01, 0x00, 0xd0], &mut w);
        assert_eq!(
            RequestStream::new(100).feed(&w, true, &mut dec()).unwrap_err(),
            H3Err::Conn(QPACK_DECOMPRESSION_FAILED)
        );
        // Indexed field line with T=0 (dynamic) despite RIC=0.
        let mut d = dec();
        assert_eq!(d.decode(&[0x00, 0x00, 0x80]), Err(qpack::QErr::Dynamic));
        // Post-base indexed and post-base literal.
        assert_eq!(d.decode(&[0x00, 0x00, 0x10]), Err(qpack::QErr::Dynamic));
        assert_eq!(d.decode(&[0x00, 0x00, 0x00]), Err(qpack::QErr::Dynamic));
        // Literal with dynamic name reference (T=0).
        assert_eq!(d.decode(&[0x00, 0x00, 0x40, 0x00]), Err(qpack::QErr::Dynamic));
    }

    #[test]
    fn malformed_field_sections_never_panic() {
        let mut d = dec();
        // Truncated values/names, out-of-range index, oversized lengths.
        assert_eq!(d.decode(&[]), Err(qpack::QErr::Malformed));
        assert_eq!(d.decode(&[0x00]), Err(qpack::QErr::Malformed));
        assert_eq!(d.decode(&[0x00, 0x00, 0xff, 0x7f]), Err(qpack::QErr::Malformed)); // idx 62+127 > 98
        assert_eq!(d.decode(&[0x00, 0x00, 0x51, 0x05, b'a']), Err(qpack::QErr::Malformed));
        assert_eq!(d.decode(&[0x00, 0x00, 0x27, b'a']), Err(qpack::QErr::Malformed));
        assert_eq!(d.decode(&[0x00, 0x00, 0x51, 0x7f, 0xff, 0xff, 0xff, 0x7f]), Err(qpack::QErr::TooLarge));
        // Exhaustive 1- and 2-byte tails after a valid prefix.
        for a in 0..=255u8 {
            let _ = d.decode(&[0, 0, a]);
            for b in (0..=255u8).step_by(5) {
                let _ = d.decode(&[0, 0, a, b]);
            }
        }
    }

    #[test]
    fn field_count_limit() {
        let b = block(|b| {
            for _ in 0..(MAX_FIELDS + 1) {
                qpack::encode_field(b"x", b"1", b);
            }
        });
        assert_eq!(qpack::Decoder::new(1 << 20).decode(&b), Err(qpack::QErr::TooLarge));
    }

    #[test]
    fn response_encoding_uses_static_entries() {
        let mut b = Vec::new();
        qpack::encode_response(
            200,
            &[
                (b"content-type".to_vec(), b"text/html; charset=utf-8".to_vec()),
                (b"server".to_vec(), b"vajra".to_vec()),
                (b"x-own".to_vec(), b"1".to_vec()),
                (b"set-cookie".to_vec(), b"a=b".to_vec()),
            ],
            &mut b,
        );
        // prefix, then :status 200 = static 25 -> 0xC0|25 = 0xD9; content-type html = 52 -> 0xF4.
        assert_eq!(&b[..4], [0x00, 0x00, 0xd9, 0xf4]);
        // Everything decodes back (the decoder is generic over field names).
        let f = qpack::Decoder::new(4096).decode(&b).unwrap();
        assert_eq!(f[0], (b":status".to_vec(), b"200".to_vec()));
        assert_eq!(f[2], (b"server".to_vec(), b"vajra".to_vec()));
        assert_eq!(f[3], (b"x-own".to_vec(), b"1".to_vec()));
        assert_eq!(f[4], (b"set-cookie".to_vec(), b"a=b".to_vec()));
        // set-cookie is literal with N=1 (never index) via static name ref 14: 0x70|14 = 0x7e.
        assert!(b.contains(&0x7e));
        // Uncommon status codes use a literal with the `:status` name reference.
        let mut b = Vec::new();
        qpack::encode_response(418, &[], &mut b);
        assert_eq!(qpack::Decoder::new(4096).decode(&b).unwrap()[0], (b":status".to_vec(), b"418".to_vec()));
    }

    #[test]
    fn every_encoded_field_roundtrips() {
        let mut d = qpack::Decoder::new(1 << 20);
        for (n, v) in qpack::STATIC_TABLE.iter() {
            for val in [*v, "other value"] {
                let mut b = vec![0, 0];
                qpack::encode_field(n.as_bytes(), val.as_bytes(), &mut b);
                let f = d.decode(&b).unwrap();
                assert_eq!(f, vec![(n.as_bytes().to_vec(), val.as_bytes().to_vec())], "{n}={val}");
            }
        }
        // Long values exercise multi-byte length prefixes.
        let long = vec![b'z'; 5000];
        let mut b = vec![0, 0];
        qpack::encode_field(b"x-long", &long, &mut b);
        assert_eq!(d.decode(&b).unwrap()[0].1, long);
    }

    #[test]
    fn control_stream_preface_is_valid_for_our_own_parser() {
        let p = control_stream_preface();
        let mut u = UniStream::new();
        assert_eq!(u.feed(&p), Ok(()));
        assert_eq!(u.kind(), Some(UniKind::Control));
    }

    fn settings_frame(pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut p = Vec::new();
        for (a, b) in pairs {
            varint_encode(*a, &mut p);
            varint_encode(*b, &mut p);
        }
        let mut f = Vec::new();
        frame(F_SETTINGS, &p, &mut f);
        f
    }

    #[test]
    fn control_stream_rules() {
        let mk = |body: Vec<u8>| {
            let mut v = vec![0x00];
            v.extend(body);
            v
        };
        // Must start with SETTINGS.
        let mut w = Vec::new();
        frame(F_GOAWAY, &[0x04], &mut w);
        assert_eq!(UniStream::new().feed(&mk(w)), Err(H3_MISSING_SETTINGS));
        // Duplicate SETTINGS.
        let mut w = settings_frame(&[]);
        w.extend(settings_frame(&[]));
        assert_eq!(UniStream::new().feed(&mk(w)), Err(H3_FRAME_UNEXPECTED));
        // Reserved HTTP/2 setting identifiers and duplicates inside a frame.
        assert_eq!(UniStream::new().feed(&mk(settings_frame(&[(0x2, 1)]))), Err(H3_SETTINGS_ERROR));
        assert_eq!(UniStream::new().feed(&mk(settings_frame(&[(0x6, 1), (0x6, 2)]))), Err(H3_SETTINGS_ERROR));
        // Unknown settings are fine; so are GOAWAY, MAX_PUSH_ID and GREASE frames afterwards.
        let mut w = settings_frame(&[(0x1, 4096), (0x7, 16), (0x1f * 5 + 0x21, 0)]);
        frame(F_GOAWAY, &[0x08], &mut w);
        frame(F_MAX_PUSH_ID, &[0x00], &mut w);
        frame(0x41, b"x", &mut w);
        assert_eq!(UniStream::new().feed(&mk(w)), Ok(()));
        // DATA / HEADERS on the control stream.
        let mut w = settings_frame(&[]);
        frame(F_DATA, b"x", &mut w);
        assert_eq!(UniStream::new().feed(&mk(w)), Err(H3_FRAME_UNEXPECTED));
        // Byte-at-a-time delivery works.
        let mut u = UniStream::new();
        for b in mk(settings_frame(&[(0x1, 0), (0x7, 0)])) {
            u.feed(&[b]).unwrap();
        }
        assert_eq!(u.kind(), Some(UniKind::Control));
    }

    #[test]
    fn other_unidirectional_streams() {
        assert_eq!(UniStream::new().feed(&[0x01]), Err(H3_STREAM_CREATION_ERROR));
        let mut u = UniStream::new();
        assert_eq!(u.feed(&[0x02, 1, 2, 3]), Ok(()));
        assert_eq!(u.kind(), Some(UniKind::QpackEncoder));
        assert_eq!(u.feed(&vec![0u8; MAX_QPACK_STREAM_BYTES]), Err(H3_EXCESSIVE_LOAD));
        let mut u = UniStream::new();
        assert_eq!(u.feed(&[0x40, 0x21, 9, 9, 9]), Ok(())); // reserved type 0x21
        assert_eq!(u.kind(), Some(UniKind::Ignored));
        assert_eq!(u.feed(&vec![0u8; 100_000]), Ok(()));
    }

    #[test]
    fn frame_parser_edge_cases() {
        assert_eq!(parse_frame(&[], 10), FrameParse::Incomplete);
        assert_eq!(parse_frame(&[0x00], 10), FrameParse::Incomplete);
        assert_eq!(parse_frame(&[0x00, 0x05, 1, 2], 10), FrameParse::Incomplete);
        assert_eq!(parse_frame(&[0x00, 0x40, 0x20], 10), FrameParse::TooLarge);
        assert_eq!(
            parse_frame(&[0x00, 0x02, 7, 8, 0xff], 10),
            FrameParse::Frame { ty: 0, payload: &[7, 8], total: 4 }
        );
        // Header-only frame types use multi-byte type varints.
        let mut o = Vec::new();
        frame(0x1f * 3 + 0x21, b"g", &mut o);
        assert!(matches!(parse_frame(&o, 10), FrameParse::Frame { .. }));
        // Cannot overflow with a huge declared length.
        let huge = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(parse_frame(&huge, 1 << 20), FrameParse::TooLarge);
    }

    #[test]
    fn goaway_and_data_headers_encode() {
        let mut o = Vec::new();
        goaway_frame(8, &mut o);
        assert_eq!(o, [0x07, 0x01, 0x08]);
        let mut o = Vec::new();
        data_frame_header(300, &mut o);
        assert_eq!(o, [0x00, 0x41, 0x2c]);
    }

    #[test]
    fn deterministic_mutation_fuzz_never_panics() {
        // A tiny xorshift keeps this in `cargo test` without extra dependencies.
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut good = Vec::new();
        request_headers_frame("POST", "ex", "/p?q=1", &[("accept", "*/*"), ("content-length", "4")], &mut good);
        data_frame(b"abcd", &mut good);
        let ctl = {
            let mut c = vec![0x00];
            c.extend(settings_frame(&[(1, 0), (7, 0)]));
            c
        };
        let mut d = dec();
        for _ in 0..20_000 {
            for base in [&good, &ctl] {
                let mut m = base.clone();
                for _ in 0..(1 + next() % 4) {
                    let i = (next() as usize) % m.len();
                    match next() % 3 {
                        0 => m[i] = next() as u8,
                        1 => m[i] ^= 1 << (next() % 8),
                        _ => {
                            m.truncate(i.max(1));
                        }
                    }
                }
                let cut = (next() as usize) % (m.len() + 1);
                let _ = RequestStream::new(4096).feed(&m[..cut], next() % 2 == 0, &mut d);
                let mut rs = RequestStream::new(4096);
                let _ = rs.feed(&m[..cut], false, &mut d);
                let _ = rs.feed(&m[cut..], true, &mut d);
                let _ = UniStream::new().feed(&m);
            }
        }
    }
}
