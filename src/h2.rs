//! HTTP/2 (RFC 9113), server side, sans-I/O.
//!
//! The worker owns the sockets and TLS. It hands this module decrypted bytes
//! ([`H2Conn::feed`]) and sends whatever lands in the `out` buffer.
//!
//! ## What is implemented
//! * Connection preface, SETTINGS (+ACK), PING, GOAWAY, RST_STREAM, PRIORITY (ignored),
//!   WINDOW_UPDATE, HEADERS/CONTINUATION (padding + priority fields handled), DATA.
//! * HPACK decoding via the `hpack` crate (Huffman + dynamic table). Encoding is
//!   hand-written and stateless (literals without indexing), so the encoder can
//!   never desynchronise from the peer's table.
//! * Receive-side flow control (batched WINDOW_UPDATEs) and send-side flow
//!   control at connection and stream level, including SETTINGS_INITIAL_WINDOW_SIZE
//!   changes. Response bodies are scheduled round-robin across streams.
//! * Request bodies are buffered (bounded by `max_body`) until END_STREAM, then the
//!   request is surfaced via [`H2Conn::take_ready`].
//! * Abuse limits: concurrent streams, header block size, RST_STREAM count.
//!
//! ## Deliberately not implemented
//! Server push (never sent), PRIORITY scheduling, extended CONNECT, h2c upgrade.
//!
//! ## Concurrency model
//! `feed` stops after at most one request becomes ready, so the worker can
//! dispatch it (possibly starting an asynchronous proxy job) before parsing
//! further frames.

use crate::static_files::OpenFile;
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::rc::Rc;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types.
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

// Flags.
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

// Error codes.
pub const NO_ERROR: u32 = 0x0;
pub const PROTOCOL_ERROR: u32 = 0x1;
pub const INTERNAL_ERROR: u32 = 0x2;
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
pub const FRAME_SIZE_ERROR: u32 = 0x6;
pub const REFUSED_STREAM: u32 = 0x7;
pub const CANCEL: u32 = 0x8;
pub const COMPRESSION_ERROR: u32 = 0x9;
pub const ENHANCE_YOUR_CALM: u32 = 0xb;

/// Largest frame payload we accept (the protocol default).
const MAX_FRAME: usize = 16_384;
/// Largest frame payload we *send*, regardless of what the peer allows.
const SEND_FRAME: usize = 16_384;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const MAX_CONCURRENT: u32 = 100;
const DEFAULT_WINDOW: i64 = 65_535;
const MAX_WINDOW: i64 = 0x7fff_ffff;
const WINDOW_BATCH: u32 = 16_384;
const MAX_RST: u32 = 1_000;

/// Bytes read from a file per `IORING_OP_READ` for HTTP/2 and TLS bodies.
pub const FILE_CHUNK: usize = 64 * 1024;

pub struct H2Request {
    pub stream: u32,
    pub method: String,
    /// Path plus optional `?query`.
    pub path: String,
    pub authority: Vec<u8>,
    /// Regular (non-pseudo) headers; names are lowercase. Cookies are merged.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

pub enum H2Body {
    Empty,
    Mem(Vec<u8>),
    File(Rc<OpenFile>),
}

pub struct H2Response {
    pub status: u16,
    /// Complete header list (lowercase names), excluding `:status`.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: H2Body,
}

/// A file read the worker must perform; its result goes to [`H2Conn::file_data`].
#[derive(Clone, Copy, Debug)]
pub struct FileRead {
    pub stream: u32,
    pub fd: RawFd,
    pub off: u64,
    pub len: u32,
}

pub struct Feed {
    /// Bytes of input fully consumed.
    pub consumed: usize,
    /// Connection error: GOAWAY was queued, close after flushing.
    pub fatal: bool,
}

struct OpenReq {
    method: String,
    path: String,
    authority: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    unacked: u32,
}

impl OpenReq {
    fn into_request(self, stream: u32) -> H2Request {
        H2Request {
            stream,
            method: self.method,
            path: self.path,
            authority: self.authority,
            headers: self.headers,
            body: self.body,
        }
    }
}

struct Cont {
    stream: u32,
    end_stream: bool,
    trailer: bool,
    refuse: bool,
    block: Vec<u8>,
}

enum SendBody {
    Mem { data: Vec<u8>, pos: usize },
    File { file: Rc<OpenFile>, off: u64, remaining: u64, inflight: bool },
}

struct SendStream {
    id: u32,
    window: i64,
    body: SendBody,
}

pub struct H2Conn {
    got_preface: bool,
    dec: hpack::Decoder<'static>,
    peer_max_frame: usize,
    peer_init_window: i64,
    conn_window: i64,
    recv_unacked: u32,
    last_stream: u32,
    cont: Option<Cont>,
    open: HashMap<u32, OpenReq>,
    ready: Option<H2Request>,
    sends: Vec<SendStream>,
    max_body: usize,
    rst_seen: u32,
    draining: bool,
}

// ───────────────────────── frame writers ─────────────────────────

fn put_frame_header(out: &mut Vec<u8>, len: usize, ty: u8, flags: u8, stream: u32) {
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags]);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
}

fn put_rst(out: &mut Vec<u8>, stream: u32, code: u32) {
    put_frame_header(out, 4, RST_STREAM, 0, stream);
    out.extend_from_slice(&code.to_be_bytes());
}

fn put_window_update(out: &mut Vec<u8>, stream: u32, inc: u32) {
    put_frame_header(out, 4, WINDOW_UPDATE, 0, stream);
    out.extend_from_slice(&inc.to_be_bytes());
}

fn put_goaway(out: &mut Vec<u8>, last: u32, code: u32) {
    put_frame_header(out, 8, GOAWAY, 0, 0);
    out.extend_from_slice(&last.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
}

fn push_setting(buf: &mut Vec<u8>, id: u16, val: u32) {
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&val.to_be_bytes());
}

// ───────────────────────── HPACK (encoder side) ─────────────────────────

/// HPACK integer with an N-bit prefix (RFC 7541 5.1). `flags` are the high bits.
fn put_int(out: &mut Vec<u8>, prefix_bits: u8, flags: u8, mut v: usize) {
    let max = (1usize << prefix_bits) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

/// String literal without Huffman coding.
fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    put_int(out, 7, 0, s.len());
    out.extend_from_slice(s);
}

/// "Literal header field without indexing - new name".
fn put_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x00);
    put_str(out, name);
    put_str(out, value);
}

fn encode_status(out: &mut Vec<u8>, status: u16) {
    // Static table entries 8..=14 are :status 200,204,206,304,400,404,500.
    match status {
        200 => out.push(0x88),
        204 => out.push(0x89),
        206 => out.push(0x8a),
        304 => out.push(0x8b),
        400 => out.push(0x8c),
        404 => out.push(0x8d),
        500 => out.push(0x8e),
        _ => {
            out.push(0x08); // literal without indexing, name = static index 8 (:status)
            put_str(out, status.to_string().as_bytes());
        }
    }
}

/// HEADERS + CONTINUATION frames for one header block.
fn write_headers(out: &mut Vec<u8>, sid: u32, block: &[u8], end_stream: bool, max: usize) {
    let total = block.len();
    let mut pos = 0;
    let mut first = true;
    loop {
        let end = (pos + max).min(total);
        let last = end == total;
        let mut flags = if last { END_HEADERS } else { 0 };
        let ty = if first {
            if end_stream {
                flags |= END_STREAM;
            }
            HEADERS
        } else {
            CONTINUATION
        };
        put_frame_header(out, end - pos, ty, flags, sid);
        out.extend_from_slice(&block[pos..end]);
        pos = end;
        first = false;
        if last {
            break;
        }
    }
}

fn strip_padding(flags: u8, p: &[u8]) -> Result<&[u8], u32> {
    if flags & PADDED == 0 {
        return Ok(p);
    }
    let (&pad, rest) = p.split_first().ok_or(PROTOCOL_ERROR)?;
    let pad = pad as usize;
    if pad > rest.len() {
        return Err(PROTOCOL_ERROR);
    }
    Ok(&rest[..rest.len() - pad])
}

/// Validate a decoded header list and turn it into a request (None = malformed).
fn build_open_req(headers: Vec<(Vec<u8>, Vec<u8>)>) -> Option<OpenReq> {
    let mut method = None;
    let mut path = None;
    let mut authority = Vec::new();
    let mut regular: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut cookies: Vec<Vec<u8>> = Vec::new();
    let mut seen_regular = false;

    for (n, v) in headers {
        if v.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            return None;
        }
        if n.first() == Some(&b':') {
            if seen_regular {
                return None; // pseudo-headers must come first
            }
            match &n[..] {
                b":method" => method = Some(String::from_utf8(v).ok()?),
                b":path" => path = Some(String::from_utf8(v).ok()?),
                b":authority" => authority = v,
                b":scheme" => {}
                _ => return None,
            }
        } else {
            seen_regular = true;
            if n.is_empty() || n.iter().any(|b| b.is_ascii_uppercase() || *b <= 0x20) {
                return None;
            }
            match &n[..] {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" => return None,
                b"te" => {
                    if v != b"trailers" {
                        return None;
                    }
                }
                b"cookie" => cookies.push(v),
                _ => regular.push((n, v)),
            }
        }
    }

    let method = method?;
    let path = path?;
    if method.is_empty() || path.is_empty() || path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return None;
    }
    if !cookies.is_empty() {
        regular.push((b"cookie".to_vec(), cookies.join(&b"; "[..])));
    }
    Some(OpenReq { method, path, authority, headers: regular, body: Vec::new(), unacked: 0 })
}

impl H2Conn {
    /// Creates the connection state and queues our SETTINGS frame.
    pub fn new(max_body: usize, out: &mut Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(12);
        push_setting(&mut payload, 3, MAX_CONCURRENT); // MAX_CONCURRENT_STREAMS
        push_setting(&mut payload, 6, MAX_HEADER_BLOCK as u32); // MAX_HEADER_LIST_SIZE
        put_frame_header(out, payload.len(), SETTINGS, 0, 0);
        out.extend_from_slice(&payload);

        Self {
            got_preface: false,
            dec: hpack::Decoder::new(),
            peer_max_frame: 16_384,
            peer_init_window: DEFAULT_WINDOW,
            conn_window: DEFAULT_WINDOW,
            recv_unacked: 0,
            last_stream: 0,
            cont: None,
            open: HashMap::new(),
            ready: None,
            sends: Vec::new(),
            max_body,
            rst_seen: 0,
            draining: false,
        }
    }

    pub fn take_ready(&mut self) -> Option<H2Request> {
        self.ready.take()
    }

    /// Graceful shutdown: tell the peer no new streams will be accepted
    /// (GOAWAY with NO_ERROR) and refuse any that arrive anyway. Streams that
    /// are already open keep running.
    pub fn start_shutdown(&mut self, out: &mut Vec<u8>) {
        if !self.draining {
            self.draining = true;
            put_goaway(out, self.last_stream, NO_ERROR);
        }
    }

    /// No request is being received or answered on this connection.
    pub fn is_idle(&self) -> bool {
        self.open.is_empty() && self.sends.is_empty() && self.ready.is_none() && self.cont.is_none()
    }

    fn fail(&mut self, code: u32, out: &mut Vec<u8>, total: usize) -> Feed {
        put_goaway(out, self.last_stream, code);
        Feed { consumed: total, fatal: true }
    }

    /// Consume as many complete frames from `input` as possible, stopping
    /// early once a request is ready. Responses to control frames are appended
    /// to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Feed {
        let total = input.len();
        let mut rest = input;

        if !self.got_preface {
            if rest.len() < PREFACE.len() {
                if PREFACE.starts_with(rest) {
                    return Feed { consumed: 0, fatal: false };
                }
                return self.fail(PROTOCOL_ERROR, out, total);
            }
            if &rest[..PREFACE.len()] != PREFACE {
                return self.fail(PROTOCOL_ERROR, out, total);
            }
            rest = &rest[PREFACE.len()..];
            self.got_preface = true;
        }

        while self.ready.is_none() && rest.len() >= 9 {
            let len = (rest[0] as usize) << 16 | (rest[1] as usize) << 8 | rest[2] as usize;
            if len > MAX_FRAME {
                return self.fail(FRAME_SIZE_ERROR, out, total);
            }
            if rest.len() < 9 + len {
                break;
            }
            let ty = rest[3];
            let flags = rest[4];
            let sid = u32::from_be_bytes([rest[5] & 0x7f, rest[6], rest[7], rest[8]]);
            let payload = &rest[9..9 + len];

            // While a header block is open, only its CONTINUATIONs may arrive.
            if let Some(c) = &self.cont {
                if ty != CONTINUATION || sid != c.stream {
                    return self.fail(PROTOCOL_ERROR, out, total);
                }
            }
            if let Err(code) = self.frame(ty, flags, sid, payload, out) {
                return self.fail(code, out, total);
            }
            rest = &rest[9 + len..];
        }
        Feed { consumed: total - rest.len(), fatal: false }
    }

    fn frame(&mut self, ty: u8, flags: u8, sid: u32, p: &[u8], out: &mut Vec<u8>) -> Result<(), u32> {
        match ty {
            DATA => self.on_data(flags, sid, p, out),
            HEADERS => self.on_headers(flags, sid, p, out),
            PRIORITY => {
                if sid == 0 {
                    Err(PROTOCOL_ERROR)
                } else if p.len() != 5 {
                    Err(FRAME_SIZE_ERROR)
                } else {
                    Ok(())
                }
            }
            RST_STREAM => {
                if sid == 0 {
                    return Err(PROTOCOL_ERROR);
                }
                if p.len() != 4 {
                    return Err(FRAME_SIZE_ERROR);
                }
                self.open.remove(&sid);
                self.sends.retain(|s| s.id != sid);
                self.rst_seen += 1;
                if self.rst_seen > MAX_RST {
                    return Err(ENHANCE_YOUR_CALM); // rapid-reset style abuse
                }
                Ok(())
            }
            SETTINGS => self.on_settings(flags, sid, p, out),
            PUSH_PROMISE => Err(PROTOCOL_ERROR), // clients must not send it
            PING => {
                if sid != 0 {
                    return Err(PROTOCOL_ERROR);
                }
                if p.len() != 8 {
                    return Err(FRAME_SIZE_ERROR);
                }
                if flags & ACK == 0 {
                    put_frame_header(out, 8, PING, ACK, 0);
                    out.extend_from_slice(p);
                }
                Ok(())
            }
            GOAWAY => {
                if sid != 0 {
                    Err(PROTOCOL_ERROR)
                } else {
                    Ok(())
                }
            }
            WINDOW_UPDATE => self.on_window_update(sid, p, out),
            CONTINUATION => self.on_continuation(flags, sid, p, out),
            _ => Ok(()), // unknown frame types must be ignored
        }
    }

    fn on_settings(&mut self, flags: u8, sid: u32, p: &[u8], out: &mut Vec<u8>) -> Result<(), u32> {
        if sid != 0 {
            return Err(PROTOCOL_ERROR);
        }
        if flags & ACK != 0 {
            return if p.is_empty() { Ok(()) } else { Err(FRAME_SIZE_ERROR) };
        }
        if p.len() % 6 != 0 {
            return Err(FRAME_SIZE_ERROR);
        }
        for e in p.chunks_exact(6) {
            let id = u16::from_be_bytes([e[0], e[1]]);
            let val = u32::from_be_bytes([e[2], e[3], e[4], e[5]]);
            match id {
                2 => {
                    if val > 1 {
                        return Err(PROTOCOL_ERROR);
                    }
                }
                4 => {
                    if val as i64 > MAX_WINDOW {
                        return Err(FLOW_CONTROL_ERROR);
                    }
                    let delta = val as i64 - self.peer_init_window;
                    self.peer_init_window = val as i64;
                    for s in self.sends.iter_mut() {
                        s.window += delta;
                        if s.window > MAX_WINDOW {
                            return Err(FLOW_CONTROL_ERROR);
                        }
                    }
                }
                5 => {
                    if !(16_384..=16_777_215).contains(&val) {
                        return Err(PROTOCOL_ERROR);
                    }
                    self.peer_max_frame = val as usize;
                }
                _ => {} // header table size (our encoder is stateless), concurrency, unknown
            }
        }
        put_frame_header(out, 0, SETTINGS, ACK, 0);
        Ok(())
    }

    fn on_window_update(&mut self, sid: u32, p: &[u8], out: &mut Vec<u8>) -> Result<(), u32> {
        if p.len() != 4 {
            return Err(FRAME_SIZE_ERROR);
        }
        let inc = (u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff) as i64;
        if sid == 0 {
            if inc == 0 {
                return Err(PROTOCOL_ERROR);
            }
            self.conn_window += inc;
            if self.conn_window > MAX_WINDOW {
                return Err(FLOW_CONTROL_ERROR);
            }
        } else if inc == 0 {
            put_rst(out, sid, PROTOCOL_ERROR);
            self.sends.retain(|s| s.id != sid);
        } else if let Some(i) = self.sends.iter().position(|s| s.id == sid) {
            self.sends[i].window += inc;
            if self.sends[i].window > MAX_WINDOW {
                put_rst(out, sid, FLOW_CONTROL_ERROR);
                self.sends.remove(i);
            }
        }
        Ok(())
    }

    fn on_headers(&mut self, flags: u8, sid: u32, p: &[u8], out: &mut Vec<u8>) -> Result<(), u32> {
        if sid == 0 || sid % 2 == 0 {
            return Err(PROTOCOL_ERROR);
        }
        let mut p = strip_padding(flags, p)?;
        if flags & PRIORITY_FLAG != 0 {
            if p.len() < 5 {
                return Err(PROTOCOL_ERROR);
            }
            p = &p[5..];
        }

        let trailer = self.open.contains_key(&sid);
        let mut refuse = false;
        if !trailer {
            if sid <= self.last_stream {
                return Err(PROTOCOL_ERROR);
            }
            self.last_stream = sid;
            refuse = self.draining || self.open.len() + self.sends.len() >= MAX_CONCURRENT as usize;
        }

        let end_stream = flags & END_STREAM != 0;
        if flags & END_HEADERS != 0 {
            self.header_block(sid, end_stream, trailer, refuse, p, out)
        } else {
            if p.len() > MAX_HEADER_BLOCK {
                return Err(ENHANCE_YOUR_CALM);
            }
            self.cont = Some(Cont { stream: sid, end_stream, trailer, refuse, block: p.to_vec() });
            Ok(())
        }
    }

    fn on_continuation(&mut self, flags: u8, sid: u32, p: &[u8], out: &mut Vec<u8>) -> Result<(), u32> {
        let Some(c) = self.cont.as_mut() else { return Err(PROTOCOL_ERROR) };
        if sid != c.stream {
            return Err(PROTOCOL_ERROR);
        }
        if c.block.len() + p.len() > MAX_HEADER_BLOCK {
            return Err(ENHANCE_YOUR_CALM);
        }
        c.block.extend_from_slice(p);
        if flags & END_HEADERS != 0 {
            let c = self.cont.take().expect("checked above");
            self.header_block(c.stream, c.end_stream, c.trailer, c.refuse, &c.block, out)
        } else {
            Ok(())
        }
    }

    /// A complete header block. It is *always* decoded, even when the stream
    /// is refused, so the HPACK dynamic table stays in sync with the peer.
    fn header_block(
        &mut self,
        sid: u32,
        end_stream: bool,
        trailer: bool,
        refuse: bool,
        block: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), u32> {
        let headers = self.dec.decode(block).map_err(|_| COMPRESSION_ERROR)?;
        let size: usize = headers.iter().map(|(n, v)| n.len() + v.len() + 32).sum();

        if refuse {
            put_rst(out, sid, REFUSED_STREAM);
            return Ok(());
        }
        if size > MAX_HEADER_BLOCK {
            put_rst(out, sid, ENHANCE_YOUR_CALM);
            self.open.remove(&sid);
            return Ok(());
        }
        if trailer {
            if !end_stream {
                return Err(PROTOCOL_ERROR);
            }
            if let Some(r) = self.open.remove(&sid) {
                self.ready = Some(r.into_request(sid));
            }
            return Ok(());
        }
        match build_open_req(headers) {
            None => put_rst(out, sid, PROTOCOL_ERROR),
            Some(r) => {
                if end_stream {
                    self.ready = Some(r.into_request(sid));
                } else {
                    self.open.insert(sid, r);
                }
            }
        }
        Ok(())
    }

    fn on_data(&mut self, flags: u8, sid: u32, p: &[u8], out: &mut Vec<u8>) -> Result<(), u32> {
        if sid == 0 {
            return Err(PROTOCOL_ERROR);
        }
        let flow_len = p.len(); // padding counts against flow control
        let data = strip_padding(flags, p)?;
        let end_stream = flags & END_STREAM != 0;

        // Connection-level credit, batched.
        self.recv_unacked += flow_len as u32;
        if self.recv_unacked >= WINDOW_BATCH {
            put_window_update(out, 0, self.recv_unacked);
            self.recv_unacked = 0;
        }

        let Some(r) = self.open.get_mut(&sid) else {
            // Closed or already answered stream: discard. An *idle* stream is an error.
            return if sid > self.last_stream { Err(PROTOCOL_ERROR) } else { Ok(()) };
        };

        if r.body.len() + data.len() > self.max_body {
            self.open.remove(&sid);
            put_rst(out, sid, CANCEL);
            return Ok(());
        }
        r.body.extend_from_slice(data);
        r.unacked += flow_len as u32;
        if r.unacked >= WINDOW_BATCH && !end_stream {
            put_window_update(out, sid, r.unacked);
            r.unacked = 0;
        }
        if end_stream {
            if let Some(r) = self.open.remove(&sid) {
                self.ready = Some(r.into_request(sid));
            }
        }
        Ok(())
    }

    // ───────────────────────── responses ─────────────────────────

    /// Queue a response: HEADERS now, body scheduled under flow control.
    pub fn respond(&mut self, stream: u32, resp: H2Response, out: &mut Vec<u8>) {
        let mut block = Vec::with_capacity(128);
        encode_status(&mut block, resp.status);
        for (n, v) in &resp.headers {
            put_literal(&mut block, n, v);
        }
        let end_now = matches!(resp.body, H2Body::Empty);
        write_headers(out, stream, &block, end_now, self.peer_max_frame.min(SEND_FRAME));

        match resp.body {
            H2Body::Empty => {}
            H2Body::Mem(data) => {
                if data.is_empty() {
                    put_frame_header(out, 0, DATA, END_STREAM, stream);
                } else {
                    self.sends.push(SendStream {
                        id: stream,
                        window: self.peer_init_window,
                        body: SendBody::Mem { data, pos: 0 },
                    });
                }
            }
            H2Body::File(file) => {
                if file.size == 0 {
                    put_frame_header(out, 0, DATA, END_STREAM, stream);
                } else {
                    let remaining = file.size;
                    self.sends.push(SendStream {
                        id: stream,
                        window: self.peer_init_window,
                        body: SendBody::File { file, off: 0, remaining, inflight: false },
                    });
                }
            }
        }
    }

    /// Emit as much in-memory body data as the windows allow, then report the
    /// next file read needed (if any). Call after anything that may have
    /// opened a window or queued a response.
    pub fn poll_output(&mut self, out: &mut Vec<u8>) -> Option<FileRead> {
        let fs = self.peer_max_frame.min(SEND_FRAME);

        let mut progress = true;
        while progress && self.conn_window > 0 {
            progress = false;
            for s in self.sends.iter_mut() {
                if let SendBody::Mem { data, pos } = &mut s.body {
                    if s.window <= 0 || self.conn_window <= 0 {
                        continue;
                    }
                    let remaining = data.len() - *pos;
                    let n = remaining
                        .min(s.window as usize)
                        .min(self.conn_window as usize)
                        .min(fs);
                    if n == 0 {
                        continue;
                    }
                    let last = n == remaining;
                    put_frame_header(out, n, DATA, if last { END_STREAM } else { 0 }, s.id);
                    out.extend_from_slice(&data[*pos..*pos + n]);
                    *pos += n;
                    s.window -= n as i64;
                    self.conn_window -= n as i64;
                    progress = true;
                }
            }
            self.sends.retain(|s| match &s.body {
                SendBody::Mem { data, pos } => *pos < data.len(),
                SendBody::File { .. } => true,
            });
        }

        if self.conn_window > 0 {
            let mut pick: Option<(usize, FileRead)> = None;
            for (i, s) in self.sends.iter_mut().enumerate() {
                if let SendBody::File { file, off, remaining, inflight } = &mut s.body {
                    if *inflight || s.window <= 0 {
                        continue;
                    }
                    let len = (*remaining)
                        .min(s.window as u64)
                        .min(self.conn_window as u64)
                        .min(FILE_CHUNK as u64) as u32;
                    if len == 0 {
                        continue;
                    }
                    *inflight = true;
                    pick = Some((i, FileRead { stream: s.id, fd: file.fd(), off: *off, len }));
                    break;
                }
            }
            if let Some((i, fr)) = pick {
                // Round-robin: the stream we just served goes to the back.
                self.sends.rotate_left(i + 1);
                return Some(fr);
            }
        }
        None
    }

    /// Deliver the result of a [`FileRead`]. An empty `data` means the read
    /// failed or hit EOF early: the stream is reset.
    pub fn file_data(&mut self, stream: u32, data: &[u8], out: &mut Vec<u8>) {
        let Some(i) = self.sends.iter().position(|s| s.id == stream) else { return };
        let fs = self.peer_max_frame.min(SEND_FRAME);

        let finished = {
            let s = &mut self.sends[i];
            let SendBody::File { off, remaining, inflight, .. } = &mut s.body else { return };
            *inflight = false;

            if data.is_empty() {
                put_rst(out, stream, INTERNAL_ERROR);
                true
            } else {
                let n = data.len().min(*remaining as usize);
                let whole = n as u64 == *remaining;
                let mut sent = 0;
                while sent < n {
                    let m = (n - sent).min(fs);
                    let last = whole && sent + m == n;
                    put_frame_header(out, m, DATA, if last { END_STREAM } else { 0 }, stream);
                    out.extend_from_slice(&data[sent..sent + m]);
                    sent += m;
                }
                *off += n as u64;
                *remaining -= n as u64;
                s.window -= n as i64;
                self.conn_window -= n as i64;
                *remaining == 0
            }
        };
        if finished {
            self.sends.remove(i);
        }
    }

    /// Number of response streams still being sent.
    pub fn active_sends(&self) -> usize {
        self.sends.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ty: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        put_frame_header(&mut v, payload.len(), ty, flags, sid);
        v.extend_from_slice(payload);
        v
    }

    /// Split a byte stream into (type, flags, stream, payload).
    fn frames(mut b: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut v = Vec::new();
        while b.len() >= 9 {
            let len = (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize;
            let sid = u32::from_be_bytes([b[5] & 0x7f, b[6], b[7], b[8]]);
            v.push((b[3], b[4], sid, b[9..9 + len].to_vec()));
            b = &b[9 + len..];
        }
        assert!(b.is_empty(), "trailing partial frame");
        v
    }

    fn encode_req(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut enc = hpack::Encoder::new();
        enc.encode(headers.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())))
    }

    fn get_headers(path: &str) -> Vec<u8> {
        encode_req(&[(":method", "GET"), (":scheme", "https"), (":path", path), (":authority", "localhost")])
    }

    fn started() -> (H2Conn, Vec<u8>) {
        let mut out = Vec::new();
        let mut h = H2Conn::new(1 << 20, &mut out);
        let mut input = PREFACE.to_vec();
        input.extend(frame(SETTINGS, 0, 0, &[]));
        let f = h.feed(&input, &mut out);
        assert!(!f.fatal);
        assert_eq!(f.consumed, input.len());
        (h, out)
    }

    #[test]
    fn handshake_emits_settings_and_ack() {
        let (_h, out) = started();
        let fs = frames(&out);
        assert_eq!(fs[0].0, SETTINGS);
        assert_eq!(fs[0].1, 0);
        assert!(fs.iter().any(|f| f.0 == SETTINGS && f.1 == ACK));
    }

    #[test]
    fn bad_preface_is_goaway() {
        let mut out = Vec::new();
        let mut h = H2Conn::new(1024, &mut out);
        out.clear();
        let f = h.feed(b"GET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n", &mut out);
        assert!(f.fatal);
        let fs = frames(&out);
        assert_eq!(fs[0].0, GOAWAY);
    }

    #[test]
    fn partial_preface_waits() {
        let mut out = Vec::new();
        let mut h = H2Conn::new(1024, &mut out);
        let f = h.feed(&PREFACE[..10], &mut out);
        assert!(!f.fatal);
        assert_eq!(f.consumed, 0);
    }

    #[test]
    fn simple_get_becomes_ready() {
        let (mut h, mut out) = started();
        out.clear();
        let block = get_headers("/hello?x=1");
        let input = frame(HEADERS, END_HEADERS | END_STREAM, 1, &block);
        let f = h.feed(&input, &mut out);
        assert_eq!(f.consumed, input.len());
        let r = h.take_ready().expect("request");
        assert_eq!((r.stream, r.method.as_str(), r.path.as_str()), (1, "GET", "/hello?x=1"));
        assert_eq!(r.authority, b"localhost");
        assert!(r.body.is_empty());
    }

    #[test]
    fn feed_stops_after_one_ready_request() {
        let (mut h, mut out) = started();
        let b = get_headers("/a");
        let mut input = frame(HEADERS, END_HEADERS | END_STREAM, 1, &b);
        let first_len = input.len();
        input.extend(frame(HEADERS, END_HEADERS | END_STREAM, 3, &get_headers("/b")));
        let f = h.feed(&input, &mut out);
        assert_eq!(f.consumed, first_len);
        assert_eq!(h.take_ready().unwrap().path, "/a");
        let f2 = h.feed(&input[first_len..], &mut out);
        assert_eq!(f2.consumed, input.len() - first_len);
        assert_eq!(h.take_ready().unwrap().path, "/b");
    }

    #[test]
    fn request_body_is_buffered_until_end_stream() {
        let (mut h, mut out) = started();
        let block = encode_req(&[(":method", "POST"), (":scheme", "https"), (":path", "/p"), (":authority", "x"), ("content-length", "5")]);
        h.feed(&frame(HEADERS, END_HEADERS, 1, &block), &mut out);
        assert!(h.take_ready().is_none());
        h.feed(&frame(DATA, 0, 1, b"he"), &mut out);
        assert!(h.take_ready().is_none());
        h.feed(&frame(DATA, END_STREAM, 1, b"llo"), &mut out);
        let r = h.take_ready().unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn continuation_frames_are_joined() {
        let (mut h, mut out) = started();
        let block = get_headers("/split");
        let (a, b) = block.split_at(block.len() / 2);
        let mut input = frame(HEADERS, END_STREAM, 1, a);
        input.extend(frame(CONTINUATION, END_HEADERS, 1, b));
        h.feed(&input, &mut out);
        assert_eq!(h.take_ready().unwrap().path, "/split");
    }

    #[test]
    fn interleaving_during_header_block_is_an_error() {
        let (mut h, mut out) = started();
        let block = get_headers("/x");
        let mut input = frame(HEADERS, 0, 1, &block[..2]);
        input.extend(frame(PING, 0, 0, &[0; 8]));
        let f = h.feed(&input, &mut out);
        assert!(f.fatal);
    }

    #[test]
    fn cookies_are_merged_and_uppercase_names_rejected() {
        let (mut h, mut out) = started();
        let block = encode_req(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), ("cookie", "a=1"), ("cookie", "b=2")]);
        h.feed(&frame(HEADERS, END_HEADERS | END_STREAM, 1, &block), &mut out);
        let r = h.take_ready().unwrap();
        let c = r.headers.iter().find(|(n, _)| n == b"cookie").unwrap();
        assert_eq!(c.1, b"a=1; b=2");

        out.clear();
        let bad = encode_req(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), ("X-Upper", "v")]);
        let f = h.feed(&frame(HEADERS, END_HEADERS | END_STREAM, 3, &bad), &mut out);
        assert!(!f.fatal);
        assert!(h.take_ready().is_none());
        let fs = frames(&out);
        assert_eq!((fs[0].0, fs[0].2), (RST_STREAM, 3));
    }

    #[test]
    fn ping_is_acked_and_stream_ids_must_increase() {
        let (mut h, mut out) = started();
        out.clear();
        h.feed(&frame(PING, 0, 0, b"12345678"), &mut out);
        let fs = frames(&out);
        assert_eq!((fs[0].0, fs[0].1), (PING, ACK));
        assert_eq!(fs[0].3, b"12345678");

        out.clear();
        h.feed(&frame(HEADERS, END_HEADERS | END_STREAM, 5, &get_headers("/")), &mut out);
        h.take_ready();
        let f = h.feed(&frame(HEADERS, END_HEADERS | END_STREAM, 3, &get_headers("/")), &mut out);
        assert!(f.fatal);
    }

    fn mem_response(len: usize) -> H2Response {
        H2Response {
            status: 200,
            headers: vec![(b"content-type".to_vec(), b"x/y".to_vec())],
            body: H2Body::Mem(vec![b'z'; len]),
        }
    }

    fn data_bytes(out: &[u8]) -> (usize, bool) {
        let mut n = 0;
        let mut ended = false;
        for (ty, flags, _, p) in frames(out) {
            if ty == DATA {
                n += p.len();
                ended |= flags & END_STREAM != 0;
            }
        }
        (n, ended)
    }

    #[test]
    fn response_headers_use_static_status_index() {
        let (mut h, mut out) = started();
        out.clear();
        h.respond(1, H2Response { status: 404, headers: vec![], body: H2Body::Empty }, &mut out);
        let fs = frames(&out);
        assert_eq!(fs[0].0, HEADERS);
        assert_eq!(fs[0].1, END_HEADERS | END_STREAM);
        assert_eq!(fs[0].3, vec![0x8d]);

        out.clear();
        h.respond(3, H2Response { status: 502, headers: vec![], body: H2Body::Empty }, &mut out);
        let fs = frames(&out);
        assert_eq!(fs[0].3, vec![0x08, 0x03, b'5', b'0', b'2']);
    }

    #[test]
    fn send_side_flow_control_blocks_then_resumes() {
        let (mut h, mut out) = started();
        out.clear();
        h.respond(1, mem_response(100_000), &mut out);
        assert!(h.poll_output(&mut out).is_none());
        let (n, ended) = data_bytes(&out);
        assert_eq!(n, 65_535, "limited by the 65535-byte windows");
        assert!(!ended);

        out.clear();
        h.feed(&frame(WINDOW_UPDATE, 0, 0, &65_535u32.to_be_bytes()), &mut out);
        h.feed(&frame(WINDOW_UPDATE, 0, 1, &65_535u32.to_be_bytes()), &mut out);
        h.poll_output(&mut out);
        let (n, ended) = data_bytes(&out);
        assert_eq!(n, 100_000 - 65_535);
        assert!(ended);
        assert_eq!(h.active_sends(), 0);
    }

    #[test]
    fn initial_window_setting_adjusts_open_streams() {
        let (mut h, mut out) = started();
        out.clear();
        h.respond(1, mem_response(200_000), &mut out);
        h.poll_output(&mut out);
        out.clear();
        // Raise the peer's per-stream window by 1 MiB and the connection window too.
        let mut s = Vec::new();
        push_setting(&mut s, 4, 1 << 20);
        h.feed(&frame(SETTINGS, 0, 0, &s), &mut out);
        h.feed(&frame(WINDOW_UPDATE, 0, 0, &(1u32 << 20).to_be_bytes()), &mut out);
        h.poll_output(&mut out);
        let (n, ended) = data_bytes(&out);
        assert_eq!(n, 200_000 - 65_535);
        assert!(ended);
    }

    #[test]
    fn frames_are_capped_at_16k() {
        let (mut h, mut out) = started();
        out.clear();
        h.respond(1, mem_response(40_000), &mut out);
        h.poll_output(&mut out);
        for (ty, _, _, p) in frames(&out) {
            if ty == DATA {
                assert!(p.len() <= 16_384);
            }
        }
    }

    #[test]
    fn rst_stream_cancels_pending_body() {
        let (mut h, mut out) = started();
        h.respond(1, mem_response(100_000), &mut out);
        h.feed(&frame(RST_STREAM, 0, 1, &CANCEL.to_be_bytes()), &mut out);
        assert_eq!(h.active_sends(), 0);
    }

    #[test]
    fn data_triggers_window_updates() {
        let (mut h, mut out) = started();
        let block = encode_req(&[(":method", "POST"), (":scheme", "https"), (":path", "/p"), (":authority", "x")]);
        h.feed(&frame(HEADERS, END_HEADERS, 1, &block), &mut out);
        out.clear();
        h.feed(&frame(DATA, 0, 1, &vec![0u8; 16_000]), &mut out);
        h.feed(&frame(DATA, 0, 1, &vec![0u8; 16_000]), &mut out);
        let fs = frames(&out);
        assert!(fs.iter().any(|f| f.0 == WINDOW_UPDATE && f.2 == 0));
        assert!(fs.iter().any(|f| f.0 == WINDOW_UPDATE && f.2 == 1));
    }

    #[test]
    fn oversized_body_resets_stream() {
        let mut out = Vec::new();
        let mut h = H2Conn::new(10, &mut out);
        let mut input = PREFACE.to_vec();
        input.extend(frame(SETTINGS, 0, 0, &[]));
        h.feed(&input, &mut out);
        let block = encode_req(&[(":method", "POST"), (":scheme", "https"), (":path", "/p"), (":authority", "x")]);
        h.feed(&frame(HEADERS, END_HEADERS, 1, &block), &mut out);
        out.clear();
        h.feed(&frame(DATA, END_STREAM, 1, &[0u8; 64]), &mut out);
        assert!(h.take_ready().is_none());
        assert_eq!(frames(&out)[0].0, RST_STREAM);
    }

    #[test]
    fn graceful_shutdown_sends_goaway_and_refuses_new_streams() {
        let (mut h, mut out) = started();
        assert!(h.is_idle());
        out.clear();
        h.start_shutdown(&mut out);
        h.start_shutdown(&mut out); // idempotent
        let fs = frames(&out);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].0, GOAWAY);
        assert_eq!(&fs[0].3[4..8], &NO_ERROR.to_be_bytes());

        out.clear();
        let f = h.feed(&frame(HEADERS, END_HEADERS | END_STREAM, 1, &get_headers("/late")), &mut out);
        assert!(!f.fatal, "refusing a stream is not a connection error");
        assert!(h.take_ready().is_none());
        let fs = frames(&out);
        assert_eq!((fs[0].0, fs[0].2), (RST_STREAM, 1));
        assert_eq!(&fs[0].3[..], &REFUSED_STREAM.to_be_bytes());
    }

    #[test]
    fn idle_tracking() {
        let (mut h, mut out) = started();
        assert!(h.is_idle());
        h.respond(1, mem_response(100_000), &mut out);
        assert!(!h.is_idle(), "response still being sent");
        h.feed(&frame(RST_STREAM, 0, 1, &CANCEL.to_be_bytes()), &mut out);
        assert!(h.is_idle());
    }

    #[test]
    fn hpack_int_encoding() {
        let mut v = Vec::new();
        put_int(&mut v, 7, 0, 10);
        assert_eq!(v, [10]);
        v.clear();
        put_int(&mut v, 7, 0, 1337 - 0);
        // 1337 with a 7-bit prefix: 127, then 1210 as base-128 varint.
        assert_eq!(v, [127, (1210 % 128) as u8 | 0x80, (1210 / 128) as u8]);
    }
}
