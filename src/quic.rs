//! Per-core QUIC + HTTP/3 engine, built on `quinn-proto`.
//!
//! `quinn-proto` is a *sans-I/O* QUIC state machine: it consumes datagrams and
//! timer expirations and produces datagrams, timer deadlines and stream
//! events. This module wraps it with the HTTP/3 layer of [`crate::h3`] and
//! exposes a small, I/O-free interface that [`crate::worker`] drives from its
//! io_uring loop (UDP `recvmsg`/`sendmsg` and a timeout operation):
//!
//! ```text
//!   worker (io_uring)                    Quic
//!   ──────────────────────────────────────────────────────────────
//!   RecvMsg completion ─ recv(now, from, bytes) ─▶  endpoint.handle
//!   Timeout completion ─ on_timeout(now) ───────▶   conn.handle_timeout
//!   after each batch   ─ flush(now) ────────────▶   drive dirty connections
//!                      ◀ take_requests() ───────    complete H3 requests
//!   route / proxy      ─ respond(id, stream, r) ▶   queue HEADERS + DATA
//!                      ◀ take_datagrams() ──────    SendMsg queue
//!                      ◀ next_timeout() ────────    re-arm the timer
//! ```
//!
//! Nothing here is shared between cores: each worker owns an endpoint bound
//! to its own `SO_REUSEPORT` UDP socket. The kernel hashes a client's
//! 4-tuple to one socket, so a connection stays on one core for as long as the
//! client's address does. **Connection migration is therefore disabled**
//! (`ServerConfig::migration(false)`); steering by connection ID needs an
//! eBPF `SO_REUSEPORT` program, which is future work.
//!
//! Request bodies are buffered (as for HTTP/2). Static file bodies are read
//! with `pread` in 64 KiB pieces as flow control allows; this is the one
//! place a page-cache miss can block the core (documented in the README).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::crypto::rustls::QuicServerConfig;
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, EndpointEvent, Event,
    IdleTimeout, Incoming, ReadError, ServerConfig, StreamEvent, StreamId, TransportConfig, VarInt,
    WriteError,
};

use crate::h2::{H2Body, H2Response};
use crate::h3::{self, qpack, H3Err, H3Request, RequestStream, UniKind, UniStream};
use crate::static_files::OpenFile;
use crate::tls;

/// Bytes of a file or buffer turned into one DATA frame at a time.
const CHUNK: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct QuicConfig {
    /// Require a Retry round trip before accepting a connection (address validation).
    pub retry: bool,
    pub idle_timeout: Duration,
    pub max_bidi_streams: u32,
    /// Request body limit (also bounds one DATA frame).
    pub max_body: usize,
    /// Refuse new connections beyond this many.
    pub max_conns: usize,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            retry: true,
            idle_timeout: Duration::from_secs(30),
            max_bidi_streams: 100,
            max_body: 1 << 20,
            max_conns: 65_536,
        }
    }
}

/// Build the QUIC server configuration from PEM files.
pub fn server_config(cert: &Path, key: &Path, cfg: &QuicConfig) -> Result<Arc<ServerConfig>, String> {
    let rustls_cfg = tls::build_quic_tls(cert, key)?;
    let crypto = QuicServerConfig::try_from(rustls_cfg).map_err(|e| format!("quic: {e}"))?;
    let mut sc = ServerConfig::with_crypto(Arc::new(crypto));

    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(cfg.max_bidi_streams));
    t.max_concurrent_uni_streams(VarInt::from_u32(8));
    t.max_idle_timeout(Some(
        IdleTimeout::try_from(cfg.idle_timeout).map_err(|_| "quic: idle timeout out of range".to_string())?,
    ));
    t.datagram_receive_buffer_size(None); // no unreliable datagrams
    t.stream_receive_window(VarInt::from_u32(256 * 1024));
    t.receive_window(VarInt::from_u32(4 * 1024 * 1024));
    t.send_window(8 * 1024 * 1024);
    sc.transport_config(Arc::new(t));
    sc.migration(false); // see module docs
    Ok(Arc::new(sc))
}

/// Identifies a connection across `Quic` calls; stale ids (the connection
/// closed and its handle was reused) are detected by the generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QConnId {
    handle: ConnectionHandle,
    gen: u64,
}

/// A complete HTTP/3 request, ready for routing.
pub struct Ready {
    pub id: QConnId,
    pub stream: StreamId,
    pub req: H3Request,
    pub peer: SocketAddr,
}

/// One UDP datagram to send.
pub struct Datagram {
    pub dest: SocketAddr,
    pub data: Vec<u8>,
}

#[derive(Default, Clone, Debug)]
pub struct QuicStats {
    pub conns_accepted: u64,
    pub conns_closed: u64,
    pub requests: u64,
    pub retries_sent: u64,
    pub refused: u64,
    pub protocol_errors: u64,
}

// ───────────────────────── per-stream output ─────────────────────────

enum Body {
    None,
    Mem { data: Vec<u8>, pos: usize },
    File { file: Rc<OpenFile>, off: u64, remaining: u64 },
}

enum Fill {
    More,
    Done,
    Error,
}

/// Response bytes waiting for stream flow control.
struct OutStream {
    pending: Vec<u8>,
    pos: usize,
    body: Body,
}

impl OutStream {
    /// Append the next DATA frame to `pending`.
    fn refill(&mut self) -> Fill {
        match &mut self.body {
            Body::None => Fill::Done,
            Body::Mem { data, pos } => {
                if *pos >= data.len() {
                    return Fill::Done;
                }
                let n = (data.len() - *pos).min(CHUNK);
                h3::data_frame_header(n as u64, &mut self.pending);
                self.pending.extend_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                Fill::More
            }
            Body::File { file, off, remaining } => {
                if *remaining == 0 {
                    return Fill::Done;
                }
                let n = (*remaining).min(CHUNK as u64) as usize;
                let mut tmp = vec![0u8; n];
                // SAFETY: `tmp` is a live buffer of `n` bytes; the fd is owned by `file`.
                let got = unsafe { libc::pread(file.fd(), tmp.as_mut_ptr().cast(), n, *off as libc::off_t) };
                if got <= 0 {
                    return Fill::Error; // truncated or unreadable file
                }
                let got = got as usize;
                h3::data_frame_header(got as u64, &mut self.pending);
                self.pending.extend_from_slice(&tmp[..got]);
                *off += got as u64;
                *remaining -= got as u64;
                Fill::More
            }
        }
    }
}

// ───────────────────────── per-connection state ─────────────────────────

struct QConn {
    conn: Connection,
    handle: ConnectionHandle,
    gen: u64,
    peer: SocketAddr,
    /// Request streams still being received.
    reqs: HashMap<StreamId, RequestStream>,
    unis: HashMap<StreamId, UniStream>,
    outs: HashMap<StreamId, OutStream>,
    /// Requests handed to the worker and not yet answered.
    pending: usize,
    /// Our control stream, once opened.
    ctl: Option<StreamId>,
    accepted_bidi: u64,
    draining: bool,
    goaway_sent: bool,
    closing: bool,
    timer: Option<(Instant, u64)>,
}

impl QConn {
    fn busy(&self) -> bool {
        !self.reqs.is_empty() || !self.outs.is_empty() || self.pending > 0
    }
}

fn vi(code: u64) -> VarInt {
    VarInt::from_u64(code).unwrap_or(VarInt::from_u32(0))
}

/// Read everything currently available on a stream.
fn read_all(conn: &mut Connection, id: StreamId) -> (Vec<u8>, bool, Option<VarInt>) {
    let mut data = Vec::new();
    let mut fin = false;
    let mut reset = None;
    let mut recv = conn.recv_stream(id);
    let Ok(mut chunks) = recv.read(true) else { return (data, false, None) };
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(c)) => data.extend_from_slice(&c.bytes),
            Ok(None) => {
                fin = true;
                break;
            }
            Err(ReadError::Reset(code)) => {
                reset = Some(code);
                break;
            }
            Err(_) => break, // Blocked: nothing more right now
        }
    }
    let _ = chunks.finalize();
    (data, fin, reset)
}

fn close_conn(qc: &mut QConn, now: Instant, code: u64) {
    if !qc.closing {
        qc.closing = true;
        qc.conn.close(now, vi(code), Bytes::new());
    }
}

/// Queue a response on `id` and start writing it.
fn start_out(qc: &mut QConn, id: StreamId, resp: H2Response) {
    let mut pending = Vec::with_capacity(256);
    let headers: Vec<(Vec<u8>, Vec<u8>)> = resp
        .headers
        .into_iter()
        .filter(|(n, _)| n != b"alt-svc" && n != b"connection")
        .collect();
    h3::response_headers_frame(resp.status, &headers, &mut pending);
    let body = match resp.body {
        H2Body::Empty => Body::None,
        H2Body::Mem(data) if data.is_empty() => Body::None,
        H2Body::Mem(data) => Body::Mem { data, pos: 0 },
        H2Body::File(file) => {
            let remaining = file.size;
            Body::File { file, off: 0, remaining }
        }
    };
    qc.outs.insert(id, OutStream { pending, pos: 0, body });
    pump_out(qc, id);
}

/// An error response generated inside the engine (no `Date` header).
fn start_error(qc: &mut QConn, id: StreamId, status: u16) {
    let body = crate::http::error_body(status);
    let resp = H2Response {
        status,
        headers: vec![
            (b"server".to_vec(), b"Vajra".to_vec()),
            (b"content-type".to_vec(), b"text/plain; charset=utf-8".to_vec()),
            (b"content-length".to_vec(), body.len().to_string().into_bytes()),
        ],
        body: H2Body::Mem(body.to_vec()),
    };
    start_out(qc, id, resp);
}

/// Write as much of the stream's response as flow control allows.
fn pump_out(qc: &mut QConn, id: StreamId) {
    let Some(mut o) = qc.outs.remove(&id) else { return };
    loop {
        if o.pos < o.pending.len() {
            match qc.conn.send_stream(id).write(&o.pending[o.pos..]) {
                Ok(n) => o.pos += n,
                Err(WriteError::Blocked) => {
                    qc.outs.insert(id, o); // resumes on StreamEvent::Writable
                    return;
                }
                Err(_) => return, // peer stopped the stream, or it is closed
            }
            continue;
        }
        o.pending.clear();
        o.pos = 0;
        match o.refill() {
            Fill::More => {}
            Fill::Done => {
                let _ = qc.conn.send_stream(id).finish();
                return;
            }
            Fill::Error => {
                let _ = qc.conn.send_stream(id).reset(vi(h3::H3_INTERNAL_ERROR));
                return;
            }
        }
    }
}

// ───────────────────────── the engine ─────────────────────────

pub struct Quic {
    endpoint: Endpoint,
    conns: HashMap<ConnectionHandle, QConn>,
    dirty: HashSet<ConnectionHandle>,
    /// (deadline, generation) -> connection; the earliest entry is the next timer.
    timers: BTreeMap<(Instant, u64), ConnectionHandle>,
    next_gen: u64,
    out: Vec<Datagram>,
    ready: Vec<Ready>,
    scratch: Vec<u8>,
    dec: qpack::Decoder,
    cfg: QuicConfig,
    draining: bool,
    pub stats: QuicStats,
}

impl Quic {
    pub fn new(cfg: QuicConfig, server: Arc<ServerConfig>) -> Self {
        Self {
            endpoint: Endpoint::new(Arc::new(EndpointConfig::default()), Some(server), false, None),
            conns: HashMap::new(),
            dirty: HashSet::new(),
            timers: BTreeMap::new(),
            next_gen: 1,
            out: Vec::new(),
            ready: Vec::new(),
            scratch: Vec::with_capacity(2048),
            dec: qpack::Decoder::new(h3::MAX_FIELD_SECTION),
            cfg,
            draining: false,
            stats: QuicStats::default(),
        }
    }

    /// Swap the TLS identity for *new* connections (certificate reload).
    pub fn set_server_config(&mut self, server: Arc<ServerConfig>) {
        self.endpoint.set_server_config(Some(server));
    }

    pub fn connections(&self) -> usize {
        self.conns.len()
    }

    /// Connections with unfinished requests or responses.
    pub fn busy(&self) -> bool {
        self.conns.values().any(|c| c.busy())
    }

    fn push_scratch(&mut self, dest: SocketAddr, size: usize) {
        self.out.push(Datagram { dest, data: self.scratch[..size].to_vec() });
    }

    /// Feed one received UDP datagram.
    pub fn recv(&mut self, now: Instant, remote: SocketAddr, data: &[u8]) {
        self.scratch.clear();
        let ev = self.endpoint.handle(now, remote, None, None, BytesMut::from(data), &mut self.scratch);
        match ev {
            None => {}
            Some(DatagramEvent::NewConnection(incoming)) => self.on_incoming(now, incoming),
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                if let Some(qc) = self.conns.get_mut(&ch) {
                    qc.conn.handle_event(ev);
                    self.dirty.insert(ch);
                }
            }
            Some(DatagramEvent::Response(t)) => self.push_scratch(t.destination, t.size),
        }
    }

    fn on_incoming(&mut self, now: Instant, incoming: Incoming) {
        if self.draining || self.conns.len() >= self.cfg.max_conns {
            self.stats.refused += 1;
            let t = self.endpoint.refuse(incoming, &mut self.scratch);
            self.push_scratch(t.destination, t.size);
            return;
        }
        if self.cfg.retry && incoming.may_retry() && !incoming.remote_address_validated() {
            if let Ok(t) = self.endpoint.retry(incoming, &mut self.scratch) {
                self.stats.retries_sent += 1;
                self.push_scratch(t.destination, t.size);
            }
            return;
        }
        match self.endpoint.accept(incoming, now, &mut self.scratch, None) {
            Ok((ch, conn)) => {
                let gen = self.next_gen;
                self.next_gen += 1;
                let peer = conn.remote_address();
                self.stats.conns_accepted += 1;
                self.conns.insert(
                    ch,
                    QConn {
                        conn,
                        handle: ch,
                        gen,
                        peer,
                        reqs: HashMap::new(),
                        unis: HashMap::new(),
                        outs: HashMap::new(),
                        pending: 0,
                        ctl: None,
                        accepted_bidi: 0,
                        draining: false,
                        goaway_sent: false,
                        closing: false,
                        timer: None,
                    },
                );
                self.dirty.insert(ch);
            }
            Err(e) => {
                if let Some(t) = e.response {
                    self.push_scratch(t.destination, t.size);
                }
            }
        }
    }

    /// Fire every expired connection timer.
    pub fn on_timeout(&mut self, now: Instant) {
        loop {
            let Some((&(when, g), &ch)) = self.timers.iter().next() else { break };
            if when > now {
                break;
            }
            self.timers.remove(&(when, g));
            if let Some(qc) = self.conns.get_mut(&ch) {
                qc.timer = None;
                qc.conn.handle_timeout(now);
                self.dirty.insert(ch);
            }
        }
        self.flush(now);
    }

    pub fn next_timeout(&self) -> Option<Instant> {
        self.timers.keys().next().map(|(t, _)| *t)
    }

    /// Process everything that changed since the last flush.
    pub fn flush(&mut self, now: Instant) {
        let dirty: Vec<ConnectionHandle> = self.dirty.drain().collect();
        for ch in dirty {
            self.drive(ch, now);
        }
    }

    pub fn take_requests(&mut self) -> Vec<Ready> {
        std::mem::take(&mut self.ready)
    }

    pub fn take_datagrams(&mut self) -> Vec<Datagram> {
        std::mem::take(&mut self.out)
    }

    /// Answer a request previously returned by [`take_requests`](Self::take_requests).
    /// Silently ignored if the connection is gone.
    pub fn respond(&mut self, id: QConnId, stream: StreamId, resp: H2Response) {
        let Some(qc) = self.conns.get_mut(&id.handle) else { return };
        if qc.gen != id.gen {
            return;
        }
        qc.pending = qc.pending.saturating_sub(1);
        if !qc.closing {
            start_out(qc, stream, resp);
        }
        self.dirty.insert(id.handle);
    }

    /// Begin a graceful shutdown: refuse new connections and requests, send
    /// GOAWAY, and close each connection once its work is done.
    pub fn begin_drain(&mut self) {
        self.draining = true;
        for (ch, qc) in self.conns.iter_mut() {
            qc.draining = true;
            self.dirty.insert(*ch);
        }
    }

    /// Immediately close every connection (`H3_NO_ERROR`) and queue the closes.
    pub fn close_all(&mut self, now: Instant) {
        for (ch, qc) in self.conns.iter_mut() {
            close_conn(qc, now, h3::H3_NO_ERROR);
            self.dirty.insert(*ch);
        }
        self.flush(now);
    }

    // ───────────────────────── driving one connection ─────────────────────────

    fn drive(&mut self, ch: ConnectionHandle, now: Instant) {
        let Some(mut qc) = self.conns.remove(&ch) else { return };
        let mut drained = false;

        'outer: loop {
            let mut progress = false;

            // Events for the endpoint (new CIDs, drained, ...).
            while let Some(ev) = qc.conn.poll_endpoint_events() {
                progress = true;
                let is_drained = ev.is_drained();
                if let Some(ce) = self.endpoint.handle_event(ch, ev) {
                    qc.conn.handle_event(ce);
                }
                if is_drained {
                    drained = true;
                    break 'outer;
                }
            }

            // Application events.
            while let Some(ev) = qc.conn.poll() {
                progress = true;
                match ev {
                    Event::Connected => self.open_control(&mut qc),
                    Event::ConnectionLost { .. } => {
                        qc.closing = true;
                        qc.reqs.clear();
                        qc.outs.clear();
                    }
                    Event::Stream(StreamEvent::Opened { .. }) => {}
                    Event::Stream(StreamEvent::Readable { id }) => self.on_readable(&mut qc, id, now),
                    Event::Stream(StreamEvent::Writable { id }) => pump_out(&mut qc, id),
                    Event::Stream(StreamEvent::Stopped { id, .. }) => {
                        qc.outs.remove(&id);
                    }
                    Event::Stream(StreamEvent::Available { dir: Dir::Uni }) => self.open_control(&mut qc),
                    _ => {}
                }
            }
            self.accept_streams(&mut qc, now);

            // Graceful drain: GOAWAY first, close when idle.
            if qc.draining && !qc.closing {
                if !qc.goaway_sent {
                    if let Some(ctl) = qc.ctl {
                        let mut f = Vec::new();
                        h3::goaway_frame(qc.accepted_bidi * 4, &mut f);
                        let _ = qc.conn.send_stream(ctl).write(&f);
                        qc.goaway_sent = true;
                        progress = true;
                    }
                }
                if !qc.busy() {
                    close_conn(&mut qc, now, h3::H3_NO_ERROR);
                    progress = true;
                }
            }

            // Datagrams to send.
            loop {
                self.scratch.clear();
                match qc.conn.poll_transmit(now, 1, &mut self.scratch) {
                    Some(t) => {
                        progress = true;
                        let size = t.size;
                        self.push_scratch(t.destination, size);
                    }
                    None => break,
                }
            }

            if !progress {
                break;
            }
        }

        if let Some(key) = qc.timer.take() {
            self.timers.remove(&key);
        }
        if drained || qc.conn.is_drained() {
            self.stats.conns_closed += 1;
            return; // dropped
        }
        if let Some(when) = qc.conn.poll_timeout() {
            let key = (when, self.next_gen);
            self.next_gen += 1;
            self.timers.insert(key, ch);
            qc.timer = Some(key);
        }
        self.conns.insert(ch, qc);
    }

    /// Open our HTTP/3 control stream and send SETTINGS (once).
    fn open_control(&mut self, qc: &mut QConn) {
        if qc.ctl.is_some() || qc.closing {
            return;
        }
        let Some(id) = qc.conn.streams().open(Dir::Uni) else { return }; // retried on Available
        qc.ctl = Some(id);
        let pre = h3::control_stream_preface();
        let _ = qc.conn.send_stream(id).write(&pre);
    }

    fn accept_streams(&mut self, qc: &mut QConn, now: Instant) {
        if qc.closing {
            return;
        }
        loop {
            let Some(id) = qc.conn.streams().accept(Dir::Bi) else { break };
            qc.accepted_bidi += 1;
            if qc.draining {
                let _ = qc.conn.recv_stream(id).stop(vi(h3::H3_REQUEST_REJECTED));
                let _ = qc.conn.send_stream(id).reset(vi(h3::H3_REQUEST_REJECTED));
                continue;
            }
            qc.reqs.insert(id, RequestStream::new(self.cfg.max_body));
            self.on_readable(qc, id, now);
        }
        loop {
            let Some(id) = qc.conn.streams().accept(Dir::Uni) else { break };
            qc.unis.insert(id, UniStream::new());
            self.on_readable(qc, id, now);
        }
    }

    fn on_readable(&mut self, qc: &mut QConn, id: StreamId, now: Instant) {
        if qc.closing {
            return;
        }
        if qc.reqs.contains_key(&id) {
            self.read_request(qc, id, now);
        } else if qc.unis.contains_key(&id) {
            self.read_uni(qc, id, now);
        }
    }

    fn read_request(&mut self, qc: &mut QConn, id: StreamId, now: Instant) {
        let (data, fin, reset) = read_all(&mut qc.conn, id);
        if reset.is_some() {
            qc.reqs.remove(&id);
            return;
        }
        let Some(rs) = qc.reqs.get_mut(&id) else { return };
        match rs.feed(&data, fin, &mut self.dec) {
            Ok(None) => {}
            Ok(Some(req)) => {
                qc.reqs.remove(&id);
                qc.pending += 1;
                self.stats.requests += 1;
                self.ready.push(Ready { id: QConnId { handle: qc.handle, gen: qc.gen }, stream: id, req, peer: qc.peer });
            }
            Err(H3Err::Conn(code)) => {
                self.stats.protocol_errors += 1;
                close_conn(qc, now, code);
            }
            Err(H3Err::Stream(code)) => {
                qc.reqs.remove(&id);
                let _ = qc.conn.recv_stream(id).stop(vi(code));
                let _ = qc.conn.send_stream(id).reset(vi(code));
            }
            Err(H3Err::TooLarge) => {
                qc.reqs.remove(&id);
                let _ = qc.conn.recv_stream(id).stop(vi(h3::H3_NO_ERROR));
                start_error(qc, id, 413);
            }
        }
    }

    fn read_uni(&mut self, qc: &mut QConn, id: StreamId, now: Instant) {
        let (data, fin, reset) = read_all(&mut qc.conn, id);
        let Some(us) = qc.unis.get_mut(&id) else { return };
        if let Err(code) = us.feed(&data) {
            self.stats.protocol_errors += 1;
            close_conn(qc, now, code);
            return;
        }
        let kind = us.kind();
        if matches!(kind, Some(UniKind::Control | UniKind::QpackEncoder | UniKind::QpackDecoder))
            && (fin || reset.is_some())
        {
            // Closing a critical stream is a connection error (RFC 9114 §6.2.1).
            self.stats.protocol_errors += 1;
            close_conn(qc, now, h3::H3_CLOSED_CRITICAL_STREAM);
        } else if kind == Some(UniKind::Ignored) {
            let _ = qc.conn.recv_stream(id).stop(vi(h3::H3_NO_ERROR));
            qc.unis.remove(&id);
        } else if fin || reset.is_some() {
            qc.unis.remove(&id);
        }
    }
}
