//! The per-core io_uring event loop.
//!
//! One `Worker` owns *everything* it touches: ring, listeners, slab pool,
//! connection table, TLS state, open-file cache, response cache, pipe pool,
//! upstream pools and balancers, metrics, access-log buffer, date cache.
//! Nothing is shared with other cores. The only way in from outside is the
//! control channel (see `control.rs`), which the ring itself waits on.
//!
//! ## Layers of a connection
//!
//! ```text
//!  transport   plain TCP            | TLS (rustls, sans-I/O)
//!  protocol    HTTP/1.1             | HTTP/1.1 or HTTP/2 (chosen by ALPN)
//!  body source memory | file splice (plain h1) | file read (TLS h1, h2) | cache | upstream
//! ```
//!
//! ## Invariant: exactly one operation in flight per connection
//! A connection has at most one outstanding SQE (a client-side recv/send/
//! splice/read, **or** an upstream connect/send/recv for a proxied request).
//! That keeps buffer ownership trivial: raw pointers handed to the kernel are
//! never touched until the matching CQE is reaped. `user_data` is
//! `[ op: 8 bits | index: 56 bits ]`. Fire-and-forget operations (closing an
//! upstream fd, cancels, linked timeouts) use `OP_IGNORE`. Two worker-level
//! operations also exist: the control-channel `READ` and the access-log `WRITE`.
//!
//! ## Control flow
//! Every completion handler updates connection state and then calls either
//! [`Worker::pump`] (parse buffered input, then decide) or [`Worker::finish`]
//! (just decide). `finish` is the single place that picks the next operation:
//! stage output (encrypting if TLS) -> send; else start a pending file/proxy
//! job; else close; else recv.
//!
//! ## Proxy attempts, failover and health
//! A proxied request is a sequence of *attempts*. Each attempt picks an
//! upstream from the route's balancer (`Balancer::pick` counts it active) and
//! ends with exactly one `release` (success or failure), which also feeds the
//! passive health state. Connect failures, and I/O failures before any response
//! byte on idempotent requests, fail over to a different upstream (at most
//! `MAX_ATTEMPTS` attempts). A stale pooled keep-alive socket is replaced by a
//! fresh connection to the *same* upstream without counting against its health.
//! Every upstream operation is protected by `IOSQE_IO_LINK` + `LINK_TIMEOUT`
//! (a fired timeout surfaces as `-ECANCELED` and becomes a 504 if no upstream
//! is left to try).
//!
//! ## Hot reload and graceful shutdown
//! `Cmd::Reload` builds every new piece (file cache, route table, TLS config,
//! log file) first and swaps only if all of it succeeded. In-flight proxy jobs
//! keep an `Rc` to the route table they started on. `Cmd::Shutdown` cancels the
//! accepts, closes idle connections, sends GOAWAY on HTTP/2, lets busy
//! connections finish, and returns from [`Worker::run`] when none are left or
//! the grace period ends (remaining connections are then abandoned).
//!
//! ## Zero-copy
//! Plain HTTP/1.1 file bodies use `splice` through a pooled pipe. TLS and
//! HTTP/2 must frame/encrypt in user space, so those bodies are read with
//! `IORING_OP_READ` into a per-connection chunk buffer. kTLS would restore
//! zero-copy for TLS.

use crate::arena::{PoolBuf, SlabPool};
use crate::cache::{self, Cache, CacheMode, CachedResponse};
use crate::config::{Dynamic, StaticSettings, UpAddr};
use crate::fastcgi;
use crate::control::{Cmd, Inbox, Snapshot};
use crate::date::{DateCache, DATE_LEN};
use crate::h2::{FileRead, H2Conn, FILE_CHUNK};
use crate::http::{self, Action, Ctx};
use crate::observe::{Http, Observer};
use crate::proxy::{self, Chunked, Framing, HeadParse, ProxySpec, ProxyState, ReqParts, RespHead};
use crate::router::{self, Reply};
use crate::static_files::{FileCache, OpenFile};
use crate::sys;
use crate::tls;
use crate::quic::{QConnId, QuicConfig};
use quinn_proto::StreamId;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use rustls::{ServerConfig, ServerConnection};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::fd::{IntoRawFd, RawFd};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

const OP_SHIFT: u64 = 56;
const IDX_MASK: u64 = (1 << OP_SHIFT) - 1;
const OP_ACCEPT: u64 = 1;
const OP_RECV: u64 = 2;
const OP_SEND: u64 = 3;
const OP_CLOSE: u64 = 4;
const OP_SPLICE_IN: u64 = 5;
const OP_SPLICE_OUT: u64 = 6;
const OP_FILE_READ: u64 = 7;
const OP_UP_CONNECT: u64 = 8;
const OP_UP_SEND: u64 = 9;
const OP_UP_RECV: u64 = 10;
const OP_IGNORE: u64 = 11;
const OP_CONTROL: u64 = 12;
const OP_LOG: u64 = 13;
const OP_T_URECV: u64 = 14;
const OP_T_USEND: u64 = 15;
const OP_Q_RECV: u64 = 16;
const OP_Q_SEND: u64 = 17;
const OP_Q_TIMER: u64 = 18;

/// Bytes moved per file->pipe splice.
const SPLICE_CHUNK: u32 = 128 * 1024;
const PIPE_SIZE: libc::c_int = 256 * 1024;
const MAX_POOLED_PIPES: usize = 256;
/// Bytes requested per upstream recv.
const UP_RECV_CHUNK: usize = 16 * 1024;
/// Upper bound on buffered plaintext per connection (HTTP/2 frames, h1 heads+bodies).
const MAX_INPUT: usize = 8 * 1024 * 1024;
/// Upstream attempts per request (first try + failovers).
const MAX_ATTEMPTS: u32 = 3;
/// WebSocket tunnel: upstream receive buffer, and the per-direction backlog
/// at which the opposite side stops being read (back-pressure).
const TUNNEL_BUF: usize = 16 * 1024;
const TUNNEL_HIGH_WATER: usize = 256 * 1024;
/// Access-log bytes allowed to pile up while a write is in flight.
const MAX_LOG_BACKLOG: usize = 8 * 1024 * 1024;

#[inline(always)]
fn user_data(op: u64, idx: usize) -> u64 {
    (op << OP_SHIFT) | idx as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub ring_entries: u32,
    /// Per-connection receive staging buffer (rounded up to 64).
    pub read_buf_size: usize,
    pub max_conns: usize,
    /// Largest buffered request body (proxy routes, HTTP/2 uploads).
    pub max_body_bytes: usize,
    /// Largest buffered upstream response.
    pub max_proxy_response_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ring_entries: 1024,
            read_buf_size: 8 * 1024,
            max_conns: 65_536,
            max_body_bytes: 1024 * 1024,
            max_proxy_response_bytes: 16 * 1024 * 1024,
        }
    }
}

/// A listening socket owned by the caller; `tls` selects the transport.
#[derive(Clone, Copy, Debug)]
pub struct Listener {
    pub fd: RawFd,
    pub tls: bool,
}

// ───────────────────────── per-connection state ─────────────────────────

/// File body of an HTTP/1.1 response in progress.
struct Transfer {
    file: Rc<OpenFile>,
    off: u64,
    remaining: u64,
    /// Plain (splice) mode only: bytes sitting in the pipe.
    in_pipe: u32,
    pipe: Option<(RawFd, RawFd)>,
}

/// An established WebSocket tunnel. The two sockets are plain byte pipes to
/// each other; frames are never parsed. Unlike every other connection state a
/// tunnel has up to four operations in flight (client recv/send, upstream
/// recv/send), each with its own `user_data` op code.
struct Tunnel {
    up_fd: RawFd,
    /// Client -> upstream bytes being sent (address-stable while `usend`) ...
    c2u: Vec<u8>,
    c2u_pos: usize,
    /// ... and bytes read from the client meanwhile.
    c2u_next: Vec<u8>,
    /// Upstream receive buffer (address-stable while `urecv`).
    ubuf: Vec<u8>,
    csend: bool,
    urecv: bool,
    usend: bool,
    client_eof: bool,
    up_eof: bool,
    /// `shutdown(SHUT_WR)` was issued on the upstream after the client finished.
    up_shut: bool,
    /// Upstream finished: flushing the last bytes (and TLS close_notify) to the client.
    closing: bool,
    /// Both sockets were shut down; the tunnel is torn down when nothing is in flight.
    dying: bool,
}

/// A request from an HTTP/3 stream being served by the proxy machinery in a
/// pseudo connection slot (no socket of its own).
#[derive(Clone, Copy)]
struct QReq {
    id: QConnId,
    stream: StreamId,
}

enum Proto {
    /// HTTP/3 request in a pseudo slot; the response goes back to the QUIC engine.
    Quic(QReq),
    /// TLS handshake still running; protocol not known yet.
    Pending,
    Http1,
    H2(Box<H2Conn>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PStage {
    Idle,
    Connecting,
    Sending,
    Receiving,
}

enum Prog {
    More,
    Done,
    Bad,
}

struct ProxyJob {
    /// The route table this request started on (survives hot reloads).
    state: Rc<ProxyState>,
    route: usize,
    /// Upstream of the current attempt; meaningful while `picked`.
    up: usize,
    /// The balancer counts this job as active on `up` until `end_attempt`.
    picked: bool,
    /// Bitmask of upstreams already tried for this request.
    tried: u64,
    attempts: u32,
    stale_retried: bool,
    hash: u64,
    client_ip: Option<IpAddr>,
    /// Serialised upstream request (identical for every upstream).
    req: Vec<u8>,
    sent: usize,
    fd: RawFd,
    /// The upstream socket came from the idle pool (may be stale).
    reused: bool,
    stage: PStage,
    /// Raw upstream response bytes.
    resp: Vec<u8>,
    recv_base: usize,
    head: Option<RespHead>,
    chunked: Chunked,
    head_req: bool,
    idempotent: bool,
    /// HTTP/2 stream awaiting the answer (0 for HTTP/1.1).
    stream: u32,
    cache: CacheMode,
    method: String,
    target: String,
    t0: Instant,
    /// WebSocket handshake: a `101` answer switches the connection to a tunnel.
    upgrade: bool,
    /// FastCGI (PHP-FPM) request: the upstream stream is decoded here and
    /// rewritten into an HTTP/1.1 response before the normal proxy path sees it.
    fcgi: Option<Box<fastcgi::Decoder>>,
}

impl ProxyJob {
    fn new(spec: ProxySpec, state: Rc<ProxyState>, client_ip: Option<IpAddr>, stream: u32) -> Self {
        Self {
            state,
            route: spec.route,
            up: 0,
            picked: false,
            tried: 0,
            attempts: 0,
            stale_retried: false,
            hash: proxy::ip_hash(client_ip),
            client_ip,
            req: spec.request,
            sent: 0,
            fd: -1,
            reused: false,
            stage: PStage::Idle,
            resp: Vec::new(),
            recv_base: 0,
            head: None,
            chunked: Chunked::default(),
            head_req: spec.head,
            idempotent: spec.idempotent,
            stream,
            cache: spec.cache,
            method: spec.method,
            target: spec.target,
            t0: Instant::now(),
            upgrade: spec.upgrade,
            fcgi: spec.fcgi.then(|| Box::new(fastcgi::Decoder::new())),
        }
    }

    /// Ask the balancer for an untried upstream. On success the attempt is
    /// counted active until [`end_attempt`](Self::end_attempt).
    fn pick_next(&mut self, now: u64) -> bool {
        let choice = self.state.bal.borrow_mut()[self.route].pick(now, self.hash, self.tried);
        match choice {
            Some(i) => {
                self.up = i;
                self.picked = true;
                self.tried |= 1u64 << i;
                self.attempts += 1;
                true
            }
            None => false,
        }
    }

    /// Release the current pick (exactly once per successful `pick_next`).
    fn end_attempt(&mut self, ok: bool, now: u64) {
        if self.picked {
            self.state.bal.borrow_mut()[self.route].release(self.up, ok, now);
            self.picked = false;
        }
    }

    fn reset_attempt(&mut self) {
        self.sent = 0;
        self.fd = -1;
        self.reused = false;
        self.stage = PStage::Idle;
        self.resp.clear();
        self.recv_base = 0;
        self.head = None;
        self.chunked = Chunked::default();
        if let Some(d) = self.fcgi.as_mut() {
            d.reset();
        }
        self.stale_retried = false;
        self.t0 = Instant::now();
    }

    /// Examine the buffered upstream bytes: is the response complete?
    fn progress(&mut self, max_resp: usize) -> Prog {
        if self.resp.len() > max_resp {
            return Prog::Bad;
        }
        if self.head.is_none() {
            match proxy::parse_response_head(&self.resp, self.head_req) {
                HeadParse::Partial => return Prog::More,
                HeadParse::Bad => return Prog::Bad,
                HeadParse::Done(h) => self.head = Some(h),
            }
        }
        let head = self.head.as_ref().expect("head parsed");
        let raw = &self.resp[head.head_len..];
        match head.framing {
            Framing::None => Prog::Done,
            Framing::Length(n) => {
                if raw.len() >= n {
                    Prog::Done
                } else {
                    Prog::More
                }
            }
            Framing::Chunked => match self.chunked.advance(raw, max_resp) {
                Err(()) => Prog::Bad,
                Ok(()) => {
                    if self.chunked.done {
                        Prog::Done
                    } else {
                        Prog::More
                    }
                }
            },
            Framing::UntilClose => Prog::More,
        }
    }
}

/// `align(64)`: each connection record starts on its own cache line.
#[repr(align(64))]
struct Conn {
    fd: RawFd, // -1 while the slot is free
    /// Receive staging buffer carved from the slab pool (address-stable).
    rbuf: PoolBuf,
    /// A RECV is the operation currently in flight (so it can be cancelled).
    in_recv: bool,
    /// Plaintext received but not yet consumed.
    input: Vec<u8>,
    /// Plaintext response bytes waiting to be encrypted/sent.
    out: Vec<u8>,
    /// Bytes ready for the wire (ciphertext for TLS); `npos..` is unsent.
    net: Vec<u8>,
    npos: usize,
    tls: Option<Box<ServerConnection>>,
    proto: Proto,
    close_after: bool,
    peer_eof: bool,
    sent_close_notify: bool,
    xfer: Option<Transfer>,
    proxy: Option<Box<ProxyJob>>,
    peer: Option<IpAddr>,
    /// `peer` has been looked up (one `getpeername`, only when needed).
    peer_known: bool,
    /// Chunk buffer for `IORING_OP_READ` (TLS HTTP/1.1 bodies and HTTP/2).
    chunk: Vec<u8>,
    pending_read: Option<FileRead>,
    reading_stream: u32,
    tunnel: Option<Box<Tunnel>>,
}

impl Conn {
    fn new(rbuf: PoolBuf) -> Self {
        Self {
            fd: -1,
            rbuf,
            in_recv: false,
            input: Vec::new(),
            out: Vec::with_capacity(1024),
            net: Vec::new(),
            npos: 0,
            tls: None,
            proto: Proto::Http1,
            close_after: false,
            peer_eof: false,
            sent_close_notify: false,
            xfer: None,
            proxy: None,
            peer: None,
            peer_known: false,
            chunk: Vec::new(),
            pending_read: None,
            reading_stream: 0,
            tunnel: None,
        }
    }
}

enum Next {
    Recv,
    Send,
    Splice,
    H1Read,
    H2Read(FileRead),
    Proxy,
    Close,
    Wait,
}

enum Step {
    SpliceIn,
    SpliceOut,
    Done,
}

/// Nothing is being received, produced or sent on this connection.
fn conn_idle(c: &Conn) -> bool {
    c.xfer.is_none()
        && c.proxy.is_none()
        && c.tunnel.is_none()
        && c.out.is_empty()
        && c.npos >= c.net.len()
        && c.pending_read.is_none()
        && match &c.proto {
            Proto::H2(h) => h.is_idle(),
            _ => c.input.is_empty(),
        }
}

// ───────────────────────── access-log sink ─────────────────────────

struct LogWrite {
    buf: Vec<u8>,
    pos: usize,
    /// The fd this write targets (it may be retired by a reload while in flight).
    fd: RawFd,
}

struct LogSink {
    /// -1 = logging disabled.
    fd: RawFd,
    /// We opened it (and must close it); false for stdout.
    owns: bool,
    inflight: Option<LogWrite>,
    /// Replaced fds waiting for their in-flight write to finish.
    retired: Vec<RawFd>,
}

/// `Ok(None)` = disabled, `Some((fd, owned))` otherwise.
fn open_log(path: Option<&str>) -> Result<Option<(RawFd, bool)>, String> {
    match path {
        None => Ok(None),
        Some("-") => Ok(Some((1, false))),
        Some(p) => {
            if let Some(dir) = std::path::Path::new(p).parent() {
                if !dir.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(dir);
                }
            }
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| format!("access_log {p}: {e}"))?;
            Ok(Some((f.into_raw_fd(), true)))
        }
    }
}

pub struct Worker {
    ring: IoUring,
    listeners: Vec<Listener>,
    conns: Vec<Conn>,
    free: Vec<usize>,
    live: usize,
    pool: SlabPool,
    files: Option<FileCache>,
    proxies: Rc<ProxyState>,
    cache: Cache,
    cache_max_object: usize,
    obs: Observer,
    log: LogSink,
    tls_cfg: Option<Arc<ServerConfig>>,
    pipes: Vec<(RawFd, RawFd)>,
    date: DateCache,
    cur_date: [u8; DATE_LEN],
    /// Unix seconds as of the current event-loop batch.
    now: u64,
    batch: Vec<(u64, i32, u32)>,
    multishot_accept: bool,
    cfg: Config,
    // control plane
    id: usize,
    ctl: Option<Inbox>,
    ctl_buf: Box<u64>,
    grace: Duration,
    draining: Option<Instant>,
    /// HTTP/3: UDP socket slots, QUIC engine and timers (see `quic_io`).
    quic: Option<Box<quic_io::QuicRt>>,
}

mod quic_io;

impl Worker {
    /// Convenience for plain-HTTP setups without a control channel.
    pub fn plain(
        listen_fd: RawFd,
        cfg: Config,
        static_cfg: Option<&StaticSettings>,
    ) -> io::Result<Self> {
        let d = Dynamic { static_files: static_cfg.cloned(), ..Dynamic::default() };
        Self::new(&[Listener { fd: listen_fd, tls: false }], cfg, &d, None)
    }

    /// Build the ring. **Must be called on the thread that will run the loop**
    /// (`SINGLE_ISSUER` binds the ring to its creating thread).
    pub fn new(
        listeners: &[Listener],
        cfg: Config,
        dynamic: &Dynamic,
        tls_cfg: Option<Arc<ServerConfig>>,
    ) -> io::Result<Self> {
        if listeners.iter().any(|l| l.tls) && tls_cfg.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TLS listener without TLS config"));
        }

        let mut builder = IoUring::builder();
        builder.setup_coop_taskrun().setup_single_issuer();
        let ring = match builder.build(cfg.ring_entries) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("vajra: optimised ring flags unavailable ({e}); using defaults");
                IoUring::new(cfg.ring_entries)?
            }
        };

        let mut obs = Observer::new();
        let proxies = ProxyState::new(&dynamic.proxies, dynamic.cache.max_object_bytes, &mut obs.m);
        let log = open_log(dynamic.access_log.as_deref()).map_err(io::Error::other)?;
        obs.log_enabled = log.is_some();
        let (log_fd, log_owns) = log.unwrap_or((-1, false));

        Ok(Self {
            ring,
            listeners: listeners.to_vec(),
            conns: Vec::new(),
            free: Vec::new(),
            live: 0,
            pool: SlabPool::new(cfg.read_buf_size, cfg.max_conns)?,
            files: dynamic.static_files.as_ref().map(FileCache::new),
            proxies: Rc::new(proxies),
            cache: Cache::new(&dynamic.cache),
            cache_max_object: dynamic.cache.max_object_bytes,
            obs,
            log: LogSink { fd: log_fd, owns: log_owns, inflight: None, retired: Vec::new() },
            tls_cfg,
            pipes: Vec::new(),
            date: DateCache::new(),
            cur_date: [b' '; DATE_LEN],
            now: 0,
            batch: Vec::with_capacity(cfg.ring_entries as usize * 2),
            multishot_accept: true,
            cfg,
            id: 0,
            ctl: None,
            ctl_buf: Box::new(0),
            grace: Duration::from_secs(5),
            draining: None,
            quic: None,
        })
    }

    /// Connect this worker to the control plane (metrics, reload, shutdown).
    pub fn attach_control(&mut self, id: usize, inbox: Inbox, grace: Duration) {
        self.id = id;
        self.ctl = Some(inbox);
        self.grace = grace;
    }

    /// Run the event loop. Returns `Ok` after a graceful shutdown, `Err` on a fatal ring error.
    pub fn run(&mut self) -> io::Result<()> {
        for li in 0..self.listeners.len() {
            self.arm_accept(li);
        }
        self.arm_control();
        self.q_arm_all();

        loop {
            self.wait()?;

            self.cur_date = *self.date.get();
            self.now = self.date.now_secs();
            self.obs.now = self.now;
            if let Some(f) = self.files.as_mut() {
                f.set_now(self.now);
            }

            let mut batch = std::mem::take(&mut self.batch);
            batch.clear();
            batch.extend(self.ring.completion().map(|c| (c.user_data(), c.result(), c.flags())));

            for &(ud, res, flags) in &batch {
                let op = ud >> OP_SHIFT;
                let idx = (ud & IDX_MASK) as usize;
                match op {
                    OP_ACCEPT => self.on_accept(idx, res, flags),
                    OP_RECV => self.on_recv(idx, res),
                    OP_SEND => self.on_send(idx, res),
                    OP_SPLICE_IN => self.on_splice_in(idx, res),
                    OP_SPLICE_OUT => self.on_splice_out(idx, res),
                    OP_FILE_READ => self.on_file_read(idx, res),
                    OP_UP_CONNECT => self.on_up_connect(idx, res),
                    OP_UP_SEND => self.on_up_send(idx, res),
                    OP_UP_RECV => self.on_up_recv(idx, res),
                    OP_CLOSE => self.on_close(idx),
                    OP_CONTROL => self.on_control(res),
                    OP_LOG => self.on_log(res),
                    OP_T_URECV => self.on_t_urecv(idx, res),
                    OP_T_USEND => self.on_t_usend(idx, res),
                    OP_Q_RECV => self.on_q_recv(idx, res),
                    OP_Q_SEND => self.on_q_send(idx, res),
                    OP_Q_TIMER => self.on_q_timer(idx),
                    OP_IGNORE => {}
                    _ => unreachable!("corrupt user_data: {ud:#x}"),
                }
            }
            self.batch = batch;

            self.q_after_batch();
            self.flush_log();
            if let Some(deadline) = self.draining {
                if (self.live == 0 && !self.q_busy()) || Instant::now() >= deadline {
                    break;
                }
            }
        }

        self.finalize();
        Ok(())
    }

    /// Submit queued SQEs and sleep until a completion arrives (or, while
    /// draining, until the grace deadline).
    fn wait(&mut self) -> io::Result<()> {
        let res = match self.draining {
            None => self.ring.submit_and_wait(1),
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                let ts = types::Timespec::new().sec(left.as_secs()).nsec(left.subsec_nanos());
                let args = types::SubmitArgs::new().timespec(&ts);
                self.ring.submitter().submit_with_args(1, &args)
            }
        };
        match res {
            Ok(_) => Ok(()),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EINTR) | Some(libc::EBUSY) | Some(libc::ETIME)
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    // ───────────────────────── control plane ─────────────────────────

    fn arm_control(&mut self) {
        let Some(fd) = self.ctl.as_ref().map(|i| i.fd()) else { return };
        let ptr = &mut *self.ctl_buf as *mut u64 as *mut u8;
        // SAFETY: `ctl_buf` is heap-allocated and owned by the worker; only one
        // control READ is ever in flight.
        let entry = opcode::Read::new(types::Fd(fd), ptr, 8)
            .build()
            .user_data(user_data(OP_CONTROL, 0));
        push(&mut self.ring, entry);
    }

    fn on_control(&mut self, res: i32) {
        if res < 0 && res != -libc::EINTR {
            eprintln!("vajra[{}]: control channel read failed: {}", self.id, io::Error::from_raw_os_error(-res));
            return; // do not re-arm: a persistent error would spin
        }
        while let Some(cmd) = self.ctl.as_ref().and_then(|i| i.try_recv()) {
            self.handle_cmd(cmd);
        }
        self.arm_control();
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Scrape(tx) => {
                let _ = tx.send(self.snapshot());
            }
            Cmd::Reload { dynamic, ack } => {
                let r = self.apply_reload(&dynamic);
                match &r {
                    Ok(()) => self.obs.m.reloads_ok += 1,
                    Err(e) => {
                        self.obs.m.reloads_failed += 1;
                        eprintln!("vajra[{}]: reload rejected: {e}", self.id);
                    }
                }
                let _ = ack.send(r);
            }
            Cmd::Shutdown => self.begin_drain(),
        }
    }

    fn snapshot(&self) -> Snapshot {
        let mut m = self.obs.m.clone();
        for u in m.ups.iter_mut() {
            u.active = 0;
        }
        {
            let bal = self.proxies.bal.borrow();
            for (r, row) in self.proxies.mids.iter().enumerate() {
                for (u, &mi) in row.iter().enumerate() {
                    m.ups[mi].active += bal[r].active(u) as i64;
                }
            }
        }
        self.q_fill_metrics(&mut m);
        Snapshot {
            worker: self.id,
            metrics: m,
            active_conns: self.live,
            cache: self.cache.stats,
            cache_entries: self.cache.len(),
            cache_bytes: self.cache.bytes(),
        }
    }

    /// Build everything first, swap only if all of it worked.
    fn apply_reload(&mut self, d: &Dynamic) -> Result<(), String> {
        if self.draining.is_some() {
            return Err("worker is shutting down".into());
        }
        let files = d.static_files.as_ref().map(FileCache::new);
        let new_tls = match (&d.tls, self.listeners.iter().any(|l| l.tls)) {
            (Some(p), true) => Some(tls::build_server_config(&p.cert, &p.key)?),
            _ => None,
        };
        let new_quic = self.q_build_server_config(d)?;
        let log = open_log(d.access_log.as_deref())?; // re-opens the file: log rotation via reload
        let state = ProxyState::new(&d.proxies, d.cache.max_object_bytes, &mut self.obs.m);

        self.files = files;
        self.proxies = Rc::new(state); // the old state lives on in in-flight jobs
        if let Some(t) = new_tls {
            self.tls_cfg = Some(t);
        }
        self.q_set_server_config(new_quic);
        // Cached entries were fetched through the old routes; start clean.
        self.cache = Cache::new(&d.cache);
        self.cache_max_object = d.cache.max_object_bytes;
        self.set_log(log);
        Ok(())
    }

    fn begin_drain(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.grace);
        self.q_begin_drain();

        for li in 0..self.listeners.len() {
            let e = opcode::AsyncCancel::new(user_data(OP_ACCEPT, li))
                .build()
                .user_data(user_data(OP_IGNORE, 0));
            push(&mut self.ring, e);
        }

        for idx in 0..self.conns.len() {
            let c = &mut self.conns[idx];
            if c.fd < 0 {
                continue;
            }
            let idle = conn_idle(c);
            if !idle {
                if let Proto::H2(h) = &mut c.proto {
                    h.start_shutdown(&mut c.out); // flushed with the next send
                }
            } else if c.in_recv {
                // Wake the pending RECV; its -ECANCELED completion closes the connection.
                let e = opcode::AsyncCancel::new(user_data(OP_RECV, idx))
                    .build()
                    .user_data(user_data(OP_IGNORE, 0));
                push(&mut self.ring, e);
            }
        }

        // WebSocket tunnels are long-lived by design: a drain ends them
        // (peers see a plain TCP close and are expected to reconnect).
        for idx in 0..self.conns.len() {
            if self.conns[idx].fd >= 0 && self.conns[idx].tunnel.is_some() {
                self.t_kill(idx);
                self.t_advance(idx);
            }
        }
    }

    // ───────────────────────── access log ─────────────────────────

    fn set_log(&mut self, new: Option<(RawFd, bool)>) {
        let (old_fd, old_owns) = (self.log.fd, self.log.owns);
        match new {
            Some((fd, owns)) => {
                self.log.fd = fd;
                self.log.owns = owns;
                self.obs.log_enabled = true;
            }
            None => {
                self.log.fd = -1;
                self.log.owns = false;
                self.obs.log_enabled = false;
                self.obs.log.clear();
            }
        }
        if old_fd >= 0 && old_owns {
            if self.log.inflight.as_ref().is_some_and(|w| w.fd == old_fd) {
                self.log.retired.push(old_fd);
            } else {
                // SAFETY: we opened this fd and nothing is using it.
                unsafe {
                    libc::close(old_fd);
                }
            }
        }
    }

    fn flush_log(&mut self) {
        if self.log.inflight.is_some() || self.log.fd < 0 {
            if self.obs.log.len() > MAX_LOG_BACKLOG {
                // The disk cannot keep up: shed log lines rather than memory.
                self.obs.m.log_write_errors += 1;
                self.obs.log.clear();
            }
            return;
        }
        if self.obs.log.is_empty() {
            return;
        }
        let buf = std::mem::take(&mut self.obs.log);
        self.log.inflight = Some(LogWrite { buf, pos: 0, fd: self.log.fd });
        self.submit_log();
    }

    fn submit_log(&mut self) {
        let w = self.log.inflight.as_ref().expect("log write in flight");
        // SAFETY: `buf` is not touched until the WRITE completes.
        let ptr = unsafe { w.buf.as_ptr().add(w.pos) };
        let len = (w.buf.len() - w.pos) as u32;
        let entry = opcode::Write::new(types::Fd(w.fd), ptr, len)
            .offset(u64::MAX) // current position / append
            .build()
            .user_data(user_data(OP_LOG, 0));
        push(&mut self.ring, entry);
    }

    fn on_log(&mut self, res: i32) {
        let Some(w) = self.log.inflight.as_mut() else { return };
        if res > 0 {
            w.pos += res as usize;
            if w.pos < w.buf.len() {
                self.submit_log();
                return;
            }
        } else if res != -libc::EINTR {
            self.obs.m.log_write_errors += 1;
        } else {
            self.submit_log();
            return;
        }
        self.log.inflight = None;
        for fd in self.log.retired.drain(..) {
            // SAFETY: retired fds were opened by us and their last write finished.
            unsafe {
                libc::close(fd);
            }
        }
        self.flush_log();
    }

    /// Shutdown path: let the last log write land, then flush the rest synchronously.
    fn finalize(&mut self) {
        self.q_finalize();
        while self.log.inflight.is_some() {
            if self.ring.submit_and_wait(1).is_err() {
                break;
            }
            let done: Vec<(u64, i32)> =
                self.ring.completion().map(|c| (c.user_data(), c.result())).collect();
            for (ud, res) in done {
                if ud >> OP_SHIFT == OP_LOG {
                    self.on_log(res);
                }
            }
        }
        if self.log.fd >= 0 && !self.obs.log.is_empty() {
            let buf = std::mem::take(&mut self.obs.log);
            let mut off = 0;
            while off < buf.len() {
                // SAFETY: valid slice, fd owned/valid for the worker's lifetime.
                let n = unsafe {
                    libc::write(self.log.fd, buf[off..].as_ptr() as *const libc::c_void, buf.len() - off)
                };
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
        }
    }

    // ───────────────────────── accept ─────────────────────────

    fn arm_accept(&mut self, li: usize) {
        let fd = types::Fd(self.listeners[li].fd);
        let entry = if self.multishot_accept {
            opcode::AcceptMulti::new(fd).build()
        } else {
            opcode::Accept::new(fd, std::ptr::null_mut(), std::ptr::null_mut()).build()
        }
        .user_data(user_data(OP_ACCEPT, li));
        push(&mut self.ring, entry);
    }

    fn on_accept(&mut self, li: usize, res: i32, flags: u32) {
        if self.draining.is_some() {
            if res >= 0 {
                // Raced with shutdown: refuse the connection.
                unsafe {
                    libc::close(res as RawFd);
                }
            }
            return; // never re-arm while draining
        }
        if res >= 0 {
            let fd = res as RawFd;
            let tls = self.listeners[li].tls;
            match self.alloc(fd, tls) {
                Some(idx) => self.submit_recv(idx),
                None => unsafe {
                    libc::close(fd);
                },
            }
        } else if res == -libc::EINVAL && self.multishot_accept {
            eprintln!("vajra: multishot accept unsupported, falling back to single-shot");
            self.multishot_accept = false;
            for l in 0..self.listeners.len() {
                self.arm_accept(l);
            }
            return;
        } else if res != -libc::ECANCELED {
            eprintln!("vajra: accept failed: {}", io::Error::from_raw_os_error(-res));
            std::thread::sleep(Duration::from_millis(1));
        }

        if !cqueue::more(flags) {
            self.arm_accept(li);
        }
    }

    fn alloc(&mut self, fd: RawFd, tls: bool) -> Option<usize> {
        if self.live >= self.cfg.max_conns {
            return None;
        }
        let tls_conn = if tls {
            let cfg = self.tls_cfg.as_ref()?;
            Some(Box::new(ServerConnection::new(Arc::clone(cfg)).ok()?))
        } else {
            None
        };

        let idx = match self.free.pop() {
            Some(i) => i,
            None => {
                let buf = self.pool.alloc()?;
                self.conns.push(Conn::new(buf));
                self.conns.len() - 1
            }
        };
        let c = &mut self.conns[idx];
        c.fd = fd;
        c.in_recv = false;
        c.input.clear();
        c.out.clear();
        c.net.clear();
        c.npos = 0;
        c.proto = if tls_conn.is_some() { Proto::Pending } else { Proto::Http1 };
        c.tls = tls_conn;
        c.close_after = false;
        c.peer_eof = false;
        c.sent_close_notify = false;
        c.xfer = None;
        c.proxy = None;
        c.peer = None;
        c.peer_known = false;
        c.pending_read = None;
        self.live += 1;
        self.obs.m.conns_accepted += 1;
        Some(idx)
    }

    // ───────────────────────── recv / ingest ─────────────────────────

    fn submit_recv(&mut self, idx: usize) {
        let c = &mut self.conns[idx];
        c.in_recv = true;
        let len = c.rbuf.len() as u32;
        // SAFETY: the slot is stable and untouched until this RECV completes
        // (one op in flight per connection).
        let entry = opcode::Recv::new(types::Fd(c.fd), c.rbuf.as_mut_ptr(), len)
            .build()
            .user_data(user_data(OP_RECV, idx));
        push(&mut self.ring, entry);
    }

    fn on_recv(&mut self, idx: usize, res: i32) {
        self.conns[idx].in_recv = false;
        if self.conns[idx].tunnel.is_some() {
            self.on_t_crecv(idx, res);
            return;
        }
        if res <= 0 {
            self.start_close(idx);
            return;
        }
        let n = res as usize;
        self.obs.m.bytes_in += n as u64;
        let c = &mut self.conns[idx];
        let fast = if c.tls.is_some() {
            if tls_ingest(c, n).is_err() {
                // An alert (if any) is queued in rustls; flush it, then close.
                c.close_after = true;
            }
            0
        } else {
            n
        };
        self.pump(idx, fast);
    }

    /// Parse buffered input with the connection's protocol, then pick the next op.
    /// `fast` > 0 means `rbuf[..fast]` holds unparsed plaintext (plain TCP only).
    fn pump(&mut self, idx: usize, fast: usize) {
        let date = self.cur_date;

        // Choose the protocol once the TLS handshake has finished.
        {
            let c = &mut self.conns[idx];
            if matches!(c.proto, Proto::Pending) {
                if let Some(t) = c.tls.as_ref() {
                    if !t.is_handshaking() {
                        self.obs.m.tls_handshakes += 1;
                        if t.alpn_protocol() == Some(&b"h2"[..]) {
                            let h = H2Conn::new(self.cfg.max_body_bytes, &mut c.out);
                            c.proto = Proto::H2(Box::new(h));
                        } else {
                            c.proto = Proto::Http1;
                        }
                    }
                }
            }
        }

        if !self.conns[idx].close_after {
            let kind = match self.conns[idx].proto {
                Proto::Pending => 0,
                Proto::Http1 => 1,
                Proto::H2(_) => 2,
                Proto::Quic(_) => 0,
            };
            match kind {
                1 => self.h1_step(idx, fast, &date),
                2 => self.h2_step(idx, &date),
                _ => {}
            }
        }

        let c = &mut self.conns[idx];
        if c.peer_eof {
            c.close_after = true;
        }
        self.finish(idx);
    }

    fn h1_step(&mut self, idx: usize, fast: usize, date: &[u8; DATE_LEN]) {
        let need_peer = !self.proxies.table.is_empty() || self.obs.log_enabled;
        let c = &mut self.conns[idx];
        ensure_peer(c, need_peer);
        let secure = c.tls.is_some();

        // Plain TCP fast path: parse straight from the staging buffer when
        // nothing is buffered; only leftovers are copied into `input`.
        let use_rbuf = fast > 0 && c.input.is_empty();
        if fast > 0 && !use_rbuf {
            c.input.extend_from_slice(&c.rbuf.as_slice()[..fast]);
        }

        let mut ctx = Ctx {
            files: self.files.as_mut(),
            proxies: &self.proxies.table,
            cache: &mut self.cache,
            obs: &mut self.obs,
            now: self.now,
            max_body: self.cfg.max_body_bytes,
            secure,
            client_ip: c.peer,
        };
        let outcome = if use_rbuf {
            http::process(&c.rbuf.as_slice()[..fast], &mut c.out, date, &mut ctx)
        } else {
            http::process(&c.input, &mut c.out, date, &mut ctx)
        };

        let consumed = outcome.consumed;
        if use_rbuf {
            if consumed < fast {
                c.input.extend_from_slice(&c.rbuf.as_slice()[consumed..fast]);
            }
        } else if consumed > 0 {
            c.input.drain(..consumed);
        }

        let partial_head = matches!(outcome.action, Action::None);
        match outcome.action {
            Action::File(f) => {
                c.xfer = Some(Transfer { remaining: f.size, file: f, off: 0, in_pipe: 0, pipe: None });
            }
            Action::Proxy(spec) => {
                c.proxy = Some(Box::new(ProxyJob::new(spec, Rc::clone(&self.proxies), c.peer, 0)));
            }
            Action::NeedBody | Action::None => {}
        }

        if outcome.close {
            c.close_after = true;
            c.input.clear();
        } else if partial_head && c.input.len() > http::MAX_HEAD_BYTES {
            http::fail(&mut c.out, &mut self.obs, c.peer, 431, date);
            c.close_after = true;
            c.input.clear();
        }
    }

    fn h2_step(&mut self, idx: usize, date: &[u8; DATE_LEN]) {
        loop {
            let req = {
                let c = &mut self.conns[idx];
                let Proto::H2(h) = &mut c.proto else { return };
                let fed = h.feed(&c.input, &mut c.out);
                c.input.drain(..fed.consumed);
                if fed.fatal {
                    c.close_after = true;
                    c.input.clear();
                    return;
                }
                match h.take_ready() {
                    Some(r) => r,
                    None => return,
                }
            };

            let need_peer = !self.proxies.table.is_empty() || self.obs.log_enabled;
            ensure_peer(&mut self.conns[idx], need_peer);
            let peer = self.conns[idx].peer;

            let path = req.path.split('?').next().unwrap_or("/");
            let head_only = req.method == "HEAD";
            let inm = req
                .headers
                .iter()
                .find(|(n, _)| n == b"if-none-match")
                .map(|(_, v)| v.as_slice());
            let reply = router::route(&req.method, path, inm, self.files.as_mut(), &self.proxies.table);

            if let Some((ri, php_target)) = reply.proxy_parts() {
                let hdrs: Vec<(&[u8], &[u8])> =
                    req.headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
                let cache_on = self.proxies.table.route(ri).cache.is_some();
                let mode = match cache::lookup_for_request(
                    &mut self.cache,
                    cache_on,
                    &req.method,
                    &req.authority,
                    &req.path,
                    &hdrs,
                    self.now,
                ) {
                    cache::Lookup::Hit(hit) => {
                        let bodyless = hit.status == 204 || hit.status == 304;
                        let body = if bodyless { Vec::new() } else { (*hit.body).clone() };
                        let resp = http::h2_proxy_response(hit.status, &hit.headers, body, false, date, Some("HIT"));
                        let bytes = if bodyless { 0 } else { hit.body.len() as u64 };
                        self.obs.response(peer, Http::H2, &req.method, &req.path, hit.status, bytes);
                        let c = &mut self.conns[idx];
                        if let Proto::H2(h) = &mut c.proto {
                            h.respond(req.stream, resp, &mut c.out);
                        }
                        continue;
                    }
                    cache::Lookup::Miss(m) => m,
                };

                let mut spec = proxy::make_spec(
                    &self.proxies.table,
                    ri,
                    &ReqParts {
                        method: &req.method,
                        target: &req.path,
                        host: if req.authority.is_empty() { None } else { Some(req.authority.as_slice()) },
                        headers: &hdrs,
                        body: &req.body,
                        client_ip: peer,
                        secure: true,
                        upgrade: false,
                        php: php_target,
                    },
                );
                spec.cache = mode;
                self.conns[idx].proxy =
                    Some(Box::new(ProxyJob::new(spec, Rc::clone(&self.proxies), peer, req.stream)));
                return; // one proxy job at a time; remaining frames wait in `input`
            }

            let resp = http::h2_response(&reply, head_only, date);
            let (status, bytes) = http::reply_meta(&reply, head_only);
            self.obs.response(peer, Http::H2, &req.method, &req.path, status, bytes);
            let c = &mut self.conns[idx];
            if let Proto::H2(h) = &mut c.proto {
                h.respond(req.stream, resp, &mut c.out);
            }
        }
    }

    // ───────────────────────── deciding the next operation ─────────────────────────

    fn finish(&mut self, idx: usize) {
        let draining = self.draining.is_some();
        let next = {
            let c = &mut self.conns[idx];
            if c.pending_read.is_none() {
                if let Proto::H2(h) = &mut c.proto {
                    c.pending_read = h.poll_output(&mut c.out);
                }
            }
            stage_tx(c);

            if c.npos < c.net.len() {
                Next::Send
            } else if c.xfer.is_some() {
                if c.tls.is_some() {
                    Next::H1Read
                } else {
                    Next::Splice
                }
            } else if let Some(j) = c.proxy.as_ref() {
                if j.stage == PStage::Idle {
                    Next::Proxy
                } else {
                    Next::Wait
                }
            } else if let Some(fr) = c.pending_read.take() {
                Next::H2Read(fr)
            } else if c.close_after || (draining && conn_idle(c)) {
                Next::Close
            } else {
                Next::Recv
            }
        };

        match next {
            Next::Send => self.submit_send(idx),
            Next::Splice => self.start_splice(idx),
            Next::H1Read => self.submit_h1_read(idx),
            Next::H2Read(fr) => self.submit_h2_read(idx, fr),
            Next::Proxy => self.start_proxy(idx),
            Next::Close => self.start_close(idx),
            Next::Recv => self.submit_recv(idx),
            Next::Wait => {}
        }
    }

    // ───────────────────────── send ─────────────────────────

    fn submit_send(&mut self, idx: usize) {
        let c = &mut self.conns[idx];
        // Plain-TCP file bodies follow the headers: let TCP coalesce them.
        let more = if c.xfer.is_some() && c.tls.is_none() { libc::MSG_MORE } else { 0 };
        // SAFETY: `net` is not modified while the SEND is in flight.
        let ptr = unsafe { c.net.as_ptr().add(c.npos) };
        let len = (c.net.len() - c.npos) as u32;
        let entry = opcode::Send::new(types::Fd(c.fd), ptr, len)
            .flags(libc::MSG_NOSIGNAL | more)
            .build()
            .user_data(user_data(OP_SEND, idx));
        push(&mut self.ring, entry);
    }

    fn on_send(&mut self, idx: usize, res: i32) {
        if self.conns[idx].tunnel.is_some() {
            self.on_t_csend(idx, res);
            return;
        }
        if res < 0 {
            self.start_close(idx);
            return;
        }
        self.obs.m.bytes_out += res as u64;
        let drained = {
            let c = &mut self.conns[idx];
            c.npos += res as usize;
            if c.npos < c.net.len() {
                false
            } else {
                c.net.clear();
                c.npos = 0;
                if c.net.capacity() > 256 * 1024 {
                    c.net = Vec::new();
                }
                true
            }
        };
        if drained {
            self.finish(idx);
        } else {
            self.submit_send(idx);
        }
    }

    // ───────────────────────── plain HTTP/1.1 file body (splice) ─────────────────────────

    fn start_splice(&mut self, idx: usize) {
        let Some(pipe) = self.acquire_pipe() else {
            self.start_close(idx);
            return;
        };
        if let Some(t) = self.conns[idx].xfer.as_mut() {
            t.pipe = Some(pipe);
        }
        self.submit_splice_in(idx);
    }

    /// file -> pipe
    fn submit_splice_in(&mut self, idx: usize) {
        let c = &self.conns[idx];
        let t = c.xfer.as_ref().expect("xfer in progress");
        let (_, pipe_w) = t.pipe.expect("pipe acquired");
        let len = t.remaining.min(SPLICE_CHUNK as u64) as u32;
        let entry = opcode::Splice::new(types::Fd(t.file.fd()), t.off as i64, types::Fd(pipe_w), -1, len)
            .build()
            .user_data(user_data(OP_SPLICE_IN, idx));
        push(&mut self.ring, entry);
    }

    /// pipe -> socket
    fn submit_splice_out(&mut self, idx: usize) {
        let c = &self.conns[idx];
        let t = c.xfer.as_ref().expect("xfer in progress");
        let (pipe_r, _) = t.pipe.expect("pipe acquired");
        let entry = opcode::Splice::new(types::Fd(pipe_r), -1, types::Fd(c.fd), -1, t.in_pipe)
            .build()
            .user_data(user_data(OP_SPLICE_OUT, idx));
        push(&mut self.ring, entry);
    }

    fn on_splice_in(&mut self, idx: usize, res: i32) {
        if res <= 0 {
            // Error, or file truncated underneath us after Content-Length was promised.
            self.start_close(idx);
            return;
        }
        if let Some(t) = self.conns[idx].xfer.as_mut() {
            t.in_pipe = res as u32;
        }
        self.submit_splice_out(idx);
    }

    fn on_splice_out(&mut self, idx: usize, res: i32) {
        if res <= 0 {
            self.start_close(idx);
            return;
        }
        self.obs.m.bytes_out += res as u64;
        let step = {
            let t = self.conns[idx].xfer.as_mut().expect("xfer in progress");
            let n = res as u32;
            t.in_pipe -= n.min(t.in_pipe);
            t.off += n as u64;
            t.remaining -= (n as u64).min(t.remaining);
            if t.in_pipe > 0 {
                Step::SpliceOut
            } else if t.remaining > 0 {
                Step::SpliceIn
            } else {
                Step::Done
            }
        };
        match step {
            Step::SpliceOut => self.submit_splice_out(idx),
            Step::SpliceIn => self.submit_splice_in(idx),
            Step::Done => {
                let (pipe, close_after) = {
                    let c = &mut self.conns[idx];
                    let t = c.xfer.take().expect("xfer in progress");
                    (t.pipe, c.close_after)
                };
                if let Some(p) = pipe {
                    self.release_pipe(p); // fully drained: safe to reuse
                }
                if close_after {
                    self.start_close(idx);
                } else {
                    self.pump(idx, 0); // pipelined requests may already be buffered
                }
            }
        }
    }

    fn acquire_pipe(&mut self) -> Option<(RawFd, RawFd)> {
        if let Some(p) = self.pipes.pop() {
            return Some(p);
        }
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds is a valid 2-element array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return None;
        }
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_SIZE);
        }
        Some((fds[0], fds[1]))
    }

    fn release_pipe(&mut self, p: (RawFd, RawFd)) {
        if self.pipes.len() < MAX_POOLED_PIPES {
            self.pipes.push(p);
        } else {
            unsafe {
                libc::close(p.0);
                libc::close(p.1);
            }
        }
    }

    // ───────────────────────── file reads (TLS HTTP/1.1 and HTTP/2) ─────────────────────────

    fn submit_h1_read(&mut self, idx: usize) {
        let c = &mut self.conns[idx];
        let (fd, off, len) = {
            let t = c.xfer.as_ref().expect("xfer in progress");
            (t.file.fd(), t.off, t.remaining.min(FILE_CHUNK as u64) as u32)
        };
        if c.chunk.len() < FILE_CHUNK {
            c.chunk.resize(FILE_CHUNK, 0);
        }
        let entry = opcode::Read::new(types::Fd(fd), c.chunk.as_mut_ptr(), len)
            .offset(off)
            .build()
            .user_data(user_data(OP_FILE_READ, idx));
        push(&mut self.ring, entry);
    }

    fn submit_h2_read(&mut self, idx: usize, fr: FileRead) {
        let c = &mut self.conns[idx];
        c.reading_stream = fr.stream;
        if c.chunk.len() < FILE_CHUNK {
            c.chunk.resize(FILE_CHUNK, 0);
        }
        let entry = opcode::Read::new(types::Fd(fr.fd), c.chunk.as_mut_ptr(), fr.len)
            .offset(fr.off)
            .build()
            .user_data(user_data(OP_FILE_READ, idx));
        push(&mut self.ring, entry);
    }

    fn on_file_read(&mut self, idx: usize, res: i32) {
        let is_h2 = matches!(self.conns[idx].proto, Proto::H2(_));
        if is_h2 {
            {
                let c = &mut self.conns[idx];
                let stream = c.reading_stream;
                if let Proto::H2(h) = &mut c.proto {
                    if res > 0 {
                        h.file_data(stream, &c.chunk[..res as usize], &mut c.out);
                    } else {
                        h.file_data(stream, &[], &mut c.out);
                    }
                }
            }
            self.finish(idx);
            return;
        }

        // HTTP/1.1 over TLS
        if res <= 0 {
            self.start_close(idx);
            return;
        }
        let done = {
            let c = &mut self.conns[idx];
            let n = res as usize;
            c.out.extend_from_slice(&c.chunk[..n]);
            let t = c.xfer.as_mut().expect("xfer in progress");
            t.off += n as u64;
            t.remaining = t.remaining.saturating_sub(n as u64);
            t.remaining == 0
        };
        if done {
            self.conns[idx].xfer = None;
            self.pump(idx, 0);
        } else {
            self.finish(idx);
        }
    }

    // ───────────────────────── reverse proxy ─────────────────────────

    fn start_proxy(&mut self, idx: usize) {
        let now = self.now;
        let picked = self.conns[idx].proxy.as_mut().expect("job").pick_next(now);
        if picked {
            self.begin_attempt(idx);
        } else {
            self.proxy_fail(idx, 502);
        }
    }

    /// Start talking to the upstream the job just picked.
    fn begin_attempt(&mut self, idx: usize) {
        let (state, route, up) = {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            job.reset_attempt();
            (Rc::clone(&job.state), job.route, job.up)
        };
        let mi = state.mids[route][up];
        self.obs.m.ups[mi].requests += 1;

        // Upgrades always dial fresh: a handshake cannot be replayed on a stale socket.
        let upgrade = self.conns[idx].proxy.as_ref().expect("job").upgrade;
        // FastCGI connections are one-shot (no KEEP_CONN), so there is nothing to reuse.
        let fcgi = self.conns[idx].proxy.as_ref().expect("job").fcgi.is_some();
        let idle = if upgrade || fcgi { None } else { state.take_idle(route, up) };
        if let Some(fd) = idle {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            job.fd = fd;
            job.reused = true;
            job.stage = PStage::Sending;
            self.submit_up_send(idx);
        } else {
            self.connect_upstream(idx);
        }
    }

    fn connect_upstream(&mut self, idx: usize) {
        let (state, route, up) = {
            let job = self.conns[idx].proxy.as_ref().expect("job");
            (Rc::clone(&job.state), job.route, job.up)
        };
        let r = state.table.route(route);
        let u = &r.upstreams[up];
        match new_upstream_socket(&u.addr) {
            Ok(fd) => {
                {
                    let job = self.conns[idx].proxy.as_mut().expect("job");
                    job.fd = fd;
                    job.reused = false;
                    job.sent = 0;
                    job.resp.clear();
                    job.head = None;
                    job.chunked = Chunked::default();
                    if let Some(d) = job.fcgi.as_mut() {
                        d.reset();
                    }
                    job.stage = PStage::Connecting;
                }
                // The pointers below live in `state`, which the job keeps alive.
                let entry = opcode::Connect::new(types::Fd(fd), u.sockaddr.as_ptr(), u.sockaddr.len())
                    .build()
                    .user_data(user_data(OP_UP_CONNECT, idx));
                push_linked(&mut self.ring, entry, &r.timeout);
            }
            Err(_) => {
                self.conns[idx].proxy.as_mut().expect("job").stage = PStage::Connecting;
                self.up_error(idx, -libc::EMFILE);
            }
        }
    }

    fn on_up_connect(&mut self, idx: usize, res: i32) {
        if res < 0 {
            self.up_error(idx, res);
            return;
        }
        self.conns[idx].proxy.as_mut().expect("job").stage = PStage::Sending;
        self.submit_up_send(idx);
    }

    fn submit_up_send(&mut self, idx: usize) {
        let job = self.conns[idx].proxy.as_ref().expect("job");
        // SAFETY: `req` is not modified while the SEND is in flight.
        let ptr = unsafe { job.req.as_ptr().add(job.sent) };
        let len = (job.req.len() - job.sent) as u32;
        let entry = opcode::Send::new(types::Fd(job.fd), ptr, len)
            .flags(libc::MSG_NOSIGNAL)
            .build()
            .user_data(user_data(OP_UP_SEND, idx));
        let timeout = &job.state.table.route(job.route).timeout;
        push_linked(&mut self.ring, entry, timeout);
    }

    fn on_up_send(&mut self, idx: usize, res: i32) {
        if res < 0 {
            self.up_error(idx, res);
            return;
        }
        let all_sent = {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            job.sent += res as usize;
            if job.sent >= job.req.len() {
                job.stage = PStage::Receiving;
                true
            } else {
                false
            }
        };
        if all_sent {
            self.submit_up_recv(idx);
        } else {
            self.submit_up_send(idx);
        }
    }

    fn submit_up_recv(&mut self, idx: usize) {
        let job = self.conns[idx].proxy.as_mut().expect("job");
        job.recv_base = job.resp.len();
        job.resp.resize(job.recv_base + UP_RECV_CHUNK, 0);
        // SAFETY: `resp` is not touched (and cannot reallocate) until this RECV completes.
        let ptr = unsafe { job.resp.as_mut_ptr().add(job.recv_base) };
        let entry = opcode::Recv::new(types::Fd(job.fd), ptr, UP_RECV_CHUNK as u32)
            .build()
            .user_data(user_data(OP_UP_RECV, idx));
        let timeout = &job.state.table.route(job.route).timeout;
        push_linked(&mut self.ring, entry, timeout);
    }

    fn on_up_recv(&mut self, idx: usize, res: i32) {
        if self.conns[idx].proxy.as_ref().expect("job").fcgi.is_some() {
            self.on_up_recv_fcgi(idx, res);
            return;
        }
        {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            let got = if res > 0 { res as usize } else { 0 };
            job.resp.truncate(job.recv_base + got);
        }
        if res < 0 {
            self.up_error(idx, res);
            return;
        }
        if res == 0 {
            // Upstream closed. Fine for read-until-close bodies; otherwise an error.
            enum Eof {
                Complete,
                Stale,
                Truncated,
            }
            let what = {
                let job = self.conns[idx].proxy.as_ref().expect("job");
                match &job.head {
                    None => Eof::Stale,
                    Some(h) if h.framing == Framing::UntilClose => Eof::Complete,
                    Some(_) => Eof::Truncated,
                }
            };
            match what {
                Eof::Complete => self.proxy_done(idx),
                Eof::Stale => self.up_error(idx, 0),
                Eof::Truncated => self.up_bad(idx),
            }
            return;
        }

        // A WebSocket handshake answered `101 Switching Protocols` leaves HTTP for good.
        let switch = {
            let job = self.conns[idx].proxy.as_ref().expect("job");
            if job.upgrade && job.head.is_none() { switching_head_len(&job.resp) } else { None }
        };
        if let Some(_head_len) = switch {
            self.start_tunnel(idx);
            return;
        }

        let max = self.cfg.max_proxy_response_bytes;
        let prog = self.conns[idx].proxy.as_mut().expect("job").progress(max);
        match prog {
            Prog::More => self.submit_up_recv(idx),
            Prog::Done => self.proxy_done(idx),
            Prog::Bad => self.up_bad(idx),
        }
    }

    /// A chunk of the FastCGI stream arrived. Records are decoded into the
    /// job's [`fastcgi::Decoder`]; once `END_REQUEST` is seen the buffered CGI
    /// output becomes an ordinary HTTP/1.1 response in `job.resp` and the
    /// regular completion path (`progress` / `proxy_done`) takes over.
    fn on_up_recv_fcgi(&mut self, idx: usize, res: i32) {
        enum Step {
            More,
            Done,
            Eof { seen: bool },
            Bad,
        }
        if res < 0 {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            job.resp.clear();
            job.recv_base = 0;
            self.up_error(idx, res);
            return;
        }
        let max = self.cfg.max_proxy_response_bytes;
        let mut stderr_note: Option<String> = None;
        let step = {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            let got = if res > 0 { res as usize } else { 0 };
            job.resp.truncate(job.recv_base + got);
            let mut buf = std::mem::take(&mut job.resp);
            let base = job.recv_base;
            job.recv_base = 0;
            let head_req = job.head_req;
            let dec = job.fcgi.as_mut().expect("fcgi job");
            let fed = if res > 0 { dec.feed(&buf[base..], max) } else { Ok(()) };
            buf.clear();
            job.resp = buf;
            let dec = job.fcgi.as_mut().expect("fcgi job");
            if !dec.stderr().is_empty() && (dec.is_done() || res <= 0) {
                stderr_note = Some(String::from_utf8_lossy(&dec.stderr()[..dec.stderr().len().min(512)]).into_owned());
            }
            if fed.is_err() {
                Step::Bad
            } else if dec.is_done() {
                match dec.take_http(head_req) {
                    Ok(http) => {
                        job.resp = http;
                        Step::Done
                    }
                    Err(_) => Step::Bad,
                }
            } else if res == 0 {
                Step::Eof { seen: dec.bytes_seen() > 0 }
            } else {
                Step::More
            }
        };
        if let Some(n) = stderr_note {
            eprintln!("vajra: php-fpm stderr: {}", n.trim_end());
        }
        match step {
            Step::More => self.submit_up_recv(idx),
            Step::Bad | Step::Eof { seen: true } => self.up_bad(idx),
            Step::Eof { seen: false } => self.up_error(idx, 0),
            Step::Done => {
                self.obs.m.fcgi_requests += 1;
                let prog = self.conns[idx].proxy.as_mut().expect("job").progress(usize::MAX);
                match prog {
                    Prog::Done => self.proxy_done(idx),
                    Prog::More | Prog::Bad => self.up_bad(idx),
                }
            }
        }
    }

    /// An upstream transport failure (`res` is a negative errno, or 0 for EOF
    /// before any response byte).
    ///
    /// 1. A stale pooled socket is replaced by a fresh connection to the same
    ///    upstream, once, with no health penalty (idempotent requests only).
    /// 2. Otherwise the failure is recorded against the upstream.
    /// 3. If it is safe to replay (nothing was sent, or the request is
    ///    idempotent and no response byte arrived), another upstream is tried.
    fn up_error(&mut self, idx: usize, res: i32) {
        let now = self.now;
        let timed_out = res == -libc::ECANCELED;

        let (state, route, up, stage, reused, idempotent, got_bytes, stale_retried, fd) = {
            let j = self.conns[idx].proxy.as_ref().expect("job");
            (
                Rc::clone(&j.state), j.route, j.up, j.stage, j.reused, j.idempotent,
                !j.resp.is_empty() || j.fcgi.as_ref().is_some_and(|d| d.bytes_seen() > 0),
                j.stale_retried, j.fd,
            )
        };
        if fd >= 0 {
            fire_close(&mut self.ring, fd);
            self.conns[idx].proxy.as_mut().expect("job").fd = -1;
        }

        if reused && idempotent && !stale_retried && !got_bytes && !timed_out && stage != PStage::Connecting {
            self.conns[idx].proxy.as_mut().expect("job").stale_retried = true;
            self.connect_upstream(idx);
            return;
        }

        {
            let m = &mut self.obs.m.ups[state.mids[route][up]];
            if timed_out {
                m.timeouts += 1;
            } else if stage == PStage::Connecting {
                m.connect_errors += 1;
            } else {
                m.io_errors += 1;
            }
        }

        let failover = {
            let job = self.conns[idx].proxy.as_mut().expect("job");
            job.end_attempt(false, now);
            let safe = stage == PStage::Connecting || (idempotent && !got_bytes);
            safe && job.attempts < MAX_ATTEMPTS && job.pick_next(now)
        };
        if failover {
            self.begin_attempt(idx);
        } else {
            self.proxy_fail(idx, if timed_out { 504 } else { 502 });
        }
    }

    /// The upstream answered with something we cannot use (malformed, too big,
    /// truncated). Counts against its health; no failover (the request may have run).
    fn up_bad(&mut self, idx: usize) {
        let now = self.now;
        let (state, route, up, fd) = {
            let j = self.conns[idx].proxy.as_ref().expect("job");
            (Rc::clone(&j.state), j.route, j.up, j.fd)
        };
        self.obs.m.ups[state.mids[route][up]].io_errors += 1;
        if fd >= 0 {
            fire_close(&mut self.ring, fd);
        }
        let job = self.conns[idx].proxy.as_mut().expect("job");
        job.fd = -1;
        job.end_attempt(false, now);
        self.proxy_fail(idx, 502);
    }

    fn proxy_fail(&mut self, idx: usize, status: u16) {
        let date = self.cur_date;
        let now = self.now;
        let mut job = self.conns[idx].proxy.take().expect("job");
        job.end_attempt(false, now);
        if job.fd >= 0 {
            fire_close(&mut self.ring, job.fd);
        }
        if let Proto::Quic(q) = self.conns[idx].proto {
            self.obs.response(
                job.client_ip,
                Http::H3,
                &job.method,
                &job.target,
                status,
                http::error_body(status).len() as u64,
            );
            self.q_respond(q, http::h2_error(status, &date));
            self.release_pseudo(idx);
            return;
        }
        let h2 = matches!(self.conns[idx].proto, Proto::H2(_));
        self.obs.response(
            job.client_ip,
            if h2 { Http::H2 } else { Http::H1 },
            &job.method,
            &job.target,
            status,
            http::error_body(status).len() as u64,
        );
        {
            let c = &mut self.conns[idx];
            match &mut c.proto {
                Proto::H2(h) => h.respond(job.stream, http::h2_error(status, &date), &mut c.out),
                _ => {
                    http::write_error(&mut c.out, status, &date);
                    c.close_after = true;
                }
            }
        }
        self.pump(idx, 0);
    }

    fn proxy_done(&mut self, idx: usize) {
        let date = self.cur_date;
        let now = self.now;
        let mut job = self.conns[idx].proxy.take().expect("job");
        let head = job.head.take().expect("head parsed");
        let raw_len = job.resp.len() - head.head_len;

        let (body, reusable) = match head.framing {
            Framing::None => (Vec::new(), head.keepalive && raw_len == 0),
            Framing::Length(n) => {
                job.resp.drain(..head.head_len);
                job.resp.truncate(n);
                (std::mem::take(&mut job.resp), head.keepalive && raw_len == n)
            }
            Framing::Chunked => (
                std::mem::take(&mut job.chunked.body),
                head.keepalive && job.chunked.consumed == raw_len,
            ),
            Framing::UntilClose => {
                job.resp.drain(..head.head_len);
                (std::mem::take(&mut job.resp), false)
            }
        };

        // Health and latency.
        job.end_attempt(true, now);
        let mi = job.state.mids[job.route][job.up];
        self.obs.m.ups[mi].latency.observe(job.t0.elapsed().as_micros() as u64);

        // Return the upstream socket to the pool of the table it came from.
        if job.fd >= 0 {
            if !(reusable && job.state.give_idle(job.route, job.up, job.fd)) {
                fire_close(&mut self.ring, job.fd);
            }
            job.fd = -1;
        }

        // Cache bookkeeping.
        let body = Rc::new(body);
        let mut xcache: Option<&'static str> = None;
        match &job.cache {
            CacheMode::Store(key) => {
                xcache = Some("MISS");
                if let Some(policy) = job.state.table.route(job.route).cache {
                    if let Some(ttl) = cache::ttl_for(head.status, &head.headers, body.len(), &policy) {
                        self.cache.put(
                            key.clone(),
                            CachedResponse {
                                status: head.status,
                                headers: cache::storable_headers(&head.headers),
                                body: Rc::clone(&body),
                                stored_at: now,
                                expires_at: now + ttl,
                            },
                        );
                    }
                }
            }
            CacheMode::Invalidate(key) => {
                if head.status < 400 {
                    self.cache.invalidate(key);
                }
            }
            CacheMode::None => {}
        }

        let bodyless = head.status == 204 || head.status == 304;
        let bytes = if job.head_req || bodyless { 0 } else { body.len() as u64 };
        let kind = match self.conns[idx].proto {
            Proto::H2(_) => Http::H2,
            Proto::Quic(_) => Http::H3,
            _ => Http::H1,
        };
        self.obs.response(job.client_ip, kind, &job.method, &job.target, head.status, bytes);

        let mut quic_resp = None;
        {
            let c = &mut self.conns[idx];
            match &mut c.proto {
                Proto::Quic(q) => {
                    let owned = Rc::try_unwrap(body).unwrap_or_else(|rc| (*rc).clone());
                    let resp = http::h2_proxy_response(head.status, &head.headers, owned, job.head_req, &date, xcache);
                    quic_resp = Some((*q, resp));
                }
                Proto::H2(h) => {
                    // Not shared with the cache => no copy.
                    let owned = Rc::try_unwrap(body).unwrap_or_else(|rc| (*rc).clone());
                    let resp = http::h2_proxy_response(head.status, &head.headers, owned, job.head_req, &date, xcache);
                    h.respond(job.stream, resp, &mut c.out);
                }
                _ => {
                    let keep = !c.close_after;
                    http::write_proxy_response(
                        &mut c.out, head.status, &head.headers, &body, job.head_req, keep, &date, xcache,
                    );
                }
            }
        }
        if let Some((q, resp)) = quic_resp {
            self.q_respond(q, resp);
            self.release_pseudo(idx);
            return;
        }
        self.pump(idx, 0); // resume parsing anything buffered behind this request
    }

    // ───────────────────────── close ─────────────────────────

    // ───────────────────────── WebSocket tunnel ─────────────────────────

    /// The upstream sent `101`: hand both sockets to a [`Tunnel`]. The 101 head
    /// (and any bytes that followed it) is forwarded to the client verbatim,
    /// and client bytes that arrived behind the handshake are forwarded upstream.
    fn start_tunnel(&mut self, idx: usize) {
        let now = self.now;
        let mut job = self.conns[idx].proxy.take().expect("job");
        // The balancer sees the handshake as a success; long-lived tunnels are
        // deliberately not counted as "active" for least_conn.
        job.end_attempt(true, now);
        let up_fd = job.fd;
        job.fd = -1;
        self.obs.m.ws_upgrades += 1;
        self.obs.response(job.client_ip, Http::H1, &job.method, &job.target, 101, 0);

        let c = &mut self.conns[idx];
        c.out.extend_from_slice(&job.resp);
        let early = std::mem::take(&mut c.input);
        c.tunnel = Some(Box::new(Tunnel {
            up_fd,
            c2u: Vec::new(),
            c2u_pos: 0,
            c2u_next: early,
            ubuf: vec![0; TUNNEL_BUF],
            csend: false,
            urecv: false,
            usend: false,
            client_eof: c.peer_eof,
            up_eof: false,
            up_shut: false,
            closing: false,
            dying: false,
        }));
        self.t_advance(idx);
    }

    /// Stop both directions. Pending operations complete promptly (EOF/error)
    /// and the last one to finish tears the tunnel down.
    fn t_kill(&mut self, idx: usize) {
        let c = &mut self.conns[idx];
        let Some(t) = c.tunnel.as_mut() else { return };
        if t.dying {
            return;
        }
        t.dying = true;
        // SAFETY: plain syscalls on descriptors this connection owns.
        unsafe {
            libc::shutdown(c.fd, libc::SHUT_RDWR);
            libc::shutdown(t.up_fd, libc::SHUT_RDWR);
        }
    }

    fn t_finalize(&mut self, idx: usize) {
        if let Some(t) = self.conns[idx].tunnel.take() {
            fire_close(&mut self.ring, t.up_fd);
        }
        self.start_close(idx);
    }

    /// Re-evaluate the tunnel after any completion: move buffered bytes toward
    /// the wire, apply back-pressure, propagate EOF, and submit whatever
    /// operations are now possible.
    fn t_advance(&mut self, idx: usize) {
        if self.conns[idx].tunnel.is_none() {
            return;
        }

        // Rotate the upstream send buffer, and encrypt/stage client-bound bytes
        // (never while a SEND is reading `net`).
        {
            let c = &mut self.conns[idx];
            let t = c.tunnel.as_mut().expect("tunnel");
            if !t.usend && t.c2u_pos >= t.c2u.len() {
                t.c2u.clear();
                t.c2u_pos = 0;
                if !t.c2u_next.is_empty() {
                    std::mem::swap(&mut t.c2u, &mut t.c2u_next);
                }
            }
            if !t.csend {
                stage_tx(c);
            }
        }

        // Upstream finished: flush the client, send close_notify, then close.
        let finish = {
            let c = &mut self.conns[idx];
            let t = c.tunnel.as_ref().expect("tunnel");
            let flushed = c.out.is_empty() && c.npos >= c.net.len() && !t.csend;
            let up_done = t.up_eof && flushed;
            if up_done && !t.closing {
                c.tunnel.as_mut().expect("tunnel").closing = true;
                c.close_after = true;
                stage_tx(c); // TLS close_notify
            }
            let t = c.tunnel.as_ref().expect("tunnel");
            let flushed = c.out.is_empty() && c.npos >= c.net.len() && !t.csend;
            t.closing && flushed
        };
        if finish {
            self.t_kill(idx);
        }

        // Client finished and everything was forwarded: half-close the upstream.
        {
            let c = &mut self.conns[idx];
            let t = c.tunnel.as_mut().expect("tunnel");
            if t.client_eof && !t.up_shut && !t.usend && t.c2u_pos >= t.c2u.len() && t.c2u_next.is_empty() {
                // SAFETY: plain syscall on the tunnel's upstream descriptor.
                unsafe {
                    libc::shutdown(t.up_fd, libc::SHUT_WR);
                }
                t.up_shut = true;
            }
        }

        // What can be submitted now?
        let (inflight, dying, want_usend, want_csend, want_crecv, want_urecv) = {
            let c = &mut self.conns[idx];
            let pending_out = c.out.len() + (c.net.len() - c.npos);
            let t = c.tunnel.as_mut().expect("tunnel");
            let inflight = t.usend || t.urecv || t.csend || c.in_recv;
            let backlog_c2u = (t.c2u.len() - t.c2u_pos) + t.c2u_next.len();
            let live = !t.dying;
            (
                inflight,
                t.dying,
                live && !t.usend && t.c2u_pos < t.c2u.len(),
                live && !t.csend && c.npos < c.net.len(),
                live && !c.in_recv && !t.client_eof && !t.closing && backlog_c2u < TUNNEL_HIGH_WATER,
                live && !t.urecv && !t.up_eof && !t.closing && pending_out < TUNNEL_HIGH_WATER,
            )
        };

        if dying {
            if !inflight {
                self.t_finalize(idx);
            }
            return;
        }
        if want_usend {
            self.submit_t_usend(idx);
        }
        if want_csend {
            self.conns[idx].tunnel.as_mut().expect("tunnel").csend = true;
            self.submit_send(idx);
        }
        if want_crecv {
            self.submit_recv(idx);
        }
        if want_urecv {
            self.submit_t_urecv(idx);
        }
    }

    fn submit_t_usend(&mut self, idx: usize) {
        let t = self.conns[idx].tunnel.as_mut().expect("tunnel");
        t.usend = true;
        // SAFETY: `c2u` is neither modified nor reallocated while `usend` is set.
        let ptr = unsafe { t.c2u.as_ptr().add(t.c2u_pos) };
        let len = (t.c2u.len() - t.c2u_pos) as u32;
        let entry = opcode::Send::new(types::Fd(t.up_fd), ptr, len)
            .flags(libc::MSG_NOSIGNAL)
            .build()
            .user_data(user_data(OP_T_USEND, idx));
        push(&mut self.ring, entry);
    }

    fn submit_t_urecv(&mut self, idx: usize) {
        let t = self.conns[idx].tunnel.as_mut().expect("tunnel");
        t.urecv = true;
        // SAFETY: `ubuf` is never resized and is untouched while `urecv` is set.
        let entry = opcode::Recv::new(types::Fd(t.up_fd), t.ubuf.as_mut_ptr(), TUNNEL_BUF as u32)
            .build()
            .user_data(user_data(OP_T_URECV, idx));
        push(&mut self.ring, entry);
    }

    fn on_t_crecv(&mut self, idx: usize, res: i32) {
        if res < 0 {
            self.t_kill(idx);
        } else if res == 0 {
            self.conns[idx].tunnel.as_mut().expect("tunnel").client_eof = true;
        } else {
            let n = res as usize;
            self.obs.m.bytes_in += n as u64;
            let c = &mut self.conns[idx];
            let ok = if c.tls.is_some() {
                let ok = tls_ingest(c, n).is_ok();
                if c.peer_eof {
                    c.tunnel.as_mut().expect("tunnel").client_eof = true;
                }
                if ok {
                    let t = c.tunnel.as_mut().expect("tunnel");
                    t.c2u_next.extend_from_slice(&c.input);
                    c.input.clear();
                }
                ok
            } else {
                let t = c.tunnel.as_mut().expect("tunnel");
                t.c2u_next.extend_from_slice(&c.rbuf.as_slice()[..n]);
                true
            };
            if !ok {
                self.t_kill(idx);
            }
        }
        self.t_advance(idx);
    }

    fn on_t_csend(&mut self, idx: usize, res: i32) {
        self.conns[idx].tunnel.as_mut().expect("tunnel").csend = false;
        if res < 0 {
            self.t_kill(idx);
        } else {
            self.obs.m.bytes_out += res as u64;
            let c = &mut self.conns[idx];
            c.npos += res as usize;
            if c.npos >= c.net.len() {
                c.net.clear();
                c.npos = 0;
            }
        }
        self.t_advance(idx);
    }

    fn on_t_urecv(&mut self, idx: usize, res: i32) {
        self.conns[idx].tunnel.as_mut().expect("tunnel").urecv = false;
        if res < 0 {
            self.t_kill(idx);
        } else if res == 0 {
            self.conns[idx].tunnel.as_mut().expect("tunnel").up_eof = true;
        } else {
            let c = &mut self.conns[idx];
            let t = c.tunnel.as_ref().expect("tunnel");
            c.out.extend_from_slice(&t.ubuf[..res as usize]);
        }
        self.t_advance(idx);
    }

    fn on_t_usend(&mut self, idx: usize, res: i32) {
        let t = self.conns[idx].tunnel.as_mut().expect("tunnel");
        t.usend = false;
        if res < 0 {
            self.t_kill(idx);
        } else {
            t.c2u_pos += res as usize;
        }
        self.t_advance(idx);
    }

    fn start_close(&mut self, idx: usize) {
        let now = self.now;
        let c = &mut self.conns[idx];
        if let Some(t) = c.xfer.take() {
            // An aborted splice may leave bytes in its pipe: destroy it.
            if let Some((r, w)) = t.pipe {
                unsafe {
                    libc::close(r);
                    libc::close(w);
                }
            }
        }
        if let Some(mut job) = c.proxy.take() {
            // Only reachable in teardown paths; keep the balancer's counts honest.
            job.end_attempt(true, now);
            if job.fd >= 0 {
                fire_close(&mut self.ring, job.fd);
            }
        }
        let entry = opcode::Close::new(types::Fd(c.fd))
            .build()
            .user_data(user_data(OP_CLOSE, idx));
        push(&mut self.ring, entry);
    }

    fn on_close(&mut self, idx: usize) {
        let c = &mut self.conns[idx];
        c.fd = -1;
        c.in_recv = false;
        // Drop per-connection protocol state now rather than at slot reuse.
        c.tls = None;
        c.proto = Proto::Http1;
        c.xfer = None;
        c.proxy = None;
        c.tunnel = None;
        c.pending_read = None;
        if c.input.capacity() > 64 * 1024 {
            c.input = Vec::new();
        }
        if c.out.capacity() > 256 * 1024 {
            c.out = Vec::new();
        }
        self.free.push(idx);
        self.live -= 1;
        self.obs.m.conns_closed += 1;
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        for &(r, w) in &self.pipes {
            unsafe {
                libc::close(r);
                libc::close(w);
            }
        }
        if self.log.fd >= 0 && self.log.owns {
            unsafe {
                libc::close(self.log.fd);
            }
        }
        for &fd in &self.log.retired {
            unsafe {
                libc::close(fd);
            }
        }
        // Idle upstream sockets are closed by `ProxyState::drop`.
    }
}

// ───────────────────────── free helpers ─────────────────────────

/// Look up the peer address once per connection, and only when something
/// (proxy `X-Forwarded-For`, the access log) needs it.
fn ensure_peer(c: &mut Conn, need: bool) {
    if need && !c.peer_known {
        c.peer = sys::peer_ip(c.fd);
        c.peer_known = true;
    }
}

/// Feed `rbuf[..n]` (ciphertext) to rustls and append any plaintext to `input`.
/// `Err` means a TLS or resource-limit failure; rustls has queued an alert if one applies.
fn tls_ingest(c: &mut Conn, n: usize) -> Result<(), ()> {
    let tls = c.tls.as_mut().expect("tls connection");
    let mut data: &[u8] = &c.rbuf.as_slice()[..n];
    let mut tmp = [0u8; 16 * 1024];

    while !data.is_empty() {
        let taken = tls.read_tls(&mut data).map_err(|_| ())?;
        tls.process_new_packets().map_err(|_| ())?;

        loop {
            match tls.reader().read(&mut tmp) {
                Ok(0) => {
                    c.peer_eof = true; // close_notify
                    break;
                }
                Ok(k) => {
                    if c.input.len() + k > MAX_INPUT {
                        return Err(());
                    }
                    c.input.extend_from_slice(&tmp[..k]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(()),
            }
        }

        if taken == 0 {
            return Err(()); // rustls refused input even after being drained
        }
    }
    Ok(())
}

/// Move plaintext output toward the wire: swap buffers for plain TCP,
/// encrypt for TLS.
fn stage_tx(c: &mut Conn) {
    match c.tls.as_mut() {
        None => {
            if !c.out.is_empty() {
                if c.net.is_empty() {
                    std::mem::swap(&mut c.out, &mut c.net);
                    c.npos = 0;
                } else {
                    c.net.extend_from_slice(&c.out);
                    c.out.clear();
                }
            }
        }
        Some(t) => {
            if !c.out.is_empty() {
                let _ = t.writer().write_all(&c.out);
                c.out.clear();
            }
            if c.close_after && !c.sent_close_notify {
                t.send_close_notify();
                c.sent_close_notify = true;
            }
            while t.wants_write() {
                match t.write_tls(&mut c.net) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
}

/// If `buf` holds a complete `HTTP/1.x 101` response head, its length.
fn switching_head_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 12 || !buf.starts_with(b"HTTP/1.") || &buf[9..12] != b"101" {
        return None;
    }
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn new_upstream_socket(addr: &UpAddr) -> io::Result<RawFd> {
    match addr {
        UpAddr::Tcp(a) => {
            let s = Socket::new(Domain::for_address(*a), Type::STREAM, Some(Protocol::TCP))?;
            s.set_nodelay(true)?;
            Ok(s.into_raw_fd())
        }
        UpAddr::Unix(_) => Ok(Socket::new(Domain::UNIX, Type::STREAM, None)?.into_raw_fd()),
    }
}

/// Close an fd without tracking the completion.
fn fire_close(ring: &mut IoUring, fd: RawFd) {
    let entry = opcode::Close::new(types::Fd(fd)).build().user_data(user_data(OP_IGNORE, 0));
    push(ring, entry);
}

/// Push an SQE, flushing the submission queue if it is full.
fn push(ring: &mut IoUring, entry: squeue::Entry) {
    loop {
        {
            let mut sq = ring.submission();
            // SAFETY: the caller guarantees the buffers referenced by `entry`
            // stay valid and unmodified until the matching CQE is reaped.
            if unsafe { sq.push(&entry) }.is_ok() {
                return;
            }
        }
        let _ = ring.submit();
    }
}

/// Push `entry` linked to a `LINK_TIMEOUT` so it is cancelled (-ECANCELED)
/// if it does not complete within `ts`. Both SQEs are placed back to back.
fn push_linked(ring: &mut IoUring, entry: squeue::Entry, ts: &types::Timespec) {
    let entry = entry.flags(squeue::Flags::IO_LINK);
    let timeout = opcode::LinkTimeout::new(ts as *const types::Timespec)
        .build()
        .user_data(user_data(OP_IGNORE, 0));
    loop {
        {
            let mut sq = ring.submission();
            if sq.capacity() - sq.len() >= 2 {
                // SAFETY: space for both entries was just checked; the timespec
                // lives in the route table, which the job keeps alive.
                unsafe {
                    sq.push(&entry).expect("space checked");
                    sq.push(&timeout).expect("space checked");
                }
                return;
            }
        }
        let _ = ring.submit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxySettings;
    use crate::observe::Metrics;

    fn state(n: usize) -> Rc<ProxyState> {
        let mut s = ProxySettings::simple("/", "127.0.0.1:1".parse().unwrap(), false, 5);
        s.upstreams = (0..n).map(|i| UpAddr::Tcp(format!("127.0.0.1:{}", 7000 + i).parse().unwrap())).collect();
        let mut m = Metrics::default();
        Rc::new(ProxyState::new(&[s], 1024, &mut m))
    }

    fn job_on(st: Rc<ProxyState>, head: bool) -> ProxyJob {
        let spec = ProxySpec {
            route: 0,
            request: Vec::new(),
            head,
            idempotent: true,
            method: "GET".into(),
            target: "/".into(),
            cache: CacheMode::None,
            upgrade: false,
            fcgi: false,
        };
        ProxyJob::new(spec, st, None, 0)
    }

    fn job(head: bool) -> ProxyJob {
        job_on(state(1), head)
    }

    #[test]
    fn progress_content_length() {
        let mut j = job(false);
        j.resp.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe");
        assert!(matches!(j.progress(1 << 20), Prog::More));
        j.resp.extend_from_slice(b"llo");
        assert!(matches!(j.progress(1 << 20), Prog::Done));
    }

    #[test]
    fn progress_chunked_and_limits() {
        let mut j = job(false);
        j.resp.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n");
        assert!(matches!(j.progress(1 << 20), Prog::More));
        j.resp.extend_from_slice(b"0\r\n\r\n");
        assert!(matches!(j.progress(1 << 20), Prog::Done));
        assert_eq!(j.chunked.body, b"abc");

        let mut j = job(false);
        j.resp.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        assert!(matches!(j.progress(10), Prog::Bad), "response over the cap is rejected");
    }

    #[test]
    fn progress_head_only_response() {
        let mut j = job(true);
        j.resp.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n");
        assert!(matches!(j.progress(1 << 20), Prog::Done));
    }

    #[test]
    fn attempts_are_paired_with_releases_and_never_repeat_an_upstream() {
        let st = state(2);
        let mut j = job_on(Rc::clone(&st), false);
        assert!(j.pick_next(0));
        let first = j.up;
        assert_eq!(st.bal.borrow()[0].active(first), 1);
        j.end_attempt(false, 0);
        assert_eq!(st.bal.borrow()[0].active(first), 0);
        j.end_attempt(false, 0); // idempotent: no double release
        assert_eq!(st.bal.borrow()[0].active(first), 0);

        assert!(j.pick_next(0));
        assert_ne!(j.up, first, "failover goes to a different upstream");
        j.end_attempt(true, 0);
        assert!(!j.pick_next(0), "both upstreams already tried");
        assert_eq!(j.attempts, 2);
    }

    #[test]
    fn reset_attempt_clears_per_attempt_state_only() {
        let mut j = job(false);
        j.pick_next(0);
        j.resp.extend_from_slice(b"junk");
        j.sent = 9;
        j.fd = 5;
        j.stale_retried = true;
        j.reset_attempt();
        assert!(j.resp.is_empty() && j.head.is_none());
        assert_eq!((j.sent, j.fd, j.stage, j.stale_retried), (0, -1, PStage::Idle, false));
        assert_eq!(j.tried, 1, "history of tried upstreams survives");
        assert!(j.picked);
    }

    #[test]
    fn switching_protocols_head_detection() {
        let r = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x00";
        assert_eq!(switching_head_len(r), Some(r.len() - 2));
        assert_eq!(switching_head_len(b"HTTP/1.1 101 Switching Protocols\r\nUpgr"), None);
        assert_eq!(switching_head_len(b"HTTP/1.1 400 Bad Request\r\n\r\n"), None);
        assert_eq!(switching_head_len(b"HTTP/1.1 101"), None);
    }

    #[test]
    fn user_data_roundtrip() {
        let ud = user_data(OP_UP_RECV, 123_456);
        assert_eq!(ud >> OP_SHIFT, OP_UP_RECV);
        assert_eq!((ud & IDX_MASK) as usize, 123_456);
    }

    #[test]
    fn access_log_targets() {
        assert_eq!(open_log(None).unwrap(), None);
        assert_eq!(open_log(Some("-")).unwrap(), Some((1, false)));
        let dir = std::env::temp_dir().join(format!("vajra-log-{}", std::process::id()));
        let path = dir.join("nested/access.log");
        let (fd, owns) = open_log(Some(path.to_str().unwrap())).unwrap().unwrap();
        assert!(owns && fd > 2);
        unsafe { libc::close(fd) };
        assert!(path.exists(), "parent directories are created");
        assert!(open_log(Some("/proc/definitely/not/writable")).is_err());
    }
}
