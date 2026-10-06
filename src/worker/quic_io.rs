//! HTTP/3 glue for the worker: UDP I/O through io_uring, the QUIC timer, and
//! request dispatch.
//!
//! This module is a child of [`crate::worker`] so it can use the worker's
//! private state directly. The sans-I/O engine lives in [`crate::quic`].
//!
//! * **Receive**: `RX_SLOTS` single-shot `IORING_OP_RECVMSG` operations stay
//!   armed; each completion feeds one datagram to the engine and re-arms its slot.
//! * **Send**: datagrams produced by the engine wait in a queue and go out
//!   through up to `TX_SLOTS` concurrent `IORING_OP_SENDMSG` operations
//!   (no GSO yet: one datagram per operation).
//! * **Timer**: one `IORING_OP_TIMEOUT` per outstanding deadline; a timer that
//!   fires early or late is harmless because the engine only acts on connections
//!   that are actually due.
//! * **Requests**: completed HTTP/3 requests are routed with exactly the same
//!   logic as HTTP/2. Proxied requests run in a *pseudo connection slot*: a
//!   `Conn` with no socket whose `Proto::Quic` records where to deliver the
//!   response, so the whole proxy machinery (balancing, failover, cache) is reused.

use super::*;
use crate::quic::{Datagram, Quic, Ready};
use socket2::SockAddr;
use std::collections::{BTreeMap, VecDeque};

const RX_SLOTS: usize = 32;
const TX_SLOTS: usize = 64;
const RX_BUF: usize = 4096;
/// Datagrams waiting for a free send slot; beyond this they are dropped
/// (QUIC retransmits, and a sender this far behind is overloaded anyway).
const MAX_TXQ: usize = 4096;

struct RxSlot {
    hdr: libc::msghdr,
    iov: libc::iovec,
    name: libc::sockaddr_storage,
    buf: Box<[u8]>,
}

struct TxSlot {
    hdr: libc::msghdr,
    iov: libc::iovec,
    addr: Option<SockAddr>,
    data: Vec<u8>,
}

pub(super) struct QuicRt {
    fd: RawFd,
    engine: Quic,
    cfg: QuicConfig,
    cert: Option<crate::config::TlsPaths>,
    rx: Vec<Box<RxSlot>>,
    tx: Vec<Box<TxSlot>>,
    tx_free: Vec<usize>,
    txq: VecDeque<Datagram>,
    /// Armed timers: sequence -> (deadline, timespec the kernel reads).
    timers: BTreeMap<u64, (Instant, Box<types::Timespec>)>,
    timer_seq: u64,
    tx_dropped: u64,
}

impl QuicRt {
    fn new(fd: RawFd, engine: Quic, cfg: QuicConfig, cert: Option<crate::config::TlsPaths>) -> Self {
        let rx = (0..RX_SLOTS)
            .map(|_| {
                // SAFETY: msghdr/iovec/sockaddr_storage are plain C structs; all-zero is valid.
                let mut s = Box::new(RxSlot {
                    hdr: unsafe { std::mem::zeroed() },
                    iov: unsafe { std::mem::zeroed() },
                    name: unsafe { std::mem::zeroed() },
                    buf: vec![0u8; RX_BUF].into_boxed_slice(),
                });
                // The slot is boxed, so these self-pointers stay valid for its lifetime.
                s.iov.iov_base = s.buf.as_mut_ptr().cast();
                s.iov.iov_len = RX_BUF;
                s.hdr.msg_name = (&mut s.name as *mut libc::sockaddr_storage).cast();
                s.hdr.msg_iov = &mut s.iov;
                s.hdr.msg_iovlen = 1;
                s
            })
            .collect();
        let tx = (0..TX_SLOTS)
            .map(|_| {
                // SAFETY: as above.
                Box::new(TxSlot {
                    hdr: unsafe { std::mem::zeroed() },
                    iov: unsafe { std::mem::zeroed() },
                    addr: None,
                    data: Vec::new(),
                })
            })
            .collect();
        Self {
            fd,
            engine,
            cfg,
            cert,
            rx,
            tx,
            tx_free: (0..TX_SLOTS).collect(),
            txq: VecDeque::new(),
            timers: BTreeMap::new(),
            timer_seq: 0,
            tx_dropped: 0,
        }
    }
}

impl Worker {
    /// Serve HTTP/3 on `udp_fd` (a bound, non-blocking UDP socket owned by the
    /// caller, who must keep it open for the worker's lifetime). Call before [`Worker::run`].
    ///
    /// `cert` are the certificate paths used again when the configuration is
    /// reloaded; `advertise` is the `Alt-Svc` value for HTTP/1.1 and HTTP/2
    /// responses (e.g. `h3=":443"; ma=86400`).
    pub fn attach_quic(
        &mut self,
        udp_fd: RawFd,
        cfg: QuicConfig,
        server: Arc<quinn_proto::ServerConfig>,
        cert: Option<crate::config::TlsPaths>,
        advertise: Option<&str>,
    ) {
        let mut cfg = cfg;
        cfg.max_body = self.cfg.max_body_bytes;
        cfg.max_conns = cfg.max_conns.min(self.cfg.max_conns);
        let engine = Quic::new(cfg.clone(), server);
        self.quic = Some(Box::new(QuicRt::new(udp_fd, engine, cfg, cert)));
        http::set_alt_svc(advertise);
    }

    // ───────────────────────── lifecycle hooks ─────────────────────────

    pub(super) fn q_arm_all(&mut self) {
        if self.quic.is_none() {
            return;
        }
        for slot in 0..RX_SLOTS {
            self.q_submit_recv(slot);
        }
    }

    pub(super) fn q_busy(&self) -> bool {
        self.quic.as_ref().is_some_and(|q| q.engine.busy() || !q.txq.is_empty())
    }

    pub(super) fn q_begin_drain(&mut self) {
        if let Some(q) = self.quic.as_mut() {
            q.engine.begin_drain();
        }
    }

    pub(super) fn q_fill_metrics(&self, m: &mut crate::observe::Metrics) {
        if let Some(q) = self.quic.as_ref() {
            let s = &q.engine.stats;
            m.quic_conns_accepted = s.conns_accepted;
            m.quic_retries = s.retries_sent;
            m.quic_protocol_errors = s.protocol_errors;
        }
    }

    /// Build the QUIC server config for a reload; `None` when HTTP/3 is off or
    /// the reload carries no certificate.
    pub(super) fn q_build_server_config(
        &self,
        d: &Dynamic,
    ) -> Result<Option<Arc<quinn_proto::ServerConfig>>, String> {
        match (&self.quic, &d.tls) {
            (Some(q), Some(p)) => crate::quic::server_config(&p.cert, &p.key, &q.cfg).map(Some),
            _ => Ok(None),
        }
    }

    pub(super) fn q_set_server_config(&mut self, cfg: Option<Arc<quinn_proto::ServerConfig>>) {
        if let (Some(q), Some(c)) = (self.quic.as_mut(), cfg) {
            q.engine.set_server_config(c);
        }
    }

    /// On exit: tell every peer the server is going away, synchronously (the ring is done).
    pub(super) fn q_finalize(&mut self) {
        let Some(q) = self.quic.as_mut() else { return };
        let now = Instant::now();
        q.engine.close_all(now);
        let mut pending: Vec<Datagram> = q.txq.drain(..).collect();
        pending.extend(q.engine.take_datagrams());
        // Sends queued on the ring but never submitted (the loop is exiting) are repeated
        // here; a duplicated datagram is harmless in QUIC.
        for s in q.tx.iter_mut() {
            if let Some(a) = s.addr.take() {
                if let Some(dest) = a.as_socket() {
                    pending.push(Datagram { dest, data: std::mem::take(&mut s.data) });
                }
            }
        }
        for d in pending {
            let sa = SockAddr::from(d.dest);
            // SAFETY: valid buffer and sockaddr; best-effort send on a non-blocking socket.
            unsafe {
                libc::sendto(q.fd, d.data.as_ptr().cast(), d.data.len(), libc::MSG_DONTWAIT, sa.as_ptr(), sa.len());
            }
        }
    }

    // ───────────────────────── UDP receive ─────────────────────────

    fn q_submit_recv(&mut self, slot: usize) {
        let Some(q) = self.quic.as_mut() else { return };
        let s = &mut q.rx[slot];
        // The kernel overwrites these on every completion.
        s.hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        s.hdr.msg_flags = 0;
        let entry = opcode::RecvMsg::new(types::Fd(q.fd), &mut s.hdr as *mut libc::msghdr)
            .build()
            .user_data(user_data(OP_Q_RECV, slot));
        push(&mut self.ring, entry);
    }

    pub(super) fn on_q_recv(&mut self, slot: usize, res: i32) {
        if self.quic.is_none() {
            return;
        }
        if res > 0 {
            let n = res as usize;
            let q = self.quic.as_mut().expect("quic");
            let s = &q.rx[slot];
            let truncated = s.hdr.msg_flags & libc::MSG_TRUNC != 0;
            if !truncated {
                if let Some(remote) = sys::sockaddr_to_std(&s.name) {
                    self.obs.m.bytes_in += n as u64;
                    q.engine.recv(Instant::now(), remote, &s.buf[..n]);
                }
            }
        }
        // Re-arm unless the socket is gone (-EBADF/-ENOTSOCK) or the operation was cancelled.
        if res >= 0 || !matches!(-res, libc::EBADF | libc::ENOTSOCK | libc::ECANCELED) {
            self.q_submit_recv(slot);
        }
    }

    // ───────────────────────── UDP send ─────────────────────────

    fn q_pump_tx(&mut self) {
        let Some(q) = self.quic.as_mut() else { return };
        loop {
            if q.txq.is_empty() {
                return;
            }
            let Some(slot) = q.tx_free.pop() else { return };
            let d = q.txq.pop_front().expect("non-empty");
            let s = &mut q.tx[slot];
            s.data = d.data;
            s.addr = Some(SockAddr::from(d.dest));
            let addr = s.addr.as_ref().expect("just set");
            s.iov.iov_base = s.data.as_mut_ptr().cast();
            s.iov.iov_len = s.data.len();
            s.hdr.msg_name = addr.as_ptr() as *mut libc::c_void;
            s.hdr.msg_namelen = addr.len();
            s.hdr.msg_iov = &mut s.iov;
            s.hdr.msg_iovlen = 1;
            let entry = opcode::SendMsg::new(types::Fd(q.fd), &s.hdr as *const libc::msghdr)
                .build()
                .user_data(user_data(OP_Q_SEND, slot));
            push(&mut self.ring, entry);
        }
    }

    pub(super) fn on_q_send(&mut self, slot: usize, res: i32) {
        let Some(q) = self.quic.as_mut() else { return };
        if res > 0 {
            self.obs.m.bytes_out += res as u64;
        }
        let s = &mut q.tx[slot];
        s.data = Vec::new();
        s.addr = None;
        q.tx_free.push(slot);
        self.q_pump_tx();
    }

    // ───────────────────────── timers ─────────────────────────

    pub(super) fn on_q_timer(&mut self, seq: usize) {
        let Some(q) = self.quic.as_mut() else { return };
        q.timers.remove(&(seq as u64));
        q.engine.on_timeout(Instant::now());
    }

    /// Make sure a timer is armed for the engine's earliest deadline.
    fn q_rearm_timer(&mut self) {
        let Some(q) = self.quic.as_mut() else { return };
        let Some(next) = q.engine.next_timeout() else { return };
        // An armed timer at or before `next` will fire first and re-arm.
        if q.timers.values().any(|(t, _)| *t <= next) {
            return;
        }
        let seq = q.timer_seq;
        q.timer_seq += 1;
        let d = next.saturating_duration_since(Instant::now());
        let ts = Box::new(types::Timespec::new().sec(d.as_secs()).nsec(d.subsec_nanos()));
        let ptr = &*ts as *const types::Timespec;
        q.timers.insert(seq, (next, ts)); // the Box keeps the timespec alive and at a fixed address
        let entry = opcode::Timeout::new(ptr).build().user_data(user_data(OP_Q_TIMER, seq as usize));
        push(&mut self.ring, entry);
    }

    // ───────────────────────── after each completion batch ─────────────────────────

    /// Flush the engine, dispatch finished requests, queue and submit outgoing
    /// datagrams, and re-arm the timer. Cheap when HTTP/3 is not configured.
    pub(super) fn q_after_batch(&mut self) {
        if self.quic.is_none() {
            return;
        }
        let now = Instant::now();
        // Requests may be answered synchronously, producing more work: iterate to quiescence.
        for _ in 0..8 {
            let reqs = {
                let q = self.quic.as_mut().expect("quic");
                q.engine.flush(now);
                q.engine.take_requests()
            };
            if reqs.is_empty() {
                break;
            }
            for r in reqs {
                self.q_dispatch(r);
            }
        }
        {
            let q = self.quic.as_mut().expect("quic");
            q.engine.flush(now);
            for d in q.engine.take_datagrams() {
                if q.txq.len() >= MAX_TXQ {
                    q.tx_dropped += 1;
                } else {
                    q.txq.push_back(d);
                }
            }
        }
        self.q_pump_tx();
        self.q_rearm_timer();
    }

    // ───────────────────────── request dispatch ─────────────────────────

    pub(super) fn q_respond(&mut self, q: QReq, resp: crate::h2::H2Response) {
        if let Some(rt) = self.quic.as_mut() {
            rt.engine.respond(q.id, q.stream, resp);
        }
    }

    /// Route one HTTP/3 request (same decisions as the HTTP/2 path).
    fn q_dispatch(&mut self, r: Ready) {
        let date = self.cur_date;
        let req = &r.req;
        let peer = Some(r.peer.ip());
        let path = req.path.split('?').next().unwrap_or("/");
        let head_only = req.method == "HEAD";
        let inm = req.headers.iter().find(|(n, _)| n == b"if-none-match").map(|(_, v)| v.as_slice());
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
                    let resp = http::h2_proxy_response(hit.status, &hit.headers, body, head_only, &date, Some("HIT"));
                    let bytes = if bodyless { 0 } else { hit.body.len() as u64 };
                    self.obs.response(peer, Http::H3, &req.method, &req.path, hit.status, bytes);
                    self.q_respond(QReq { id: r.id, stream: r.stream }, resp);
                    return;
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
            let q = QReq { id: r.id, stream: r.stream };
            match self.alloc_pseudo(q) {
                Some(idx) => {
                    self.conns[idx].proxy =
                        Some(Box::new(ProxyJob::new(spec, Rc::clone(&self.proxies), peer, 0)));
                    self.start_proxy(idx);
                }
                None => {
                    self.obs.response(peer, Http::H3, &req.method, &req.path, 503, 0);
                    self.q_respond(q, http::h2_error(503, &date));
                }
            }
            return;
        }

        let resp = http::h2_response(&reply, head_only, &date);
        let (status, bytes) = http::reply_meta(&reply, head_only);
        self.obs.response(peer, Http::H3, &req.method, &req.path, status, bytes);
        self.q_respond(QReq { id: r.id, stream: r.stream }, resp);
    }

    // ───────────────────────── pseudo connection slots ─────────────────────────

    /// A connection slot without a socket, used to run one proxied HTTP/3 request.
    fn alloc_pseudo(&mut self, q: QReq) -> Option<usize> {
        if self.live >= self.cfg.max_conns {
            return None;
        }
        let idx = match self.free.pop() {
            Some(i) => i,
            None => {
                let buf = self.pool.alloc()?;
                self.conns.push(Conn::new(buf));
                self.conns.len() - 1
            }
        };
        let c = &mut self.conns[idx];
        c.fd = -1; // never a real descriptor; the drain scan skips it
        c.in_recv = false;
        c.input.clear();
        c.out.clear();
        c.net.clear();
        c.npos = 0;
        c.proto = Proto::Quic(q);
        c.tls = None;
        c.close_after = false;
        c.peer_eof = false;
        c.xfer = None;
        c.proxy = None;
        c.tunnel = None;
        c.pending_read = None;
        self.live += 1;
        Some(idx)
    }

    pub(super) fn release_pseudo(&mut self, idx: usize) {
        let c = &mut self.conns[idx];
        c.proto = Proto::Http1;
        c.proxy = None;
        self.free.push(idx);
        self.live -= 1;
    }
}
