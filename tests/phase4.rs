//! Phase 4 end-to-end tests: load balancing, failover, caching, metrics,
//! hot reload, access-log rotation and graceful shutdown, against a real
//! worker with a control channel. Each test skips (passes) if io_uring is
//! unavailable.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use vajra::admin::{self, Manager};
use vajra::config::{Balance, Dynamic, ProxySettings, Settings};
use vajra::control;
use vajra::sys;
use vajra::worker::{Config, Listener, Worker};

// ───────────────────────── mock upstream ─────────────────────────

type Handler = dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static;

struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>, // raw request heads, in arrival order
    accepts: Arc<AtomicUsize>,
}

impl Upstream {
    fn requests(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

fn spawn_upstream(handler: Arc<Handler>) -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let (s2, a2) = (seen.clone(), accepts.clone());

    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { break };
            a2.fetch_add(1, Ordering::SeqCst);
            let (handler, seen) = (handler.clone(), s2.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let head_end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        match s.read(&mut tmp) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let cl = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + cl {
                        match s.read(&mut tmp) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let body = buf[head_end..head_end + cl].to_vec();
                    buf.drain(..head_end + cl);
                    seen.lock().unwrap().push(head.clone());
                    if s.write_all(&handler(&head, &body)).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Upstream { addr, seen, accepts }
}

fn ok(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        .into_bytes()
}

/// An upstream that always answers with its own name.
fn named(name: &'static str) -> Upstream {
    spawn_upstream(Arc::new(move |_, _| ok(name)))
}

/// A port that refuses connections.
fn dead_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

// ───────────────────────── server harness ─────────────────────────

struct Server {
    addr: SocketAddr,
    mgr: Arc<Manager>,
    /// Receives the result of `Worker::run` when the worker exits.
    done: mpsc::Receiver<std::io::Result<()>>,
}

fn start(dynamic: Dynamic, config_path: Option<PathBuf>) -> Option<Server> {
    let sock = sys::listener("127.0.0.1:0".parse().unwrap(), false, 128).unwrap();
    let addr = sock.local_addr().unwrap().as_socket().unwrap();
    let (handle, inbox) = control::channel().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    std::thread::spawn(move || {
        let l = [Listener { fd: sock.as_raw_fd(), tls: false }];
        match Worker::new(&l, Config::default(), &dynamic, None) {
            Ok(mut w) => {
                w.attach_control(0, inbox, Duration::from_secs(3));
                ready_tx.send(true).unwrap();
                let r = w.run();
                drop(w);
                drop(sock);
                let _ = done_tx.send(r);
            }
            Err(e) => {
                eprintln!("io_uring unavailable ({e}); skipping");
                ready_tx.send(false).unwrap();
            }
        }
    });

    if !ready_rx.recv().unwrap() {
        return None;
    }
    let mgr = Arc::new(Manager::new(vec![handle], config_path, Settings::default()));
    Some(Server { addr, mgr, done: done_rx })
}

fn proxies(p: Vec<ProxySettings>) -> Dynamic {
    Dynamic { proxies: p, ..Dynamic::default() }
}

fn multi(prefix: &str, ups: &[SocketAddr], balance: Balance) -> ProxySettings {
    let mut p = ProxySettings::simple(prefix, ups[0], false, 5);
    p.upstreams = ups.iter().map(|&a| a.into()).collect();
    p.balance = balance;
    p.max_fails = 2;
    p.fail_timeout_secs = 30;
    p
}

fn tmpdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("vajra-p4-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

// ───────────────────────── HTTP helpers ─────────────────────────

fn split_response(buf: &[u8]) -> (String, Vec<u8>) {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end") + 4;
    (String::from_utf8_lossy(&buf[..split]).into_owned(), buf[split..].to_vec())
}

/// One request on a fresh connection.
fn send(addr: SocketAddr, method: &str, path: &str, extra: &str, body: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: t\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    split_response(&buf)
}

fn get(addr: SocketAddr, path: &str) -> (String, Vec<u8>) {
    send(addr, "GET", path, "", "")
}

fn text(body: Vec<u8>) -> String {
    String::from_utf8(body).unwrap()
}

/// Read exactly one Content-Length-framed response from a keep-alive connection.
fn read_response(s: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = s.read(&mut tmp).unwrap();
        assert!(n > 0, "connection closed before a full response");
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let cl = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .map(|v| v.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + cl {
        let n = s.read(&mut tmp).unwrap();
        assert!(n > 0, "connection closed mid-body");
        buf.extend_from_slice(&tmp[..n]);
    }
    (head, buf[head_end..head_end + cl].to_vec())
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn write_cfg(path: &Path, upstream: SocketAddr, log: Option<&Path>) {
    let mut t = format!("[[proxy]]\nprefix = \"/api/\"\nupstream = \"{upstream}\"\n");
    if let Some(l) = log {
        t += &format!("[logging]\naccess_log = \"{}\"\n", l.display());
    }
    std::fs::write(path, t).unwrap();
}

// ───────────────────────── load balancing ─────────────────────────

#[test]
fn round_robin_spreads_requests_evenly() {
    let (a, b) = (named("A"), named("B"));
    let Some(s) = start(proxies(vec![multi("/api/", &[a.addr, b.addr], Balance::RoundRobin)]), None) else { return };

    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..10 {
        let (head, body) = get(s.addr, "/api/x");
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        *counts.entry(text(body)).or_default() += 1;
    }
    assert_eq!((counts["A"], counts["B"]), (5, 5), "{counts:?}");
}

#[test]
fn ip_hash_pins_a_client_to_one_upstream() {
    let (a, b) = (named("A"), named("B"));
    let Some(s) = start(proxies(vec![multi("/api/", &[a.addr, b.addr], Balance::IpHash)]), None) else { return };

    let bodies: std::collections::HashSet<_> =
        (0..6).map(|_| text(get(s.addr, "/api/x").1)).collect();
    assert_eq!(bodies.len(), 1, "same client address => same upstream: {bodies:?}");
}

#[test]
fn dead_upstream_is_failed_over_then_skipped() {
    let dead = dead_addr();
    let live = named("live");
    let Some(s) = start(proxies(vec![multi("/api/", &[dead, live.addr], Balance::RoundRobin)]), None) else { return };

    for i in 0..8 {
        let (head, body) = get(s.addr, "/api/x");
        assert!(head.starts_with("HTTP/1.1 200 OK"), "request {i}: {head}");
        assert_eq!(body, b"live");
    }

    // max_fails = 2: the dead upstream is tried twice, then its circuit opens.
    let m = s.mgr.scrape();
    assert!(m.contains(&format!("vajra_upstream_connect_errors_total{{upstream=\"{dead}\"}} 2\n")), "{m}");
    assert!(m.contains(&format!("vajra_upstream_requests_total{{upstream=\"{dead}\"}} 2\n")), "{m}");
    assert!(m.contains(&format!("vajra_upstream_requests_total{{upstream=\"{}\"}} 8\n", live.addr)), "{m}");
    assert_eq!(live.requests(), 8);
}

#[test]
fn connect_failures_fail_over_even_for_post() {
    let dead = dead_addr();
    let live = named("live");
    let Some(s) = start(proxies(vec![multi("/api/", &[dead, live.addr], Balance::RoundRobin)]), None) else { return };

    // Nothing was sent to the dead upstream, so replaying the POST is safe.
    let (head, body) = send(s.addr, "POST", "/api/submit", "", "payload");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert_eq!(body, b"live");
    assert!(live.seen.lock().unwrap()[0].starts_with("POST /api/submit"));
}

#[test]
fn all_upstreams_dead_gives_502() {
    let Some(s) = start(proxies(vec![multi("/api/", &[dead_addr(), dead_addr()], Balance::RoundRobin)]), None) else { return };
    let (head, body) = get(s.addr, "/api/x");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(body, b"bad gateway\n");
}

// ───────────────────────── caching ─────────────────────────

#[test]
fn proxy_cache_hit_miss_bypass_and_invalidation() {
    let up = spawn_upstream(Arc::new(|head, _| {
        if head.starts_with("GET /c/private") {
            b"HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Length: 4\r\n\r\ndata".to_vec()
        } else {
            ok("fresh")
        }
    }));
    let mut p = ProxySettings::simple("/c/", up.addr, false, 5);
    p.cache = true;
    p.cache_default_ttl_secs = 60;
    let Some(s) = start(proxies(vec![p]), None) else { return };

    // 1. miss, 2. hit: the upstream is asked only once.
    let (head, body) = get(s.addr, "/c/x");
    assert!(head.contains("X-Cache: MISS\r\n"), "{head}");
    assert_eq!(body, b"fresh");
    let (head, body) = get(s.addr, "/c/x");
    assert!(head.contains("X-Cache: HIT\r\n"), "{head}");
    assert_eq!(body, b"fresh");
    assert_eq!(up.requests(), 1);

    // 3. Authorization bypasses the cache entirely (no header, upstream asked).
    let (head, _) = send(s.addr, "GET", "/c/x", "Authorization: Bearer t\r\n", "");
    assert!(!head.contains("X-Cache"), "{head}");
    assert_eq!(up.requests(), 2);

    // 4. no-store responses are never kept.
    for _ in 0..2 {
        let (head, body) = get(s.addr, "/c/private");
        assert!(head.contains("X-Cache: MISS\r\n"), "{head}");
        assert_eq!(body, b"data");
    }
    assert_eq!(up.requests(), 4);

    // 5. A successful POST invalidates the URL.
    let (head, _) = send(s.addr, "POST", "/c/x", "", "z");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    let (head, _) = get(s.addr, "/c/x");
    assert!(head.contains("X-Cache: MISS\r\n"), "after invalidation: {head}");
    assert_eq!(up.requests(), 6);

    let m = s.mgr.scrape();
    assert!(m.contains("vajra_cache_hits_total 1\n"), "{m}");
    assert!(m.contains("vajra_cache_stores_total 2\n"), "{m}");
    assert!(m.contains("vajra_cache_invalidations_total 1\n"), "{m}");
    assert!(m.contains("vajra_cache_entries{worker=\"0\"} 1\n"), "{m}");
}

// ───────────────────────── metrics ─────────────────────────

#[test]
fn metrics_are_exposed_over_http() {
    let Some(s) = start(Dynamic::default(), None) else { return };
    for _ in 0..3 {
        assert!(get(s.addr, "/health").0.starts_with("HTTP/1.1 200"));
    }
    assert!(get(s.addr, "/missing").0.starts_with("HTTP/1.1 404"));

    let (admin_addr, _h) = admin::serve("127.0.0.1:0".parse().unwrap(), Arc::clone(&s.mgr)).unwrap();
    let mut c = TcpStream::connect(admin_addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();

    assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
    assert!(out.contains("version=0.0.4"));
    assert!(out.contains("vajra_workers 1\n"), "{out}");
    assert!(out.contains("vajra_connections_total 4\n"), "{out}");
    assert!(out.contains("vajra_http_requests_total{protocol=\"http1\"} 4\n"), "{out}");
    assert!(out.contains("vajra_http_responses_total{class=\"2xx\"} 3\n"), "{out}");
    assert!(out.contains("vajra_http_responses_total{class=\"4xx\"} 1\n"), "{out}");
    assert!(!out.contains("vajra_sent_bytes_total 0\n"), "bytes were sent: {out}");
    assert!(out.contains("# TYPE vajra_upstream_latency_seconds histogram"));
}

#[test]
fn upstream_latency_histogram_counts_proxied_requests() {
    let up = named("x");
    let Some(s) = start(proxies(vec![ProxySettings::simple("/api/", up.addr, false, 5)]), None) else { return };
    for _ in 0..3 {
        get(s.addr, "/api/x");
    }
    let m = s.mgr.scrape();
    assert!(m.contains(&format!("vajra_upstream_latency_seconds_count{{upstream=\"{}\"}} 3\n", up.addr)), "{m}");
    assert!(m.contains(&format!("vajra_upstream_latency_seconds_bucket{{upstream=\"{}\",le=\"+Inf\"}} 3\n", up.addr)), "{m}");
}

// ───────────────────────── hot reload ─────────────────────────

#[test]
fn hot_reload_swaps_routes_without_dropping_connections() {
    let (a, b) = (named("A"), named("B"));
    let dir = tmpdir("reload");
    let cfg = dir.join("vajra.toml");
    write_cfg(&cfg, a.addr, None);
    let settings = Settings::load(&cfg).unwrap();
    let Some(s) = start(settings.dynamic(), Some(cfg.clone())) else { return };

    // A keep-alive connection opened before the reload...
    let mut c = TcpStream::connect(s.addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"GET /api/x HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut c).1, b"A");

    write_cfg(&cfg, b.addr, None);
    let msg = s.mgr.reload().expect("reload");
    assert!(msg.contains("reloaded 1 worker"), "{msg}");

    // ...survives it and its next request already uses the new route.
    c.write_all(b"GET /api/x HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut c).1, b"B");
    assert_eq!(get(s.addr, "/api/x").1, b"B");

    // A broken config is rejected and changes nothing.
    std::fs::write(&cfg, "[[proxy]]\nprefix = \"/api/\"\n").unwrap(); // no upstream
    assert!(s.mgr.reload().is_err());
    std::fs::write(&cfg, "this is = not [valid").unwrap();
    assert!(s.mgr.reload().is_err());
    assert_eq!(get(s.addr, "/api/x").1, b"B");

    let m = s.mgr.scrape();
    assert!(m.contains("vajra_config_reloads_total{result=\"ok\"} 1\n"), "{m}");
}

#[test]
fn reload_drops_cached_entries_from_the_old_routes() {
    let (a, b) = (named("A"), named("B"));
    let dir = tmpdir("reload-cache");
    let cfg = dir.join("vajra.toml");
    let toml = |up: SocketAddr| {
        format!("[[proxy]]\nprefix = \"/c/\"\nupstream = \"{up}\"\ncache = true\ncache_default_ttl_secs = 300\n")
    };
    std::fs::write(&cfg, toml(a.addr)).unwrap();
    let Some(s) = start(Settings::load(&cfg).unwrap().dynamic(), Some(cfg.clone())) else { return };

    assert_eq!(get(s.addr, "/c/x").1, b"A");
    assert!(get(s.addr, "/c/x").0.contains("X-Cache: HIT"));

    std::fs::write(&cfg, toml(b.addr)).unwrap();
    s.mgr.reload().unwrap();
    let (head, body) = get(s.addr, "/c/x");
    assert!(head.contains("X-Cache: MISS"), "{head}");
    assert_eq!(body, b"B", "a stale answer from the old upstream must not survive the reload");
}

#[test]
fn access_log_is_written_and_rotated_by_reload() {
    let up = named("A");
    let dir = tmpdir("rotate");
    let (cfg, log) = (dir.join("vajra.toml"), dir.join("logs/access.log"));
    write_cfg(&cfg, up.addr, Some(&log));
    let Some(s) = start(Settings::load(&cfg).unwrap().dynamic(), Some(cfg.clone())) else { return };

    assert!(get(s.addr, "/health").0.starts_with("HTTP/1.1 200"));
    wait_for("first log line", || file_len(&log) > 0);

    // Rotate: move the file away, then reload so the worker reopens the path.
    let rotated = dir.join("logs/access.log.1");
    std::fs::rename(&log, &rotated).unwrap();
    s.mgr.reload().unwrap();

    assert!(get(s.addr, "/api/x").0.starts_with("HTTP/1.1 200"));
    wait_for("log line in the new file", || file_len(&log) > 0);

    let old = std::fs::read_to_string(&rotated).unwrap();
    let new = std::fs::read_to_string(&log).unwrap();
    assert_eq!(old.lines().count(), 1, "{old}");
    assert_eq!(new.lines().count(), 1, "{new}");
    assert!(old.contains("\"GET /health HTTP/1.1\" 200 3"), "{old}");
    assert!(new.contains("\"GET /api/x HTTP/1.1\" 200 1"), "{new}");
}

#[test]
fn access_log_format() {
    let dir = tmpdir("logfmt");
    let log = dir.join("access.log");
    let d = Dynamic { access_log: Some(log.to_string_lossy().into_owned()), ..Dynamic::default() };
    let Some(s) = start(d, None) else { return };

    get(s.addr, "/health");
    get(s.addr, "/nope?q=1");
    s.mgr.shutdown();
    assert!(s.done.recv_timeout(Duration::from_secs(10)).unwrap().is_ok());

    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    for l in &lines {
        assert!(l.starts_with("127.0.0.1 - - ["), "{l}");
        assert!(l.contains(" +0000] \""), "{l}");
    }
    assert!(lines[0].ends_with("\"GET /health HTTP/1.1\" 200 3"), "{}", lines[0]);
    assert!(lines[1].ends_with("\"GET /nope?q=1 HTTP/1.1\" 404 10"), "{}", lines[1]);
}

// ───────────────────────── graceful shutdown ─────────────────────────

#[test]
fn graceful_shutdown_finishes_in_flight_work_and_closes_idle_connections() {
    let up = spawn_upstream(Arc::new(|_, _| {
        std::thread::sleep(Duration::from_millis(700));
        ok("slow-but-complete")
    }));
    let Some(s) = start(proxies(vec![ProxySettings::simple("/slow/", up.addr, false, 5)]), None) else { return };

    // An idle keep-alive connection.
    let mut idle = TcpStream::connect(s.addr).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    idle.write_all(b"GET /health HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut idle).1, b"ok\n");

    // A request that is still running when shutdown begins.
    let addr = s.addr;
    let busy = std::thread::spawn(move || get(addr, "/slow/x"));
    std::thread::sleep(Duration::from_millis(250));
    s.mgr.shutdown();

    // The idle connection is closed by the server...
    let mut b = [0u8; 16];
    assert_eq!(idle.read(&mut b).unwrap_or(0), 0, "idle connection should see EOF");

    // ...the in-flight request still completes...
    let (head, body) = busy.join().unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert_eq!(body, b"slow-but-complete");

    // ...and the worker exits cleanly once nothing is left.
    assert!(s.done.recv_timeout(Duration::from_secs(10)).expect("worker did not exit").is_ok());
}

#[test]
fn shutdown_deadline_abandons_stuck_connections() {
    // A client that never finishes its request must not hold the process forever.
    let Some(s) = start(Dynamic::default(), None) else { return };
    let mut stuck = TcpStream::connect(s.addr).unwrap();
    stuck.write_all(b"GET /health HTTP/1.1\r\nHost: t\r\n").unwrap(); // headers never completed
    std::thread::sleep(Duration::from_millis(100));

    let t0 = Instant::now();
    s.mgr.shutdown();
    // Grace period is 3 s in this harness.
    assert!(s.done.recv_timeout(Duration::from_secs(10)).expect("worker did not exit").is_ok());
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(2500) && took < Duration::from_secs(8), "{took:?}");
}
