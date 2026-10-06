//! Reverse-proxy end-to-end tests: a real worker in front of a tiny
//! hand-rolled upstream server. Skips (passes) if io_uring is unavailable.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use vajra::config::{Dynamic, ProxySettings};
use vajra::sys;
use vajra::worker::{Config, Listener, Worker};

type Handler = dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static;

struct Upstream {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>, // raw request heads, in arrival order
}

/// Keep-alive HTTP/1.1 upstream. `handler(head, body)` returns the raw response.
fn spawn_upstream(handler: Arc<Handler>) -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (a2, s2) = (accepts.clone(), seen.clone());

    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { break };
            a2.fetch_add(1, Ordering::SeqCst);
            let (handler, seen) = (handler.clone(), s2.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    // Read one full request (head + Content-Length body).
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
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
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
                    let resp = handler(&head, &body);
                    if s.write_all(&resp).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Upstream { addr, accepts, seen }
}

fn ok(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Up: yes\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        .into_bytes()
}

fn start(proxies: Vec<ProxySettings>) -> Option<SocketAddr> {
    let sock = sys::listener("127.0.0.1:0".parse().unwrap(), false, 128).unwrap();
    let addr = sock.local_addr().unwrap().as_socket().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let l = [Listener { fd: sock.as_raw_fd(), tls: false }];
        let dynamic = Dynamic { proxies, ..Dynamic::default() };
        match Worker::new(&l, Config::default(), &dynamic, None) {
            Ok(mut w) => {
                tx.send(true).unwrap();
                let _ = w.run();
            }
            Err(e) => {
                eprintln!("io_uring unavailable ({e}); skipping");
                tx.send(false).unwrap();
            }
        }
        drop(sock);
    });
    rx.recv().unwrap().then_some(addr)
}

fn route(prefix: &str, up: SocketAddr, strip: bool, timeout: u64) -> ProxySettings {
    ProxySettings::simple(prefix, up, strip, timeout)
}

fn exchange(addr: SocketAddr, raw: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end") + 4;
    (String::from_utf8_lossy(&buf[..split]).into_owned(), buf[split..].to_vec())
}

#[test]
fn get_is_forwarded_with_forwarding_headers() {
    let up = spawn_upstream(Arc::new(|_, _| ok("from upstream")));
    let Some(addr) = start(vec![route("/api/", up.addr, false, 5)]) else { return };

    let (head, body) = exchange(
        addr,
        "GET /api/users?id=7 HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("X-Up: yes"));
    assert!(head.contains("Content-Length: 13"));
    assert_eq!(body, b"from upstream");

    let seen = up.seen.lock().unwrap();
    let req = &seen[0];
    assert!(req.starts_with("GET /api/users?id=7 HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("Host: example.com"));
    assert!(req.contains("X-Forwarded-For: 127.0.0.1"));
    assert!(!req.contains("6.6.6.6"), "client-supplied XFF must not be trusted");
    assert!(req.contains("X-Forwarded-Proto: http"));
}

#[test]
fn strip_prefix_and_post_body() {
    let up = spawn_upstream(Arc::new(|_, body| ok(&format!("got {} bytes", body.len()))));
    let Some(addr) = start(vec![route("/svc/", up.addr, true, 5)]) else { return };

    let payload = "x".repeat(20_000); // larger than the 8 KiB receive buffer
    let req = format!(
        "POST /svc/upload HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let (head, body) = exchange(addr, &req);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert_eq!(body, b"got 20000 bytes");
    assert!(up.seen.lock().unwrap()[0].starts_with("POST /upload HTTP/1.1"));
}

#[test]
fn chunked_upstream_response_is_decoded() {
    let up = spawn_upstream(Arc::new(|_, _| {
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec()
    }));
    let Some(addr) = start(vec![route("/c/", up.addr, false, 5)]) else { return };
    let (head, body) = exchange(addr, "GET /c/x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert!(head.contains("Content-Length: 11"), "{head}");
    assert!(!head.to_ascii_lowercase().contains("transfer-encoding"));
    assert_eq!(body, b"hello world");
}

#[test]
fn upstream_connections_are_pooled_and_reused() {
    let up = spawn_upstream(Arc::new(|_, _| ok("pooled")));
    let Some(addr) = start(vec![route("/p/", up.addr, false, 5)]) else { return };

    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = [0u8; 4096];
    for _ in 0..5 {
        s.write_all(b"GET /p/x HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        let n = s.read(&mut buf).unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("HTTP/1.1 200 OK"));
    }
    assert_eq!(up.accepts.load(Ordering::SeqCst), 1, "all requests should share one upstream socket");
}

#[test]
fn dead_upstream_gives_502() {
    // Bind then drop to get a port that refuses connections.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let Some(addr) = start(vec![route("/d/", dead, false, 5)]) else { return };
    let (head, body) = exchange(addr, "GET /d/x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(body, b"bad gateway\n");
}

#[test]
fn slow_upstream_gives_504() {
    let up = spawn_upstream(Arc::new(|_, _| {
        std::thread::sleep(Duration::from_secs(5));
        ok("too late")
    }));
    let Some(addr) = start(vec![route("/slow/", up.addr, false, 1)]) else { return };
    let (head, _) = exchange(addr, "GET /slow/x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 504"), "{head}");
}

#[test]
fn oversized_and_chunked_requests_are_rejected() {
    let up = spawn_upstream(Arc::new(|_, _| ok("x")));
    let Some(addr) = start(vec![route("/a/", up.addr, false, 5)]) else { return };
    let (head, _) = exchange(addr, "POST /a/x HTTP/1.1\r\nHost: h\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 413"), "{head}");
    let (head, _) = exchange(addr, "POST /a/x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 411"), "{head}");
}

#[test]
fn health_and_unmatched_paths_stay_local() {
    let up = spawn_upstream(Arc::new(|_, _| ok("proxied")));
    let Some(addr) = start(vec![route("/api/", up.addr, false, 5)]) else { return };
    let (head, body) = exchange(addr, "GET /health HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(body, b"ok\n");
    let (head, _) = exchange(addr, "GET /elsewhere HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 404"));
    assert!(up.seen.lock().unwrap().is_empty());
}

#[test]
fn pipelined_requests_around_a_proxied_one() {
    let up = spawn_upstream(Arc::new(|_, _| ok("mid")));
    let Some(addr) = start(vec![route("/api/", up.addr, false, 5)]) else { return };
    let raw = "GET /health HTTP/1.1\r\nHost: h\r\n\r\n\
               GET /api/x HTTP/1.1\r\nHost: h\r\n\r\n\
               GET /health HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 3, "{text}");
    let first = text.find("ok\n").unwrap();
    let mid = text.find("mid").unwrap();
    assert!(first < mid, "responses must keep request order");
}
