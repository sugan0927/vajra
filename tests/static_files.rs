//! End-to-end static file tests: a real worker, real io_uring, real splice.
//! Each test skips (passes) if the environment forbids io_uring.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use vajra::config::StaticSettings;
use vajra::sys;
use vajra::worker::{Config, Worker};

const SMALL: &[u8] = b"hello static\n";
const BIG_LEN: usize = 1_500_000;

fn big_body() -> Vec<u8> {
    (0..BIG_LEN).map(|i| (i % 251) as u8).collect()
}

fn make_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("vajra-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), SMALL).unwrap();
    std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::write(root.join("big.bin"), big_body()).unwrap();
    std::fs::write(root.join("empty.txt"), "").unwrap();
    std::fs::write(root.join(".hidden"), "secret").unwrap();
    root
}

fn start(root: &Path) -> Option<SocketAddr> {
    let sock = sys::listener("127.0.0.1:0".parse().unwrap(), false, 128).unwrap();
    let addr = sock.local_addr().unwrap().as_socket().unwrap();
    let settings = StaticSettings::new(root).unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        match Worker::plain(sock.as_raw_fd(), Config::default(), Some(&settings)) {
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

/// Send raw bytes, read until the server closes, split head/body.
fn exchange(addr: SocketAddr, raw: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end") + 4;
    (String::from_utf8_lossy(&buf[..split]).into_owned(), buf[split..].to_vec())
}

fn get(addr: SocketAddr, path: &str) -> (String, Vec<u8>) {
    exchange(addr, &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
}

#[test]
fn serves_small_file_with_headers() {
    let Some(addr) = start(&make_root("small")) else { return };
    let (head, body) = get(addr, "/a.txt");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("Content-Type: text/plain; charset=utf-8"));
    assert!(head.contains(&format!("Content-Length: {}", SMALL.len())));
    assert!(head.contains("ETag: \""));
    assert!(head.contains("Last-Modified: "));
    assert_eq!(body, SMALL);
}

#[test]
fn serves_large_file_intact_via_splice() {
    let Some(addr) = start(&make_root("big")) else { return };
    let (head, body) = get(addr, "/big.bin");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(body.len(), BIG_LEN);
    assert!(body == big_body(), "body corrupted in transit");
}

#[test]
fn index_for_root_path() {
    let Some(addr) = start(&make_root("index")) else { return };
    let (head, body) = get(addr, "/");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.contains("text/html"));
    assert_eq!(body, b"<h1>home</h1>");
}

#[test]
fn head_and_conditional_requests() {
    let Some(addr) = start(&make_root("cond")) else { return };

    let (head, body) = exchange(addr, "HEAD /a.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.contains(&format!("Content-Length: {}", SMALL.len())));
    assert!(body.is_empty());

    let etag = head
        .lines()
        .find_map(|l| l.strip_prefix("ETag: "))
        .expect("etag header")
        .to_string();
    let req = format!(
        "GET /a.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
    );
    let (head, body) = exchange(addr, &req);
    assert!(head.starts_with("HTTP/1.1 304 Not Modified"), "{head}");
    assert!(body.is_empty());
}

#[test]
fn empty_file_has_no_body() {
    let Some(addr) = start(&make_root("empty")) else { return };
    let (head, body) = get(addr, "/empty.txt");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.contains("Content-Length: 0"));
    assert!(body.is_empty());
}

#[test]
fn missing_hidden_and_traversal() {
    let Some(addr) = start(&make_root("sec")) else { return };
    assert!(get(addr, "/missing.txt").0.starts_with("HTTP/1.1 404"));
    assert!(get(addr, "/.hidden").0.starts_with("HTTP/1.1 404"));
    assert!(get(addr, "/../etc/passwd").0.starts_with("HTTP/1.1 400"));
    assert!(get(addr, "/%2e%2e/etc/passwd").0.starts_with("HTTP/1.1 400"));
    assert!(get(addr, "/a.txt%00.png").0.starts_with("HTTP/1.1 400"));
}

#[test]
fn pipelined_file_requests_on_one_connection() {
    let Some(addr) = start(&make_root("pipe")) else { return };
    // Two file responses back to back plus a built-in route, all pipelined.
    let raw = "GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n\
               GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n\
               GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);

    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 3, "{text}");
    assert_eq!(text.matches("hello static").count(), 2);
    assert!(text.ends_with("ok\n"));
}

#[test]
fn concurrent_large_transfers_reuse_pipes() {
    let Some(addr) = start(&make_root("conc")) else { return };
    let expected = big_body();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let expected = expected.clone();
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let (head, body) = get(addr, "/big.bin");
                    assert!(head.starts_with("HTTP/1.1 200 OK"));
                    assert!(body == expected);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn client_hanging_up_mid_transfer_does_not_wedge_the_worker() {
    let Some(addr) = start(&make_root("abort")) else { return };
    for _ in 0..10 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut one = [0u8; 16];
        let _ = s.read(&mut one);
        drop(s); // RST/FIN while splice is in flight
    }
    // The worker must still answer afterwards.
    let (head, body) = get(addr, "/a.txt");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(body, SMALL);
}
