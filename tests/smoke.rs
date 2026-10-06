//! End-to-end test: run a real worker (real io_uring) on an ephemeral port and
//! talk to it over TCP. Skips (passes) if the environment forbids io_uring,
//! e.g. a default Docker seccomp profile.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::mpsc;
use std::time::Duration;

use vajra::sys;
use vajra::worker::{Config, Worker};

/// Start a worker; returns its address, or None if io_uring is unavailable.
fn start_server() -> Option<SocketAddr> {
    let sock = sys::listener("127.0.0.1:0".parse().unwrap(), false, 128).unwrap();
    let addr = sock.local_addr().unwrap().as_socket().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        match Worker::plain(sock.as_raw_fd(), Config::default(), None) {
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

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

#[test]
fn pipelined_requests_then_close() {
    let Some(addr) = start_server() else { return };
    let mut s = connect(addr);

    s.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n\
          GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .unwrap();

    let mut out = String::new();
    s.read_to_string(&mut out).unwrap(); // server closes after the 2nd response
    assert_eq!(out.matches("HTTP/1.1 200 OK").count(), 2, "got: {out}");
    assert!(out.contains("Vajra"));
}

#[test]
fn keepalive_serves_many_sequential_requests() {
    let Some(addr) = start_server() else { return };
    let mut s = connect(addr);
    let mut buf = [0u8; 4096];

    for _ in 0..100 {
        s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let n = s.read(&mut buf).unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }
}

#[test]
fn request_split_across_packets() {
    let Some(addr) = start_server() else { return };
    let mut s = connect(addr);
    s.set_nodelay(true).unwrap();

    s.write_all(b"GET / HT").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    s.write_all(b"TP/1.1\r\nHost: x\r\n\r\n").unwrap();

    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).unwrap();
    assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("HTTP/1.1 200 OK"));
}

#[test]
fn many_concurrent_connections() {
    let Some(addr) = start_server() else { return };
    let handles: Vec<_> = (0..64)
        .map(|_| {
            std::thread::spawn(move || {
                let mut s = connect(addr);
                for _ in 0..20 {
                    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                    let mut buf = [0u8; 1024];
                    let n = s.read(&mut buf).unwrap();
                    assert!(n > 0);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
