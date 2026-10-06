//! FastCGI / PHP-FPM end-to-end tests: a real worker in front of a small
//! in-process FastCGI application server (TCP and Unix socket). Skips
//! (passes) if io_uring is unavailable. Real PHP-FPM is covered by
//! `scripts/php-smoke.sh`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use vajra::config::{Dynamic, ProxySettings, StaticSettings, UpAddr};
use vajra::fastcgi;
use vajra::php::PhpConfig;
use vajra::sys;
use vajra::worker::{Config, Listener, Worker};

// ───────────────────────── mock FastCGI application server ─────────────────────────

enum Answer {
    /// CGI output, sent as STDOUT records followed by END_REQUEST.
    Cgi(Vec<u8>),
    /// CGI output plus a STDERR record.
    CgiWithStderr(Vec<u8>, Vec<u8>),
    /// Bytes that are not FastCGI at all.
    Raw(Vec<u8>),
    /// Partial output, then the connection is closed without END_REQUEST.
    Truncated(Vec<u8>),
}

type App = dyn Fn(&HashMap<String, String>, &[u8]) -> Answer + Send + Sync + 'static;

fn record(ty: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![1, ty, 0, 1];
    v.extend_from_slice(&(content.len() as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(content);
    v
}

/// Read one request (up to the empty STDIN record) and answer it.
fn serve<S: Read + Write>(mut s: S, app: &App) {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let (mut params_blob, mut stdin) = (Vec::new(), Vec::new());
    let mut begun = false;
    'read: loop {
        while buf.len() >= 8 {
            let len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            let total = 8 + len + buf[6] as usize;
            if buf.len() < total {
                break;
            }
            let ty = buf[1];
            let content = buf[8..8 + len].to_vec();
            buf.drain(..total);
            match ty {
                fastcgi::BEGIN_REQUEST => {
                    assert_eq!(content[..3], [0, 1, 0], "responder role, KEEP_CONN unset");
                    begun = true;
                }
                fastcgi::PARAMS => params_blob.extend(content),
                fastcgi::STDIN => {
                    if content.is_empty() {
                        break 'read;
                    }
                    stdin.extend(content);
                }
                _ => {}
            }
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    assert!(begun, "BEGIN_REQUEST must come first");
    let params: HashMap<String, String> = fastcgi::decode_params(&params_blob)
        .expect("valid params")
        .into_iter()
        .map(|(k, v)| (String::from_utf8_lossy(&k).into_owned(), String::from_utf8_lossy(&v).into_owned()))
        .collect();

    let mut out = Vec::new();
    let stdout = |out: &mut Vec<u8>, data: &[u8]| {
        for c in data.chunks(1000) {
            out.extend(record(fastcgi::STDOUT, c));
        }
        out.extend(record(fastcgi::STDOUT, &[]));
    };
    let end = record(fastcgi::END_REQUEST, &[0, 0, 0, 0, 0, 0, 0, 0]);
    match app(&params, &stdin) {
        Answer::Cgi(d) => {
            stdout(&mut out, &d);
            out.extend(end);
        }
        Answer::CgiWithStderr(d, e) => {
            out.extend(record(fastcgi::STDERR, &e));
            stdout(&mut out, &d);
            out.extend(end);
        }
        Answer::Raw(r) => out = r,
        Answer::Truncated(d) => {
            for c in d.chunks(1000) {
                out.extend(record(fastcgi::STDOUT, c));
            }
        }
    }
    let _ = s.write_all(&out);
    let _ = s.flush();
    // Dropping the stream closes the connection, as PHP-FPM does without KEEP_CONN.
}

struct Fpm {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

fn spawn_fpm(app: Arc<App>) -> Fpm {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { break };
            h2.fetch_add(1, Ordering::SeqCst);
            let app = app.clone();
            std::thread::spawn(move || serve(c, &*app));
        }
    });
    Fpm { addr, hits }
}

fn spawn_fpm_unix(path: &Path, app: Arc<App>) -> Arc<AtomicUsize> {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { break };
            h2.fetch_add(1, Ordering::SeqCst);
            let app = app.clone();
            std::thread::spawn(move || serve(c, &*app));
        }
    });
    hits
}

/// A PHP-ish app: echoes the interesting CGI variables as text/plain.
fn echo_app() -> Arc<App> {
    Arc::new(|p, stdin| {
        let g = |k: &str| p.get(k).cloned().unwrap_or_else(|| "-".into());
        let body = format!(
            "script={} name={} path_info={} uri={} qs={} method={} root={} https={} remote={} len={} ctype={} cookie={} xff={} proxy={} stdin={}",
            g("SCRIPT_FILENAME"), g("SCRIPT_NAME"), g("PATH_INFO"), g("REQUEST_URI"), g("QUERY_STRING"),
            g("REQUEST_METHOD"), g("DOCUMENT_ROOT"), g("HTTPS"), g("REMOTE_ADDR"), g("CONTENT_LENGTH"),
            g("CONTENT_TYPE"), g("HTTP_COOKIE"), g("HTTP_X_FORWARDED_FOR"), g("HTTP_PROXY"),
            String::from_utf8_lossy(stdin),
        );
        Answer::Cgi(format!("Content-Type: text/plain\r\nX-Powered-By: mock\r\n\r\n{body}").into_bytes())
    })
}

// ───────────────────────── site + server fixtures ─────────────────────────

fn make_site(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("vajra-phptest-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["wp-content/uploads", "wp-admin", ".git"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    for (f, c) in [
        ("index.php", "<?php // front"),
        ("wp-login.php", "<?php // login"),
        ("wp-admin/index.php", "<?php // admin"),
        ("style.css", "body{color:red}"),
        ("wp-content/uploads/evil.php", "<?php evil"),
        ("wp-content/uploads/pic.jpg", "JPEGDATA"),
        (".git/config", "secret"),
    ] {
        std::fs::write(root.join(f), c).unwrap();
    }
    std::fs::canonicalize(root).unwrap()
}

fn php_route(root: &Path, ups: Vec<UpAddr>, timeout: u64) -> ProxySettings {
    let mut p = ProxySettings::simple("", "127.0.0.1:1".parse().unwrap(), false, timeout);
    p.upstreams = ups;
    p.php = Some(PhpConfig::wordpress(root));
    p
}

fn start(root: &Path, proxies: Vec<ProxySettings>, cfg: Config) -> Option<SocketAddr> {
    let sock = sys::listener("127.0.0.1:0".parse().unwrap(), false, 128).unwrap();
    let addr = sock.local_addr().unwrap().as_socket().unwrap();
    let (tx, rx) = mpsc::channel();
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        let l = [Listener { fd: sock.as_raw_fd(), tls: false }];
        let dynamic = Dynamic {
            static_files: Some(StaticSettings::new(&root).unwrap()),
            proxies,
            ..Dynamic::default()
        };
        match Worker::new(&l, cfg, &dynamic, None) {
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

struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Resp {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn header_count(&self, name: &str) -> usize {
        let n = format!("{}:", name.to_ascii_lowercase());
        self.head.lines().filter(|l| l.to_ascii_lowercase().starts_with(&n)).count()
    }
}

fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response head") + 4;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    Resp { status, head, body: raw[split..].to_vec() }
}

fn get(addr: SocketAddr, path: &str) -> Resp {
    http(addr, "GET", path, &[], b"")
}

// ───────────────────────── tests ─────────────────────────

#[test]
fn wordpress_routing() {
    let root = make_site("routing");
    let fpm = spawn_fpm(echo_app());
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 5)], Config::default()) else { return };
    let r = root.to_str().unwrap();

    let t = get(addr, "/wp-login.php?redirect_to=%2Fwp-admin%2F");
    assert_eq!(t.status, 200);
    let b = t.text();
    assert!(b.contains(&format!("script={r}/wp-login.php")), "{b}");
    assert!(b.contains("name=/wp-login.php") && b.contains("path_info=-"), "{b}");
    assert!(b.contains("qs=redirect_to=%2Fwp-admin%2F") && b.contains(&format!("root={r} ")), "{b}");
    assert!(t.head.contains("X-Powered-By: mock") && t.head.to_ascii_lowercase().contains("content-type: text/plain"));

    // Pretty permalink: front controller, original URI preserved.
    let b = get(addr, "/2026/10/hello-world/?p=2").text();
    assert!(b.contains(&format!("script={r}/index.php")) && b.contains("uri=/2026/10/hello-world/?p=2"), "{b}");

    // PATH_INFO split.
    let b = get(addr, "/index.php/foo/bar").text();
    assert!(b.contains("name=/index.php") && b.contains("path_info=/foo/bar"), "{b}");

    // Directory indexes.
    assert!(get(addr, "/").text().contains(&format!("script={r}/index.php")));
    assert!(get(addr, "/wp-admin/").text().contains(&format!("script={r}/wp-admin/index.php")));
    assert!(get(addr, "/wp-admin").text().contains(&format!("script={r}/wp-admin/index.php")));

    let before = fpm.hits.load(Ordering::SeqCst);
    // Static files never reach PHP.
    let css = get(addr, "/style.css");
    assert_eq!((css.status, css.text().as_str()), (200, "body{color:red}"));
    let jpg = get(addr, "/wp-content/uploads/pic.jpg");
    assert_eq!((jpg.status, jpg.text().as_str()), (200, "JPEGDATA"));
    // Missing / denied / hidden scripts and files never reach PHP either.
    assert_eq!(get(addr, "/nope.php").status, 404);
    assert_eq!(get(addr, "/style.css/x.php").status, 404, "must not run style.css");
    assert_eq!(get(addr, "/wp-content/uploads/evil.php").status, 404, "no execution in uploads");
    assert_eq!(get(addr, "/wp-content/uploads/pic.jpg/x.php").status, 404);
    assert_eq!(get(addr, "/.git/config").status, 404);
    assert_eq!(get(addr, "/%2e%2e/etc/passwd").status, 400);
    assert_eq!(get(addr, "/a%00.php").status, 400);
    assert_eq!(fpm.hits.load(Ordering::SeqCst), before, "none of those touched the application");

    // Built-in endpoints still win.
    assert_eq!(get(addr, "/health").text(), "ok\n");
    // POST to a static file is not a script request.
    assert_eq!(http(addr, "POST", "/style.css", &[], b"x").status, 405);
}

#[test]
fn post_body_headers_and_spoofing() {
    let root = make_site("post");
    let fpm = spawn_fpm(echo_app());
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 5)], Config::default()) else { return };

    let r = http(
        addr,
        "POST",
        "/wp-login.php",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Cookie", "wordpress_test_cookie=WP+Cookie+check"),
            ("X-Forwarded-For", "6.6.6.6"),
            ("Proxy", "http://evil.test:8080"),
        ],
        b"log=admin&pwd=secret",
    );
    assert_eq!(r.status, 200);
    let b = r.text();
    assert!(b.contains("method=POST") && b.contains("len=20") && b.contains("stdin=log=admin&pwd=secret"), "{b}");
    assert!(b.contains("ctype=application/x-www-form-urlencoded"), "{b}");
    assert!(b.contains("cookie=wordpress_test_cookie=WP+Cookie+check"), "{b}");
    assert!(b.contains("remote=127.0.0.1"), "{b}");
    assert!(b.contains("xff=- ") && b.contains("proxy=- "), "client X-Forwarded-For / Proxy must not reach PHP: {b}");
    assert!(b.contains("https=- "), "plain HTTP listener: {b}");
}

#[test]
fn large_request_and_response() {
    let root = make_site("large");
    let big_resp: Arc<App> = Arc::new(|_, stdin| {
        let mut out = b"Content-Type: application/octet-stream\r\n\r\n".to_vec();
        out.extend(std::iter::repeat(b'z').take(300_000));
        out.extend(format!("|{}", stdin.len()).bytes());
        Answer::Cgi(out)
    });
    let fpm = spawn_fpm(big_resp);
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 10)], Config::default()) else { return };
    let upload = vec![b'u'; 200_000]; // > 3 STDIN records
    let r = http(addr, "POST", "/wp-login.php", &[("Content-Type", "application/octet-stream")], &upload);
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 300_000 + "|200000".len());
    assert!(r.body.ends_with(b"zzz|200000"));
}

#[test]
fn status_redirect_and_multiple_cookies() {
    let root = make_site("status");
    let app: Arc<App> = Arc::new(|p, _| {
        let uri = p.get("REQUEST_URI").cloned().unwrap_or_default();
        if uri.starts_with("/index.php/redirect") {
            Answer::Cgi(b"Location: /wp-admin/\r\nSet-Cookie: a=1; path=/\r\nSet-Cookie: b=2; path=/\r\n\r\n".to_vec())
        } else if uri.starts_with("/index.php/gone") {
            Answer::Cgi(b"Status: 410 Gone\r\nContent-Type: text/plain\r\n\r\nit is gone".to_vec())
        } else if uri.starts_with("/index.php/empty") {
            Answer::Cgi(b"Status: 204 No Content\r\n\r\n".to_vec())
        } else {
            Answer::Cgi(b"Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\nplain".to_vec())
        }
    });
    let fpm = spawn_fpm(app);
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 5)], Config::default()) else { return };

    let r = get(addr, "/index.php/redirect");
    assert_eq!(r.status, 302);
    assert!(r.head.contains("Location: /wp-admin/"));
    assert_eq!(r.header_count("set-cookie"), 2, "both cookies survive: {}", r.head);

    let r = get(addr, "/index.php/gone");
    assert_eq!((r.status, r.text().as_str()), (410, "it is gone"));
    assert_eq!(get(addr, "/index.php/empty").status, 204);

    // The application's own framing headers are ignored and replaced.
    let r = get(addr, "/index.php/plain");
    assert_eq!((r.status, r.text().as_str()), (200, "plain"));
    assert_eq!(r.header_count("content-length"), 1);
    assert!(!r.head.to_ascii_lowercase().contains("999"));
}

#[test]
fn head_requests_have_no_body() {
    let root = make_site("head");
    let fpm = spawn_fpm(echo_app());
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 5)], Config::default()) else { return };
    let r = http(addr, "HEAD", "/index.php", &[], b"");
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
}

#[test]
fn broken_applications_give_502() {
    let root = make_site("broken");
    let app: Arc<App> = Arc::new(|p, _| {
        let uri = p.get("REQUEST_URI").cloned().unwrap_or_default();
        if uri.contains("garbage") {
            Answer::Raw(b"HTTP/1.1 200 OK\r\n\r\nthis is not fastcgi".to_vec())
        } else if uri.contains("truncated") {
            Answer::Truncated(b"Content-Type: text/plain\r\n\r\nhalf a respo".to_vec())
        } else if uri.contains("nohead") {
            Answer::Cgi(b"just a body without a header block".to_vec())
        } else if uri.contains("empty") {
            Answer::Cgi(Vec::new())
        } else {
            Answer::CgiWithStderr(b"Content-Type: text/plain\r\n\r\nfine".to_vec(), b"PHP Warning: something".to_vec())
        }
    });
    let fpm = spawn_fpm(app);
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 5)], Config::default()) else { return };
    for p in ["/index.php/garbage", "/index.php/truncated", "/index.php/nohead", "/index.php/empty"] {
        assert_eq!(get(addr, p).status, 502, "{p}");
    }
    // stderr output does not break an otherwise good response.
    assert_eq!(get(addr, "/index.php/ok").text(), "fine");
}

#[test]
fn dead_application_gives_502_and_slow_one_504() {
    let root = make_site("dead");
    // Nothing listens on this port.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let Some(addr) = start(&root, vec![php_route(&root, vec![dead.into()], 2)], Config::default()) else { return };
    assert_eq!(get(addr, "/index.php").status, 502);

    let slow: Arc<App> = Arc::new(|_, _| {
        std::thread::sleep(Duration::from_secs(4));
        Answer::Cgi(b"Content-Type: text/plain\r\n\r\nlate".to_vec())
    });
    let fpm = spawn_fpm(slow);
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 1)], Config::default()) else { return };
    assert_eq!(get(addr, "/index.php").status, 504);
}

#[test]
fn failover_to_a_second_application_server() {
    let root = make_site("failover");
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let fpm = spawn_fpm(echo_app());
    let Some(addr) =
        start(&root, vec![php_route(&root, vec![dead.into(), fpm.addr.into()], 3)], Config::default())
    else {
        return;
    };
    for _ in 0..6 {
        assert_eq!(get(addr, "/index.php").status, 200, "GET fails over past the dead upstream");
    }
    assert!(fpm.hits.load(Ordering::SeqCst) >= 6);
}

#[test]
fn unix_socket_upstream() {
    let root = make_site("unix");
    let sock = std::env::temp_dir().join(format!("vajra-fpm-{}.sock", std::process::id()));
    let hits = spawn_fpm_unix(&sock, echo_app());
    let Some(addr) = start(&root, vec![php_route(&root, vec![UpAddr::Unix(sock.clone())], 5)], Config::default())
    else {
        return;
    };
    let r = get(addr, "/index.php/via/unix");
    assert_eq!(r.status, 200);
    assert!(r.text().contains("path_info=/via/unix"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_file(sock);
}

#[test]
fn many_concurrent_requests() {
    let root = make_site("conc");
    let fpm = spawn_fpm(echo_app());
    let Some(addr) = start(&root, vec![php_route(&root, vec![fpm.addr.into()], 10)], Config::default()) else { return };
    let handles: Vec<_> = (0..64)
        .map(|i| {
            std::thread::spawn(move || {
                let r = get(addr, &format!("/index.php/n{i}?i={i}"));
                assert_eq!(r.status, 200);
                assert!(r.text().contains(&format!("path_info=/n{i} ")), "{}", r.text());
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(fpm.hits.load(Ordering::SeqCst), 64, "one FastCGI connection per request");
}
