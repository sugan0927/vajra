//! Control-plane manager and the admin HTTP endpoint.
//!
//! [`Manager`] is the only thing that talks to all workers at once: it fans a
//! command out over the per-worker control channels and gathers the replies.
//! Three front-ends use it:
//!
//! * the admin HTTP server below (`GET /metrics`, `POST /reload`, `GET /healthz`),
//! * the signal loop in `main` (`SIGHUP` = reload, `SIGINT`/`SIGTERM` = shutdown),
//! * tests.
//!
//! ## Why the admin server is a plain blocking thread
//! It is control plane, not data plane: a handful of requests per minute from a
//! monitoring system. Running it on its own thread keeps scrapes from ever
//! touching a worker's event loop; the workers only see a `Cmd::Scrape` message.
//! (This is a deliberate exception to "io_uring for all I/O".)
//!
//! **The admin endpoint has no authentication.** Bind it to loopback or an
//! internal network only. Requests are served one at a time with 5 s socket
//! timeouts, so a stalled client delays other admin requests, never traffic.
//!
//! ## Reload semantics
//! 1. Re-read and validate the config file (any error aborts, nothing changes).
//! 2. Build the TLS config once to fail early on a bad certificate.
//! 3. Send the new [`Dynamic`] settings to every worker; each validates, builds
//!    its new state (file cache, route table, TLS config, log file) and then swaps
//!    it in. Existing connections keep running; in-flight requests finish on the
//!    configuration they started with.
//! 4. Settings that cannot change at runtime (listen addresses, worker count,
//!    limits) are reported, not applied.
//!
//! The swap is per worker, so a reload is not atomic across cores: for a few
//! milliseconds different cores can serve different generations.

use crate::config::Settings;
use crate::control::{Cmd, Handle, Snapshot};
use crate::observe;
use crate::tls;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SCRAPE_TIMEOUT: Duration = Duration::from_secs(3);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);
const TEXT: &str = "text/plain; charset=utf-8";
const PROM: &str = "text/plain; version=0.0.4; charset=utf-8";

pub struct Manager {
    handles: Vec<Handle>,
    config_path: Option<PathBuf>,
    running: Mutex<Settings>,
}

impl Manager {
    pub fn new(handles: Vec<Handle>, config_path: Option<PathBuf>, running: Settings) -> Self {
        Self { handles, config_path, running: Mutex::new(running) }
    }

    /// Gather a snapshot from every worker and render Prometheus text.
    pub fn scrape(&self) -> String {
        let (tx, rx) = mpsc::channel::<Snapshot>();
        let mut expected = 0;
        for h in &self.handles {
            if h.send(Cmd::Scrape(tx.clone())) {
                expected += 1;
            }
        }
        drop(tx);

        let deadline = Instant::now() + SCRAPE_TIMEOUT;
        let mut snaps = Vec::with_capacity(expected);
        while snaps.len() < expected {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(s) => snaps.push(s),
                Err(_) => break,
            }
        }
        snaps.sort_by_key(|s| s.worker);
        observe::render_prometheus(&snaps)
    }

    /// Re-read the config file and push the reloadable part to every worker.
    pub fn reload(&self) -> Result<String, String> {
        let path = self
            .config_path
            .as_ref()
            .ok_or_else(|| "no config file was given at startup; nothing to reload".to_string())?;
        let new = Settings::load(path)?;

        if let Some(t) = &new.tls {
            tls::build_server_config(&t.cert, &t.key)?; // fail early, change nothing
        }

        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let pending_restart = running.restart_required(&new);

        let dynamic = Arc::new(new.dynamic());
        let (ack, rx) = mpsc::channel::<Result<(), String>>();
        let mut expected = 0;
        for h in &self.handles {
            if h.send(Cmd::Reload { dynamic: Arc::clone(&dynamic), ack: ack.clone() }) {
                expected += 1;
            }
        }
        drop(ack);

        let deadline = Instant::now() + RELOAD_TIMEOUT;
        let (mut ok, mut errors) = (0usize, Vec::new());
        while ok + errors.len() < expected {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Ok(())) => ok += 1,
                Ok(Err(e)) => errors.push(e),
                Err(_) => {
                    errors.push("timed out waiting for a worker".to_string());
                    break;
                }
            }
        }
        if !errors.is_empty() {
            errors.dedup();
            return Err(format!("{ok}/{expected} workers applied the new config; {}", errors.join("; ")));
        }

        // Remember the reloadable parts; keep the rest as actually running.
        running.static_files = new.static_files.clone();
        running.proxies = new.proxies.clone();
        running.tls = match (&running.tls, &new.tls) {
            (Some(old), Some(n)) => Some(crate::config::TlsSettings { listen: old.listen, cert: n.cert.clone(), key: n.key.clone() }),
            (old, _) => old.clone(),
        };
        running.access_log = new.access_log.clone();
        running.cache = new.cache;

        let mut msg = format!("reloaded {ok} worker(s): {} proxy route(s)", dynamic.proxies.len());
        if !pending_restart.is_empty() {
            msg.push_str(&format!("; restart required for: {}", pending_restart.join(", ")));
        }
        Ok(msg)
    }

    /// Ask every worker to drain and exit.
    pub fn shutdown(&self) {
        for h in &self.handles {
            h.send(Cmd::Shutdown);
        }
    }
}

/// Map an admin request to `(status, content-type, body)`.
pub fn route_admin(method: &str, path: &str, mgr: &Manager) -> (u16, &'static str, String) {
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        ("GET" | "HEAD", "/metrics") => (200, PROM, mgr.scrape()),
        ("GET" | "HEAD", "/healthz") => (200, TEXT, "ok\n".to_string()),
        ("POST", "/reload") => match mgr.reload() {
            Ok(m) => (200, TEXT, format!("{m}\n")),
            Err(e) => (500, TEXT, format!("reload failed: {e}\n")),
        },
        (_, "/metrics" | "/healthz" | "/reload") => (405, TEXT, "method not allowed\n".to_string()),
        _ => (404, TEXT, "not found\n".to_string()),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    }
}

fn write_response(s: &mut TcpStream, status: u16, ctype: &str, body: &str, head_only: bool) {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    if !head_only {
        let _ = s.write_all(body.as_bytes());
    }
}

fn handle(mut s: TcpStream, mgr: &Manager) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; 8192];
    let mut n = 0;
    loop {
        match s.read(&mut buf[n..]) {
            Ok(0) | Err(_) => return,
            Ok(k) => n += k,
        }
        let mut hs = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut hs);
        match req.parse(&buf[..n]) {
            Ok(httparse::Status::Complete(_)) => {
                let method = req.method.unwrap_or("");
                let (status, ctype, body) = route_admin(method, req.path.unwrap_or("/"), mgr);
                write_response(&mut s, status, ctype, &body, method == "HEAD");
                return;
            }
            Ok(httparse::Status::Partial) => {
                if n == buf.len() {
                    write_response(&mut s, 400, TEXT, "request too large\n", false);
                    return;
                }
            }
            Err(_) => {
                write_response(&mut s, 400, TEXT, "bad request\n", false);
                return;
            }
        }
    }
}

/// Bind the admin listener and serve it on a dedicated thread.
/// Returns the bound address (useful with port 0) and the thread handle.
pub fn serve(addr: SocketAddr, mgr: Arc<Manager>) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let h = thread::Builder::new().name("vajra-admin".into()).spawn(move || {
        for conn in listener.incoming() {
            if let Ok(s) = conn {
                handle(s, &mgr);
            }
        }
    })?;
    Ok((bound, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_manager() -> Manager {
        Manager::new(Vec::new(), None, Settings::default())
    }

    #[test]
    fn routing_table() {
        let m = empty_manager();
        let (s, c, b) = route_admin("GET", "/healthz", &m);
        assert_eq!((s, c, b.as_str()), (200, TEXT, "ok\n"));
        let (s, c, b) = route_admin("GET", "/metrics?x=1", &m);
        assert_eq!((s, c), (200, PROM));
        assert!(b.contains("vajra_workers 0\n"));
        assert_eq!(route_admin("DELETE", "/metrics", &m).0, 405);
        assert_eq!(route_admin("GET", "/reload", &m).0, 405);
        assert_eq!(route_admin("GET", "/nope", &m).0, 404);
    }

    #[test]
    fn reload_without_config_file_is_an_error() {
        let m = empty_manager();
        let (s, _, b) = route_admin("POST", "/reload", &m);
        assert_eq!(s, 500);
        assert!(b.contains("nothing to reload"), "{b}");
    }

    #[test]
    fn reload_rejects_invalid_config_without_touching_workers() {
        let dir = std::env::temp_dir().join(format!("vajra-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.toml");
        std::fs::write(&p, "this is = not [valid").unwrap();
        let m = Manager::new(Vec::new(), Some(p), Settings::default());
        assert!(m.reload().is_err());
    }

    #[test]
    fn http_roundtrip_over_a_socket() {
        let m = Arc::new(empty_manager());
        let (addr, _h) = serve("127.0.0.1:0".parse().unwrap(), m).unwrap();
        let get = |req: &str| {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(req.as_bytes()).unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        let r = get("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK") && r.ends_with("ok\n"), "{r}");
        let r = get("HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(r.contains("Content-Length: 3") && r.ends_with("\r\n\r\n"));
        let r = get("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(r.contains("version=0.0.4") && r.contains("vajra_workers 0"));
        assert!(get("GET /zzz HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
        assert!(get("garbage\r\n\r\n").starts_with("HTTP/1.1 400"));
    }
}
