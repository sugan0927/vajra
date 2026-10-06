//! Vajra entry point: load settings, spawn one pinned worker thread per core,
//! start the admin endpoint, then wait for signals.
//!
//! * `SIGHUP`            -> reload the configuration file (hot, no dropped connections)
//! * `SIGINT`/`SIGTERM`  -> graceful shutdown (a second signal exits immediately)
//!
//! Each worker creates its **own** SO_REUSEPORT listeners (plain and, if
//! configured, TLS), its own io_uring, TLS config, file cache, response cache
//! and upstream pools, so threads share nothing after startup. The main thread
//! only talks to workers over their control channels.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use vajra::admin::{self, Manager};
use vajra::config::{Settings, StaticSettings};
use vajra::config::TlsPaths;
use vajra::control;
use vajra::quic::{self, QuicConfig};
use vajra::sys::{self, Signal};
use vajra::tls;
use vajra::worker::{Listener, Worker};

#[derive(Default)]
struct Cli {
    config: Option<PathBuf>,
    listen: Option<SocketAddr>,
    admin: Option<SocketAddr>,
    workers: Option<usize>,
    root: Option<PathBuf>,
    no_pin: bool,
    check: bool,
}

fn usage() -> ! {
    eprintln!(
        "vajra 0.7 - thread-per-core io_uring web server\n\n\
         USAGE: vajra [--config FILE] [--listen ADDR] [--admin ADDR] [--workers N]\n\
         \x20            [--root DIR] [--no-pin] [--check]\n\n\
         \x20 --config FILE   TOML configuration file (enables SIGHUP / POST /reload)\n\
         \x20 --listen ADDR   plain-HTTP address       (default 0.0.0.0:8080)\n\
         \x20 --admin ADDR    metrics/reload endpoint  (default: disabled; NO authentication)\n\
         \x20 --workers N     cores to use             (default 1; 0 = all CPUs)\n\
         \x20 --root DIR      serve static files from DIR\n\
         \x20 --no-pin        do not pin workers to CPUs\n\
         \x20 --check         validate the configuration and exit\n\n\
         Command-line flags override values from the config file.\n\
         Signals: SIGHUP reloads the config, SIGINT/SIGTERM shut down gracefully."
    );
    exit(2);
}

fn parse_cli() -> Cli {
    let mut cli = Cli::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => cli.config = Some(it.next().map(PathBuf::from).unwrap_or_else(|| usage())),
            "--listen" => cli.listen = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--admin" => cli.admin = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--workers" => cli.workers = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--root" => cli.root = Some(it.next().map(PathBuf::from).unwrap_or_else(|| usage())),
            "--no-pin" => cli.no_pin = true,
            "--check" => cli.check = true,
            _ => usage(),
        }
    }
    cli
}

fn die(msg: String) -> ! {
    eprintln!("vajra: {msg}");
    exit(1);
}

fn main() {
    let cli = parse_cli();

    let mut settings = match &cli.config {
        Some(path) => Settings::load(path).unwrap_or_else(|e| die(e)),
        None => Settings::default(),
    };
    if let Some(a) = cli.listen {
        settings.listen = a;
    }
    if let Some(a) = cli.admin {
        settings.admin = Some(a);
    }
    if let Some(w) = cli.workers {
        settings.workers = w;
    }
    if cli.no_pin {
        settings.pin = false;
    }
    if let Some(root) = &cli.root {
        settings.static_files = Some(StaticSettings::new(root).unwrap_or_else(|e| die(e)));
    }
    if settings.workers == 0 {
        settings.workers = sys::available_cpus();
    }

    // Fail fast on bad certificates instead of inside a worker thread.
    if let Some(t) = &settings.tls {
        if let Err(e) = tls::build_server_config(&t.cert, &t.key) {
            die(e);
        }
    }

    let quic_cfg = settings.quic.as_ref().map(|q| QuicConfig {
        retry: q.retry,
        idle_timeout: Duration::from_secs(q.idle_timeout_secs),
        max_bidi_streams: q.max_streams,
        ..QuicConfig::default()
    });
    if let (Some(qc), Some(t)) = (&quic_cfg, &settings.tls) {
        if let Err(e) = quic::server_config(&t.cert, &t.key, qc) {
            die(e);
        }
    }

    if cli.check {
        println!(
            "vajra: configuration ok ({} worker(s), {} proxy route(s), tls: {}, http3: {}, admin: {})",
            settings.workers,
            settings.proxies.len(),
            settings.tls.is_some(),
            settings.quic.is_some(),
            settings.admin.is_some()
        );
        return;
    }

    // Block the control signals before any thread exists so every thread
    // inherits the mask; only `wait_signal` below ever sees them.
    sys::block_signals().unwrap_or_else(|e| die(format!("cannot block signals: {e}")));
    // A write to a reset connection must never kill the process.
    // SAFETY: installing SIG_IGN is async-signal-safe and process-wide.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let ncpu = sys::available_cpus();
    println!("vajra: http  on {}  ({} worker(s))", settings.listen, settings.workers);
    if let Some(t) = &settings.tls {
        println!("vajra: https on {}  (HTTP/2 via ALPN)", t.listen);
    }
    if let Some(q) = &settings.quic {
        println!("vajra: http3 on {} (udp{})", q.listen, if q.retry { ", retry" } else { "" });
    }
    if let Some(s) = &settings.static_files {
        println!("vajra: static root {}", s.root.display());
    }
    for p in &settings.proxies {
        if let Some(php) = &p.php {
            println!(
                "vajra: php (fastcgi) -> {} upstream(s), root {}{}",
                p.upstreams.len(),
                php.root.display(),
                match &php.front_controller {
                    Some(f) => format!(", front controller {f}"),
                    None => String::new(),
                }
            );
            continue;
        }
        println!(
            "vajra: proxy {} -> {} upstream(s) [{:?}]{}",
            p.prefix,
            p.upstreams.len(),
            p.balance,
            if p.cache { " +cache" } else { "" }
        );
    }
    if let Some(l) = &settings.access_log {
        println!("vajra: access log {l}");
    }

    let dynamic = settings.dynamic();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let mut handles = Vec::with_capacity(settings.workers);
    let mut joins = Vec::with_capacity(settings.workers);

    for core in 0..settings.workers {
        // Bind in the main thread so bind errors abort startup immediately.
        let plain = sys::listener(settings.listen, true, 4096)
            .unwrap_or_else(|e| die(format!("cannot bind {}: {e}", settings.listen)));
        let secure = settings.tls.as_ref().map(|t| {
            sys::listener(t.listen, true, 4096)
                .unwrap_or_else(|e| die(format!("cannot bind {}: {e}", t.listen)))
        });
        let udp = settings.quic.as_ref().map(|q| {
            sys::udp_listener(q.listen, true)
                .unwrap_or_else(|e| die(format!("cannot bind udp {}: {e}", q.listen)))
        });
        let (handle, inbox) = control::channel().unwrap_or_else(|e| die(format!("eventfd: {e}")));
        handles.push(handle);

        let (settings, dynamic, ready) = (settings.clone(), dynamic.clone(), ready_tx.clone());
        let quic_cfg = quic_cfg.clone();
        let j = thread::Builder::new()
            .name(format!("vajra-{core}"))
            .spawn(move || {
                if settings.pin {
                    if let Err(e) = sys::pin_to_core(core % ncpu) {
                        eprintln!("vajra[{core}]: pin failed: {e}");
                    }
                }

                let mut listeners = vec![Listener { fd: plain.as_raw_fd(), tls: false }];
                let mut tls_cfg = None;
                if let (Some(sock), Some(t)) = (&secure, &settings.tls) {
                    listeners.push(Listener { fd: sock.as_raw_fd(), tls: true });
                    match tls::build_server_config(&t.cert, &t.key) {
                        Ok(c) => tls_cfg = Some(c),
                        Err(e) => {
                            let _ = ready.send(Err(format!("worker {core}: {e}")));
                            return;
                        }
                    }
                }

                // The ring (and all non-Send state) is created on this thread.
                let mut w = match Worker::new(&listeners, settings.worker, &dynamic, tls_cfg) {
                    Ok(w) => w,
                    Err(e) => {
                        let _ = ready.send(Err(format!("worker {core}: io_uring setup failed: {e}")));
                        return;
                    }
                };
                w.attach_control(core, inbox, Duration::from_secs(settings.grace_secs));
                if let (Some(sock), Some(q), Some(qc), Some(t)) = (&udp, &settings.quic, &quic_cfg, &settings.tls) {
                    match quic::server_config(&t.cert, &t.key, qc) {
                        Ok(server) => {
                            let alt = q.advertise.then(|| format!("h3=\":{}\"; ma=86400", q.listen.port()));
                            let paths = TlsPaths { cert: t.cert.clone(), key: t.key.clone() };
                            w.attach_quic(sock.as_raw_fd(), qc.clone(), server, Some(paths), alt.as_deref());
                        }
                        Err(e) => {
                            let _ = ready.send(Err(format!("worker {core}: {e}")));
                            return;
                        }
                    }
                }
                let _ = ready.send(Ok(()));
                drop(ready);

                if let Err(e) = w.run() {
                    eprintln!("vajra[{core}]: event loop failed: {e}");
                }
                drop(w);
                drop((plain, secure, udp)); // listeners must outlive the worker
            })
            .expect("spawn worker thread");
        joins.push(j);
    }
    drop(ready_tx);

    for _ in 0..settings.workers {
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => die(e),
            Err(_) => die("a worker exited during startup".into()),
        }
    }

    let manager = Arc::new(Manager::new(handles, cli.config.clone(), settings.clone()));
    if let Some(addr) = settings.admin {
        match admin::serve(addr, Arc::clone(&manager)) {
            Ok((bound, _)) => println!("vajra: admin on http://{bound}  (/metrics /healthz POST /reload; no auth)"),
            Err(e) => die(format!("cannot bind admin {addr}: {e}")),
        }
    }
    println!("vajra: ready (SIGHUP reloads, SIGINT/SIGTERM stops)");

    // Signal loop on the main thread.
    loop {
        match sys::wait_signal() {
            Signal::Reload => match manager.reload() {
                Ok(msg) => println!("vajra: {msg}"),
                Err(e) => eprintln!("vajra: reload failed, keeping the running configuration: {e}"),
            },
            Signal::Shutdown => {
                println!("vajra: shutting down (up to {}s grace)...", settings.grace_secs);
                manager.shutdown();
                break;
            }
        }
    }

    // A second signal while draining means "now".
    thread::spawn(|| {
        loop {
            if sys::wait_signal() == Signal::Shutdown {
                eprintln!("vajra: forced exit");
                exit(130);
            }
        }
    });

    for j in joins {
        let _ = j.join();
    }
    println!("vajra: bye");
}
