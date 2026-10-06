//! TOML configuration.
//!
//! ```toml
//! [server]
//! listen     = "0.0.0.0:8080"
//! workers    = 0          # 0 = one per CPU
//! pin        = true
//! grace_secs = 5          # graceful-shutdown deadline
//!
//! [limits]
//! max_conns                = 65536     # per worker
//! read_buf_size            = 8192
//! ring_entries             = 1024
//! max_body_bytes           = 1048576
//! max_proxy_response_bytes = 16777216
//!
//! [tls]
//! listen = "0.0.0.0:8443"
//! cert   = "cert.pem"
//! key    = "key.pem"
//!
//! [static]
//! root = "./public"
//!
//! [cache]                       # per-worker proxy cache limits
//! max_entries       = 10000
//! max_bytes         = 67108864
//! max_object_bytes  = 1048576
//!
//! [logging]
//! access_log = "logs/access.log"   # "-" = stdout; omit to disable
//!
//! [admin]                       # metrics + reload endpoint (no authentication!)
//! listen = "127.0.0.1:9100"
//!
//! [[proxy]]
//! prefix        = "/api/"
//! upstreams     = ["10.0.0.1:9000", "10.0.0.2:9000"]   # or: upstream = "10.0.0.1:9000"
//! balance       = "round_robin"    # round_robin | least_conn | ip_hash
//! strip_prefix  = false
//! timeout_secs  = 30
//! max_fails     = 3                # consecutive failures before an upstream is skipped
//! fail_timeout_secs = 10           # ... for this long
//! cache         = false
//! cache_default_ttl_secs = 0       # freshness when upstream sends no Cache-Control
//!
//! [php]                            # FastCGI / PHP-FPM; requires [static] (its root is the document root)
//! upstream      = "unix:/run/php/php8.3-fpm.sock"   # or "127.0.0.1:9000", or upstreams = [...]
//! index         = ["index.php"]    # directory index scripts
//! front_controller = "/index.php"  # "" disables (WordPress pretty permalinks need it)
//! extensions    = [".php"]
//! deny_exec     = ["/wp-content/uploads/"]   # scripts under these prefixes never run
//! script_root   = "/var/www/html"  # document root as PHP-FPM sees it (containers); default: static root
//! timeout_secs  = 60               # also: balance, max_fails, fail_timeout_secs
//! ```
//!
//! Unknown keys are rejected. Relative paths resolve against the config file's directory.
//!
//! ## Hot reload
//! [`Dynamic`] is the reloadable subset: static root, proxy routes, TLS
//! certificate/key, cache limits and the access-log path. Everything else
//! needs a restart; [`Settings::restart_required`] reports what changed.

use crate::php::PhpConfig;
use crate::worker::Config as WorkerConfig;
use serde::Deserialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
const DEFAULT_INDEX: &str = "index.html";
const MAX_UPSTREAMS: usize = 64;

#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    /// 0 means "one per CPU" (resolved by `main`).
    pub workers: usize,
    pub pin: bool,
    pub grace_secs: u64,
    pub worker: WorkerConfig,
    pub static_files: Option<StaticSettings>,
    pub tls: Option<TlsSettings>,
    pub quic: Option<QuicSettings>,
    pub proxies: Vec<ProxySettings>,
    pub cache: CacheSettings,
    pub access_log: Option<String>,
    pub admin: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct StaticSettings {
    pub root: PathBuf,
    pub index: String,
    pub cache_ttl_secs: u64,
    pub max_cached_files: usize,
}

#[derive(Debug, Clone)]
pub struct TlsSettings {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// HTTP/3 over QUIC (UDP). Uses the `[tls]` certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicSettings {
    pub listen: SocketAddr,
    /// Require a Retry round trip (address validation) before a handshake starts.
    pub retry: bool,
    pub idle_timeout_secs: u64,
    pub max_streams: u32,
    /// Send `Alt-Svc: h3=":port"` on HTTP/1.1 and HTTP/2 responses.
    pub advertise: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Balance {
    RoundRobin,
    LeastConn,
    IpHash,
}

/// An upstream endpoint: a TCP address or a Unix domain socket (`unix:/run/php/php-fpm.sock`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UpAddr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl From<SocketAddr> for UpAddr {
    fn from(a: SocketAddr) -> Self {
        UpAddr::Tcp(a)
    }
}

impl std::fmt::Display for UpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpAddr::Tcp(a) => write!(f, "{a}"),
            UpAddr::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

/// `host:port` or `unix:/absolute/path`.
fn parse_upstream(what: &str, s: &str) -> Result<UpAddr, String> {
    match s.strip_prefix("unix:") {
        Some(path) => {
            if !path.starts_with('/') || path.len() > 107 || path.contains('\0') {
                return Err(format!("{what} {s:?}: unix socket path must be absolute and shorter than 108 bytes"));
            }
            Ok(UpAddr::Unix(PathBuf::from(path)))
        }
        None => Ok(UpAddr::Tcp(resolve_addr(what, s)?)),
    }
}

#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub prefix: String,
    pub upstreams: Vec<UpAddr>,
    pub balance: Balance,
    pub strip_prefix: bool,
    pub timeout_secs: u64,
    pub max_fails: u32,
    pub fail_timeout_secs: u64,
    pub cache: bool,
    pub cache_default_ttl_secs: u64,
    /// `Some`: this route speaks FastCGI to PHP-FPM and is chosen by the PHP
    /// resolver instead of by `prefix`.
    pub php: Option<PhpConfig>,
}

impl ProxySettings {
    /// A single-upstream route with defaults for everything else.
    pub fn simple(prefix: &str, upstream: SocketAddr, strip_prefix: bool, timeout_secs: u64) -> Self {
        Self {
            prefix: prefix.to_string(),
            upstreams: vec![UpAddr::Tcp(upstream)],
            balance: Balance::RoundRobin,
            strip_prefix,
            timeout_secs,
            max_fails: 3,
            fail_timeout_secs: 10,
            cache: false,
            cache_default_ttl_secs: 0,
            php: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSettings {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_object_bytes: usize,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self { max_entries: 10_000, max_bytes: 64 * 1024 * 1024, max_object_bytes: 1024 * 1024 }
    }
}

/// Everything a worker can swap at runtime without dropping connections.
#[derive(Debug, Clone, Default)]
pub struct Dynamic {
    pub static_files: Option<StaticSettings>,
    pub proxies: Vec<ProxySettings>,
    /// `None` leaves the current TLS configuration untouched.
    pub tls: Option<TlsPaths>,
    pub access_log: Option<String>,
    pub cache: CacheSettings,
}

impl StaticSettings {
    pub fn new(root: &Path) -> Result<Self, String> {
        Self::build(root.to_path_buf(), DEFAULT_INDEX.to_string(), 2, 4096)
    }

    fn build(root: PathBuf, index: String, ttl: u64, max: usize) -> Result<Self, String> {
        let canon = std::fs::canonicalize(&root)
            .map_err(|e| format!("static.root {}: {e}", root.display()))?;
        if !canon.is_dir() {
            return Err(format!("static.root {} is not a directory", canon.display()));
        }
        if index.is_empty() || index.contains('/') {
            return Err("static.index must be a bare file name".into());
        }
        if max == 0 {
            return Err("static.max_cached_files must be >= 1".into());
        }
        Ok(Self { root: canon, index, cache_ttl_secs: ttl, max_cached_files: max })
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.parse().unwrap(),
            workers: 1,
            pin: true,
            grace_secs: 5,
            worker: WorkerConfig::default(),
            static_files: None,
            tls: None,
            quic: None,
            proxies: Vec::new(),
            cache: CacheSettings::default(),
            access_log: None,
            admin: None,
        }
    }
}

// ---- raw (serde) shapes ---------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Raw {
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    limits: RawLimits,
    #[serde(rename = "static")]
    static_files: Option<RawStatic>,
    tls: Option<RawTls>,
    quic: Option<RawQuic>,
    #[serde(default)]
    proxy: Vec<RawProxy>,
    php: Option<RawPhp>,
    #[serde(default)]
    cache: RawCache,
    #[serde(default)]
    logging: RawLogging,
    admin: Option<RawAdmin>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawServer {
    listen: String,
    workers: usize,
    pin: bool,
    grace_secs: u64,
}
impl Default for RawServer {
    fn default() -> Self {
        Self { listen: DEFAULT_LISTEN.into(), workers: 1, pin: true, grace_secs: 5 }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLimits {
    max_conns: usize,
    read_buf_size: usize,
    ring_entries: u32,
    max_body_bytes: usize,
    max_proxy_response_bytes: usize,
}
impl Default for RawLimits {
    fn default() -> Self {
        let d = WorkerConfig::default();
        Self {
            max_conns: d.max_conns,
            read_buf_size: d.read_buf_size,
            ring_entries: d.ring_entries,
            max_body_bytes: d.max_body_bytes,
            max_proxy_response_bytes: d.max_proxy_response_bytes,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStatic {
    root: String,
    #[serde(default = "default_index")]
    index: String,
    #[serde(default = "default_ttl")]
    cache_ttl_secs: u64,
    #[serde(default = "default_max_cached")]
    max_cached_files: usize,
}
fn default_index() -> String {
    DEFAULT_INDEX.into()
}
fn default_ttl() -> u64 {
    2
}
fn default_max_cached() -> usize {
    4096
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    listen: String,
    cert: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuic {
    listen: String,
    #[serde(default = "yes")]
    retry: bool,
    #[serde(default = "default_quic_idle")]
    idle_timeout_secs: u64,
    #[serde(default = "default_quic_streams")]
    max_streams: u32,
    #[serde(default = "yes")]
    advertise: bool,
}
fn yes() -> bool {
    true
}
fn default_quic_idle() -> u64 {
    30
}
fn default_quic_streams() -> u32 {
    100
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    prefix: String,
    upstream: Option<String>,
    upstreams: Option<Vec<String>>,
    balance: Option<String>,
    #[serde(default)]
    strip_prefix: bool,
    #[serde(default = "default_proxy_timeout")]
    timeout_secs: u64,
    #[serde(default = "default_max_fails")]
    max_fails: u32,
    #[serde(default = "default_fail_timeout")]
    fail_timeout_secs: u64,
    #[serde(default)]
    cache: bool,
    #[serde(default)]
    cache_default_ttl_secs: u64,
}
fn default_proxy_timeout() -> u64 {
    30
}
fn default_max_fails() -> u32 {
    3
}
fn default_fail_timeout() -> u64 {
    10
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPhp {
    upstream: Option<String>,
    upstreams: Option<Vec<String>>,
    #[serde(default = "default_php_index")]
    index: Vec<String>,
    /// `""` disables the front controller.
    #[serde(default = "default_front_controller")]
    front_controller: String,
    #[serde(default = "default_php_ext")]
    extensions: Vec<String>,
    #[serde(default = "default_deny_exec")]
    deny_exec: Vec<String>,
    /// Document root as PHP-FPM sees it (containers); defaults to `[static] root`.
    script_root: Option<String>,
    balance: Option<String>,
    #[serde(default = "default_php_timeout")]
    timeout_secs: u64,
    #[serde(default = "default_max_fails")]
    max_fails: u32,
    #[serde(default = "default_fail_timeout")]
    fail_timeout_secs: u64,
}
fn default_php_index() -> Vec<String> {
    vec!["index.php".into()]
}
fn default_front_controller() -> String {
    "/index.php".into()
}
fn default_php_ext() -> Vec<String> {
    vec![".php".into()]
}
fn default_deny_exec() -> Vec<String> {
    vec!["/wp-content/uploads/".into()]
}
fn default_php_timeout() -> u64 {
    60
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawCache {
    max_entries: usize,
    max_bytes: usize,
    max_object_bytes: usize,
}
impl Default for RawCache {
    fn default() -> Self {
        let d = CacheSettings::default();
        Self { max_entries: d.max_entries, max_bytes: d.max_bytes, max_object_bytes: d.max_object_bytes }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawLogging {
    access_log: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdmin {
    listen: String,
}

fn resolve(base: &Path, p: &str) -> PathBuf {
    let p = PathBuf::from(p);
    if p.is_absolute() {
        p
    } else {
        base.join(p)
    }
}

fn resolve_addr(what: &str, s: &str) -> Result<SocketAddr, String> {
    s.to_socket_addrs()
        .map_err(|e| format!("{what} {s:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{what} {s:?} did not resolve"))
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_toml_str(&text, base).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn from_toml_str(text: &str, base_dir: &Path) -> Result<Self, String> {
        let raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;

        let listen: SocketAddr = raw
            .server
            .listen
            .parse()
            .map_err(|e| format!("server.listen {:?}: {e}", raw.server.listen))?;
        if !(1..=3600).contains(&raw.server.grace_secs) {
            return Err("server.grace_secs must be in 1..=3600".into());
        }

        let l = &raw.limits;
        if !(1..=1 << 20).contains(&l.max_conns) {
            return Err("limits.max_conns must be in 1..=1048576".into());
        }
        if !(1024..=1 << 20).contains(&l.read_buf_size) {
            return Err("limits.read_buf_size must be in 1024..=1048576".into());
        }
        if !(16..=32768).contains(&l.ring_entries) {
            return Err("limits.ring_entries must be in 16..=32768".into());
        }
        if l.max_body_bytes > 1 << 30 || l.max_proxy_response_bytes > 1 << 30 {
            return Err("limits.max_body_bytes / max_proxy_response_bytes must be <= 1 GiB".into());
        }

        let static_files = match raw.static_files {
            None => None,
            Some(s) => Some(StaticSettings::build(
                resolve(base_dir, &s.root),
                s.index,
                s.cache_ttl_secs,
                s.max_cached_files,
            )?),
        };

        let tls = match raw.tls {
            None => None,
            Some(t) => {
                let cert = resolve(base_dir, &t.cert);
                let key = resolve(base_dir, &t.key);
                for (what, p) in [("tls.cert", &cert), ("tls.key", &key)] {
                    if !p.is_file() {
                        return Err(format!("{what}: {} is not a file", p.display()));
                    }
                }
                Some(TlsSettings { listen: resolve_addr("tls.listen", &t.listen)?, cert, key })
            }
        };

        let quic = match raw.quic {
            None => None,
            Some(q) => {
                if tls.is_none() {
                    return Err("[quic] requires a [tls] section (the same certificate is used)".into());
                }
                if !(1..=600).contains(&q.idle_timeout_secs) {
                    return Err("quic.idle_timeout_secs must be in 1..=600".into());
                }
                if !(1..=1000).contains(&q.max_streams) {
                    return Err("quic.max_streams must be in 1..=1000".into());
                }
                Some(QuicSettings {
                    listen: resolve_addr("quic.listen", &q.listen)?,
                    retry: q.retry,
                    idle_timeout_secs: q.idle_timeout_secs,
                    max_streams: q.max_streams,
                    advertise: q.advertise,
                })
            }
        };

        let mut proxies = Vec::with_capacity(raw.proxy.len());
        for p in raw.proxy {
            if !p.prefix.starts_with('/') {
                return Err(format!("proxy.prefix {:?} must start with '/'", p.prefix));
            }
            if !(1..=3600).contains(&p.timeout_secs) {
                return Err("proxy.timeout_secs must be in 1..=3600".into());
            }
            if p.max_fails == 0 || !(1..=3600).contains(&p.fail_timeout_secs) {
                return Err("proxy.max_fails must be >= 1 and fail_timeout_secs in 1..=3600".into());
            }
            let names: Vec<String> = match (p.upstream, p.upstreams) {
                (Some(u), None) => vec![u],
                (None, Some(us)) => us,
                _ => {
                    return Err(format!(
                        "proxy {:?}: set exactly one of `upstream` or `upstreams`",
                        p.prefix
                    ))
                }
            };
            if names.is_empty() || names.len() > MAX_UPSTREAMS {
                return Err(format!("proxy {:?}: need 1..={MAX_UPSTREAMS} upstreams", p.prefix));
            }
            let mut upstreams = Vec::with_capacity(names.len());
            for n in &names {
                let a = parse_upstream("proxy.upstream", n)?;
                if !upstreams.contains(&a) {
                    upstreams.push(a);
                }
            }
            let balance = match p.balance.as_deref().unwrap_or("round_robin") {
                "round_robin" => Balance::RoundRobin,
                "least_conn" => Balance::LeastConn,
                "ip_hash" => Balance::IpHash,
                other => {
                    return Err(format!(
                        "proxy.balance {other:?}: expected round_robin, least_conn or ip_hash"
                    ))
                }
            };
            proxies.push(ProxySettings {
                prefix: p.prefix,
                upstreams,
                balance,
                strip_prefix: p.strip_prefix,
                timeout_secs: p.timeout_secs,
                max_fails: p.max_fails,
                fail_timeout_secs: p.fail_timeout_secs,
                cache: p.cache,
                cache_default_ttl_secs: p.cache_default_ttl_secs,
                php: None,
            });
        }

        if let Some(php) = raw.php {
            let root = match &static_files {
                Some(sf) => sf.root.clone(),
                None => return Err("[php] requires a [static] section (its root is the PHP document root)".into()),
            };
            if !(1..=3600).contains(&php.timeout_secs) {
                return Err("php.timeout_secs must be in 1..=3600".into());
            }
            if php.max_fails == 0 || !(1..=3600).contains(&php.fail_timeout_secs) {
                return Err("php.max_fails must be >= 1 and fail_timeout_secs in 1..=3600".into());
            }
            let names: Vec<String> = match (php.upstream, php.upstreams) {
                (Some(u), None) => vec![u],
                (None, Some(us)) => us,
                _ => return Err("php: set exactly one of `upstream` or `upstreams`".into()),
            };
            if names.is_empty() || names.len() > MAX_UPSTREAMS {
                return Err(format!("php: need 1..={MAX_UPSTREAMS} upstreams"));
            }
            let mut upstreams = Vec::with_capacity(names.len());
            for n in &names {
                let a = parse_upstream("php.upstream", n)?;
                if !upstreams.contains(&a) {
                    upstreams.push(a);
                }
            }
            let balance = match php.balance.as_deref().unwrap_or("round_robin") {
                "round_robin" => Balance::RoundRobin,
                "least_conn" => Balance::LeastConn,
                other => return Err(format!("php.balance {other:?}: expected round_robin or least_conn")),
            };
            if php.index.is_empty() || php.index.iter().any(|i| i.is_empty() || i.contains('/')) {
                return Err("php.index must be a non-empty list of bare file names".into());
            }
            let front_controller = if php.front_controller.is_empty() {
                None
            } else {
                let f = php.front_controller;
                if !f.starts_with('/') || f.split('/').any(|seg| seg == "..") {
                    return Err("php.front_controller must be an absolute path below the root (or \"\")".into());
                }
                Some(f)
            };
            let mut extensions = Vec::new();
            for e in &php.extensions {
                let e = e.to_ascii_lowercase();
                if e.len() < 2 || e.len() > 16 || !e.starts_with('.') || e.contains('/') {
                    return Err(format!("php.extensions: {e:?} must look like \".php\""));
                }
                extensions.push(e);
            }
            if extensions.is_empty() {
                return Err("php.extensions must not be empty".into());
            }
            let mut deny_exec = Vec::new();
            for d in &php.deny_exec {
                if !d.starts_with('/') {
                    return Err(format!("php.deny_exec: {d:?} must start with '/'"));
                }
                deny_exec.push(d.to_ascii_lowercase());
            }
            let fpm_root = match php.script_root {
                Some(r) => {
                    if !r.starts_with('/') {
                        return Err("php.script_root must be an absolute path".into());
                    }
                    r
                }
                None => root.to_string_lossy().into_owned(),
            };
            proxies.push(ProxySettings {
                prefix: String::new(),
                upstreams,
                balance,
                strip_prefix: false,
                timeout_secs: php.timeout_secs,
                max_fails: php.max_fails,
                fail_timeout_secs: php.fail_timeout_secs,
                cache: false,
                cache_default_ttl_secs: 0,
                php: Some(PhpConfig {
                    root,
                    fpm_root,
                    index: php.index,
                    front_controller,
                    extensions,
                    deny_exec,
                }),
            });
        }

        let c = &raw.cache;
        if c.max_object_bytes > c.max_bytes && c.max_bytes > 0 {
            return Err("cache.max_object_bytes must not exceed cache.max_bytes".into());
        }

        let access_log = raw.logging.access_log.map(|p| {
            if p == "-" {
                p
            } else {
                resolve(base_dir, &p).to_string_lossy().into_owned()
            }
        });
        let admin = match raw.admin {
            None => None,
            Some(a) => Some(resolve_addr("admin.listen", &a.listen)?),
        };

        Ok(Self {
            listen,
            workers: raw.server.workers,
            pin: raw.server.pin,
            grace_secs: raw.server.grace_secs,
            worker: WorkerConfig {
                ring_entries: l.ring_entries,
                read_buf_size: l.read_buf_size,
                max_conns: l.max_conns,
                max_body_bytes: l.max_body_bytes,
                max_proxy_response_bytes: l.max_proxy_response_bytes,
            },
            static_files,
            tls,
            quic,
            proxies,
            cache: CacheSettings {
                max_entries: c.max_entries,
                max_bytes: c.max_bytes,
                max_object_bytes: c.max_object_bytes,
            },
            access_log,
            admin,
        })
    }

    /// The reloadable subset.
    pub fn dynamic(&self) -> Dynamic {
        Dynamic {
            static_files: self.static_files.clone(),
            proxies: self.proxies.clone(),
            tls: self.tls.as_ref().map(|t| TlsPaths { cert: t.cert.clone(), key: t.key.clone() }),
            access_log: self.access_log.clone(),
            cache: self.cache,
        }
    }

    /// Settings that differ between `self` (running) and `new` but cannot be
    /// applied without a restart.
    pub fn restart_required(&self, new: &Settings) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.listen != new.listen {
            v.push("server.listen");
        }
        if self.workers != new.workers {
            v.push("server.workers");
        }
        if self.pin != new.pin {
            v.push("server.pin");
        }
        if self.worker != new.worker {
            v.push("[limits]");
        }
        if self.tls.as_ref().map(|t| t.listen) != new.tls.as_ref().map(|t| t.listen) {
            v.push("tls.listen (adding/removing/moving the HTTPS listener)");
        }
        if self.quic != new.quic {
            v.push("[quic] (adding/removing/changing the HTTP/3 listener)");
        }
        if self.admin != new.admin {
            v.push("admin.listen");
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vajra-cfg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn parse(t: &str) -> Result<Settings, String> {
        Settings::from_toml_str(t, Path::new("."))
    }

    #[test]
    fn empty_config_gives_defaults() {
        let s = parse("").unwrap();
        assert_eq!(s.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!((s.workers, s.grace_secs), (1, 5));
        assert!(s.pin && s.static_files.is_none() && s.tls.is_none() && s.proxies.is_empty());
        assert!(s.access_log.is_none() && s.admin.is_none());
        assert_eq!(s.cache, CacheSettings::default());
    }

    #[test]
    fn php_section() {
        let d = tmpdir("php");
        let base = format!("[static]\nroot = {:?}\n", d.to_str().unwrap());
        let s = parse(&format!("{base}[php]\nupstream = \"unix:/run/php/php8.3-fpm.sock\"\n")).unwrap();
        let p = s.proxies.last().unwrap();
        assert_eq!(p.upstreams, vec![UpAddr::Unix(PathBuf::from("/run/php/php8.3-fpm.sock"))]);
        assert_eq!(p.timeout_secs, 60);
        let php = p.php.as_ref().unwrap();
        assert_eq!(php.index, ["index.php"]);
        assert_eq!(php.front_controller.as_deref(), Some("/index.php"));
        assert_eq!(php.extensions, [".php"]);
        assert_eq!(php.deny_exec, ["/wp-content/uploads/"]);
        assert_eq!(php.root, php.root.canonicalize().unwrap());
        assert_eq!(php.fpm_root, php.root.to_string_lossy());

        let s = parse(&format!(
            "{base}[php]\nupstreams = [\"127.0.0.1:9000\", \"127.0.0.1:9001\"]\nfront_controller = \"\"\nextensions = [\".PHP\", \".phtml\"]\nscript_root = \"/var/www/html\"\ndeny_exec = [\"/Uploads/\"]\n"
        ))
        .unwrap();
        let php = s.proxies.last().unwrap().php.clone().unwrap();
        assert_eq!(php.front_controller, None);
        assert_eq!(php.extensions, [".php", ".phtml"]);
        assert_eq!(php.fpm_root, "/var/www/html");
        assert_eq!(php.deny_exec, ["/uploads/"]);
        assert_eq!(s.proxies.last().unwrap().upstreams.len(), 2);

        // Mixed with a normal proxy route: both survive.
        let s = parse(&format!(
            "{base}[[proxy]]\nprefix = \"/api/\"\nupstream = \"127.0.0.1:1\"\n[php]\nupstream = \"127.0.0.1:9000\"\n"
        ))
        .unwrap();
        assert_eq!(s.proxies.len(), 2);
        assert!(s.proxies[0].php.is_none() && s.proxies[1].php.is_some());
    }

    #[test]
    fn php_section_errors() {
        let d = tmpdir("phperr");
        let base = format!("[static]\nroot = {:?}\n", d.to_str().unwrap());
        assert!(parse("[php]\nupstream = \"127.0.0.1:9000\"").is_err(), "needs [static]");
        for bad in [
            "",                                                   // no upstream
            "upstream = \"127.0.0.1:9000\"\nupstreams = [\"127.0.0.1:1\"]",
            "upstream = \"unix:relative.sock\"",
            "upstream = \"127.0.0.1:9000\"\nextensions = [\"php\"]",
            "upstream = \"127.0.0.1:9000\"\nextensions = []",
            "upstream = \"127.0.0.1:9000\"\nindex = [\"a/b.php\"]",
            "upstream = \"127.0.0.1:9000\"\nfront_controller = \"index.php\"",
            "upstream = \"127.0.0.1:9000\"\nfront_controller = \"/../x.php\"",
            "upstream = \"127.0.0.1:9000\"\ndeny_exec = [\"uploads\"]",
            "upstream = \"127.0.0.1:9000\"\nscript_root = \"rel\"",
            "upstream = \"127.0.0.1:9000\"\ntimeout_secs = 0",
            "upstream = \"127.0.0.1:9000\"\nbalance = \"ip_hash\"",
            "upstream = \"127.0.0.1:9000\"\nunknown = 1",
        ] {
            assert!(parse(&format!("{base}[php]\n{bad}\n")).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn unix_proxy_upstream() {
        let s = parse("[[proxy]]\nprefix = \"/a/\"\nupstream = \"unix:/tmp/app.sock\"").unwrap();
        assert_eq!(s.proxies[0].upstreams[0].to_string(), "unix:/tmp/app.sock");
        assert!(parse("[[proxy]]\nprefix = \"/a/\"\nupstream = \"unix:app.sock\"").is_err());
    }

    #[test]
    fn quic_section() {
        let base = tmpdir("quic");
        std::fs::write(base.join("c.pem"), "x").unwrap();
        std::fs::write(base.join("k.pem"), "x").unwrap();
        let tls = "[tls]\nlisten=\"127.0.0.1:9443\"\ncert=\"c.pem\"\nkey=\"k.pem\"\n";
        let ok = format!("{tls}[quic]\nlisten=\"127.0.0.1:9443\"\n");
        let s = Settings::from_toml_str(&ok, &base).unwrap();
        let q = s.quic.unwrap();
        assert!(q.retry && q.advertise);
        assert_eq!((q.idle_timeout_secs, q.max_streams, q.listen.port()), (30, 100, 9443));

        let custom = format!(
            "{tls}[quic]\nlisten=\"127.0.0.1:9444\"\nretry=false\nadvertise=false\nidle_timeout_secs=5\nmax_streams=7\n"
        );
        let q = Settings::from_toml_str(&custom, &base).unwrap().quic.unwrap();
        assert!(!q.retry && !q.advertise);
        assert_eq!((q.idle_timeout_secs, q.max_streams), (5, 7));

        // QUIC needs the TLS identity; limits are validated; unknown keys rejected.
        assert!(Settings::from_toml_str("[quic]\nlisten=\"127.0.0.1:1\"", &base).is_err());
        for bad in ["idle_timeout_secs=0", "idle_timeout_secs=601", "max_streams=0", "max_streams=1001", "bogus=1"] {
            let t = format!("{tls}[quic]\nlisten=\"127.0.0.1:9443\"\n{bad}\n");
            assert!(Settings::from_toml_str(&t, &base).is_err(), "{bad}");
        }

        // Changing the HTTP/3 listener needs a restart.
        let a = Settings::from_toml_str(&ok, &base).unwrap();
        let b = Settings::from_toml_str(&custom, &base).unwrap();
        assert!(a.restart_required(&b).iter().any(|s| s.contains("quic")));
        assert!(a.restart_required(&a).is_empty());
    }

    #[test]
    fn full_config() {
        let base = tmpdir("full");
        std::fs::create_dir_all(base.join("public")).unwrap();
        std::fs::write(base.join("c.pem"), "x").unwrap();
        std::fs::write(base.join("k.pem"), "x").unwrap();
        let toml = r#"
            [server]
            listen = "127.0.0.1:9000"
            workers = 4
            pin = false
            grace_secs = 9
            [limits]
            max_conns = 100
            read_buf_size = 4096
            ring_entries = 256
            max_body_bytes = 2048
            [tls]
            listen = "127.0.0.1:9443"
            cert = "c.pem"
            key = "k.pem"
            [static]
            root = "public"
            index = "home.html"
            [cache]
            max_entries = 50
            max_bytes = 4096
            max_object_bytes = 1024
            [logging]
            access_log = "logs/access.log"
            [admin]
            listen = "127.0.0.1:9100"
            [[proxy]]
            prefix = "/api/"
            upstreams = ["127.0.0.1:7000", "127.0.0.1:7001", "127.0.0.1:7000"]
            balance = "least_conn"
            strip_prefix = true
            timeout_secs = 5
            max_fails = 2
            fail_timeout_secs = 20
            cache = true
            cache_default_ttl_secs = 60
            [[proxy]]
            prefix = "/other"
            upstream = "127.0.0.1:7002"
        "#;
        let s = Settings::from_toml_str(toml, &base).unwrap();
        assert_eq!((s.listen.port(), s.workers, s.grace_secs), (9000, 4, 9));
        assert_eq!(s.worker.max_body_bytes, 2048);
        assert_eq!(s.tls.as_ref().unwrap().listen.port(), 9443);
        assert_eq!(s.static_files.as_ref().unwrap().index, "home.html");
        assert_eq!(s.cache.max_entries, 50);
        assert_eq!(s.admin.unwrap().port(), 9100);
        assert!(s.access_log.as_ref().unwrap().ends_with("logs/access.log"));
        assert!(std::path::Path::new(s.access_log.as_ref().unwrap()).is_absolute());

        assert_eq!(s.proxies.len(), 2);
        let p = &s.proxies[0];
        assert_eq!(p.upstreams.len(), 2, "duplicates removed");
        assert_eq!(p.balance, Balance::LeastConn);
        assert!(p.strip_prefix && p.cache);
        assert_eq!((p.timeout_secs, p.max_fails, p.fail_timeout_secs, p.cache_default_ttl_secs), (5, 2, 20, 60));
        let q = &s.proxies[1];
        assert_eq!((q.upstreams.len(), q.balance, q.timeout_secs, q.cache), (1, Balance::RoundRobin, 30, false));

        let d = s.dynamic();
        assert_eq!(d.proxies.len(), 2);
        assert!(d.tls.is_some() && d.static_files.is_some());
    }

    #[test]
    fn stdout_access_log_is_kept_verbatim() {
        assert_eq!(parse("[logging]\naccess_log = \"-\"").unwrap().access_log.as_deref(), Some("-"));
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(parse("[server]\nlisten_addr = \"x\"").is_err());
        assert!(parse("bogus = 1").is_err());
        assert!(parse("[[proxy]]\nprefix=\"/\"\nupstream=\"127.0.0.1:1\"\nx=1").is_err());
        assert!(parse("[cache]\nmax = 1").is_err());
    }

    #[test]
    fn bad_values_rejected() {
        assert!(parse("[server]\nlisten = \"nope\"").is_err());
        assert!(parse("[server]\ngrace_secs = 0").is_err());
        assert!(parse("[limits]\nmax_conns = 0").is_err());
        assert!(parse("[limits]\nread_buf_size = 10").is_err());
        assert!(parse("[static]\nroot = \"/definitely/not/here\"").is_err());
        assert!(parse("[tls]\nlisten=\"127.0.0.1:1\"\ncert=\"/no\"\nkey=\"/no\"").is_err());
        assert!(parse("[[proxy]]\nprefix=\"api\"\nupstream=\"127.0.0.1:1\"").is_err());
        assert!(parse("[[proxy]]\nprefix=\"/a\"\nupstream=\"127.0.0.1:1\"\ntimeout_secs=0").is_err());
        assert!(parse("[[proxy]]\nprefix=\"/a\"\nupstream=\"127.0.0.1:1\"\nmax_fails=0").is_err());
        assert!(parse("[[proxy]]\nprefix=\"/a\"\nupstream=\"127.0.0.1:1\"\nbalance=\"random\"").is_err());
        assert!(parse("[[proxy]]\nprefix=\"/a\"").is_err(), "no upstream");
        assert!(parse("[[proxy]]\nprefix=\"/a\"\nupstream=\"127.0.0.1:1\"\nupstreams=[\"127.0.0.1:2\"]").is_err());
        assert!(parse("[[proxy]]\nprefix=\"/a\"\nupstreams=[]").is_err());
        assert!(parse("[cache]\nmax_bytes = 10\nmax_object_bytes = 100").is_err());
    }

    #[test]
    fn restart_required_detection() {
        let a = parse("").unwrap();
        let mut b = a.clone();
        assert!(a.restart_required(&b).is_empty());
        b.listen = "127.0.0.1:1".parse().unwrap();
        b.workers = 8;
        b.worker.max_conns = 5;
        b.admin = Some("127.0.0.1:2".parse().unwrap());
        let r = a.restart_required(&b);
        assert_eq!(r.len(), 4, "{r:?}");
        // Reloadable fields never appear.
        let mut c = a.clone();
        c.proxies.push(ProxySettings::simple("/x", "127.0.0.1:1".parse().unwrap(), false, 5));
        c.access_log = Some("-".into());
        assert!(a.restart_required(&c).is_empty());
    }
}
