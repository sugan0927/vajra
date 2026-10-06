//! Protocol-independent routing. HTTP/1.1 and HTTP/2 both call [`route`] and
//! then render the returned [`Reply`] in their own wire format.
//!
//! Precedence: `/health` -> proxy prefixes (longest match) -> static files
//! (or the built-in hello page when no static root is configured).

use crate::php::{self, Class, Target};
use crate::proxy::ProxyTable;
use crate::static_files::{FileCache, Lookup, OpenFile};
use std::rc::Rc;

pub const TEXT: &str = "text/plain; charset=utf-8";
pub const BODY_ROOT: &[u8] = b"Vajra: hello from io_uring\n";
pub const BODY_HEALTH: &[u8] = b"ok\n";
pub const BODY_404: &[u8] = b"not found\n";
pub const BODY_405: &[u8] = b"method not allowed\n";

pub enum Reply {
    /// A small fixed response.
    Mem { status: u16, ctype: &'static str, body: &'static [u8], allow: bool },
    /// A static file: 200 with a streamed body, or 304 with no body.
    File { file: Rc<OpenFile>, not_modified: bool },
    /// Forward to proxy route `.0`; the caller builds and runs the upstream request.
    Proxy(usize),
    /// Run a PHP script through the FastCGI route `.0`.
    Php(usize, Box<Target>),
    /// Malformed or malicious request target.
    BadRequest,
}

impl Reply {
    /// Route index and (for PHP) the script to run, if this reply is handled by the proxy machinery.
    pub fn proxy_parts(&self) -> Option<(usize, Option<&Target>)> {
        match self {
            Reply::Proxy(i) => Some((*i, None)),
            Reply::Php(i, t) => Some((*i, Some(t))),
            _ => None,
        }
    }
}

fn mem(status: u16, body: &'static [u8]) -> Reply {
    Reply::Mem { status, ctype: TEXT, body, allow: false }
}

/// `path` must already have its query string removed.
pub fn route(
    method: &str,
    path: &str,
    if_none_match: Option<&[u8]>,
    files: Option<&mut FileCache>,
    proxies: &ProxyTable,
) -> Reply {
    let is_read = method == "GET" || method == "HEAD";

    if path == "/health" && is_read {
        return mem(200, BODY_HEALTH);
    }
    if let Some(i) = proxies.find(path) {
        return Reply::Proxy(i);
    }
    if let Some((pi, cfg)) = proxies.php_route() {
        return route_php(pi, cfg, is_read, path, if_none_match, files);
    }
    if !is_read {
        return Reply::Mem { status: 405, ctype: TEXT, body: BODY_405, allow: true };
    }
    match files {
        Some(fc) => match fc.lookup(path) {
            Lookup::Found(f) => {
                let not_modified =
                    if_none_match.is_some_and(|v| etag_matches(v, f.etag.as_bytes()));
                Reply::File { file: f, not_modified }
            }
            Lookup::NotFound => mem(404, BODY_404),
            Lookup::BadRequest => Reply::BadRequest,
        },
        None if path == "/" => mem(200, BODY_ROOT),
        None => mem(404, BODY_404),
    }
}

/// Routing when `[php]` is configured: scripts first, then static files, then
/// directory index / front controller (see `php.rs`).
fn route_php(
    pi: usize,
    cfg: &php::PhpConfig,
    is_read: bool,
    path: &str,
    if_none_match: Option<&[u8]>,
    files: Option<&mut FileCache>,
) -> Reply {
    let norm = match php::classify(cfg, path) {
        Class::Bad => return Reply::BadRequest,
        Class::NotFound => return mem(404, BODY_404),
        Class::Script(t) => return Reply::Php(pi, Box::new(t)),
        Class::Other(n) => n,
    };
    let found = match files {
        Some(fc) => fc.lookup(path),
        None => Lookup::NotFound,
    };
    match found {
        Lookup::Found(f) => {
            if !is_read {
                return Reply::Mem { status: 405, ctype: TEXT, body: BODY_405, allow: true };
            }
            let not_modified = if_none_match.is_some_and(|v| etag_matches(v, f.etag.as_bytes()));
            Reply::File { file: f, not_modified }
        }
        Lookup::BadRequest => Reply::BadRequest,
        Lookup::NotFound => match php::fallback(cfg, &norm) {
            Some(t) => Reply::Php(pi, Box::new(t)),
            None => mem(404, BODY_404),
        },
    }
}

/// `If-None-Match` evaluation (weak comparison, `*` matches anything).
pub fn etag_matches(header: &[u8], etag: &[u8]) -> bool {
    header.split(|&b| b == b',').any(|t| {
        let t = t.trim_ascii();
        let t = t.strip_prefix(b"W/").unwrap_or(t);
        t == b"*" || t == etag
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxySettings;

    fn table() -> ProxyTable {
        ProxyTable::new(
            &[ProxySettings::simple("/api/", "127.0.0.1:9".parse().unwrap(), false, 1)],
            1 << 20,
        )
    }

    #[test]
    fn builtin_routes() {
        let t = ProxyTable::empty();
        assert!(matches!(route("GET", "/health", None, None, &t), Reply::Mem { status: 200, .. }));
        assert!(matches!(route("GET", "/", None, None, &t), Reply::Mem { status: 200, .. }));
        assert!(matches!(route("GET", "/x", None, None, &t), Reply::Mem { status: 404, .. }));
        assert!(matches!(
            route("POST", "/", None, None, &t),
            Reply::Mem { status: 405, allow: true, .. }
        ));
    }

    #[test]
    fn proxy_takes_every_method_but_health_wins() {
        let t = table();
        assert!(matches!(route("POST", "/api/x", None, None, &t), Reply::Proxy(0)));
        assert!(matches!(route("GET", "/api/", None, None, &t), Reply::Proxy(0)));
        assert!(matches!(route("GET", "/health", None, None, &t), Reply::Mem { status: 200, .. }));
        assert!(matches!(route("GET", "/other", None, None, &t), Reply::Mem { status: 404, .. }));
    }

    #[test]
    fn php_routing_order() {
        use crate::config::StaticSettings;
        let root = std::env::temp_dir().join(format!("vajra-router-php-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("wp-content/uploads")).unwrap();
        for f in ["index.php", "wp-login.php", "style.css", "wp-content/uploads/e.php"] {
            std::fs::write(root.join(f), b"x").unwrap();
        }
        let st = StaticSettings::new(&root).unwrap();
        let mut files = FileCache::new(&st);
        let mut php = ProxySettings::simple("", "127.0.0.1:9".parse().unwrap(), false, 1);
        php.php = Some(crate::php::PhpConfig::wordpress(&st.root));
        let api = ProxySettings::simple("/api/", "127.0.0.1:9".parse().unwrap(), false, 1);
        let t = ProxyTable::new(&[api, php], 1 << 20);

        let mut r = |m: &str, p: &str| route(m, p, None, Some(&mut files), &t);
        // Explicit proxy prefixes and /health keep priority.
        assert!(matches!(r("GET", "/api/x"), Reply::Proxy(0)));
        assert!(matches!(r("GET", "/health"), Reply::Mem { status: 200, .. }));
        // Scripts, PATH_INFO, directory index, front controller (any method).
        assert!(matches!(r("POST", "/wp-login.php"), Reply::Php(1, ref t) if t.script_name == "/wp-login.php"));
        assert!(matches!(r("GET", "/index.php/a"), Reply::Php(1, ref t) if t.path_info == "/a"));
        assert!(matches!(r("GET", "/"), Reply::Php(1, ref t) if t.script_name == "/index.php"));
        assert!(matches!(r("POST", "/wp-json/wp/v2/posts"), Reply::Php(1, ref t) if t.script_name == "/index.php"));
        // Static files win over the front controller; writes to them are 405.
        assert!(matches!(r("GET", "/style.css"), Reply::File { .. }));
        assert!(matches!(r("POST", "/style.css"), Reply::Mem { status: 405, .. }));
        // Denied / missing scripts, hidden files, traversal.
        assert!(matches!(r("GET", "/wp-content/uploads/e.php"), Reply::Mem { status: 404, .. }));
        assert!(matches!(r("GET", "/missing.php"), Reply::Mem { status: 404, .. }));
        assert!(matches!(r("GET", "/.env"), Reply::Mem { status: 404, .. }));
        assert!(matches!(r("GET", "/%2e%2e/x"), Reply::BadRequest));
        // The PHP route is never matched by prefix.
        assert_eq!(t.find("/anything"), None);
    }

    #[test]
    fn etag_matching() {
        assert!(etag_matches(b"\"abc\"", b"\"abc\""));
        assert!(etag_matches(b"W/\"abc\"", b"\"abc\""));
        assert!(etag_matches(b"\"x\", \"abc\"", b"\"abc\""));
        assert!(etag_matches(b"*", b"\"abc\""));
        assert!(!etag_matches(b"\"other\"", b"\"abc\""));
    }
}
