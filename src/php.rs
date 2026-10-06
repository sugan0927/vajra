//! PHP request routing (WordPress-style). Pure `std`, no sockets.
//!
//! For a request path this decides: run a PHP script (and which, with which
//! `PATH_INFO`), serve a static file, or answer 404/400. It reproduces the
//! usual nginx recipe
//!
//! ```text
//! location ~ \.php(/|$) { split path info; try_files $script =404; fastcgi_pass ... }
//! location /            { try_files $uri $uri/ /index.php?$args; }
//! ```
//!
//! Rules, in order (see [`classify`] and [`fallback`]):
//! 1. The path is percent-decoded and normalised. `..`, NUL and `\` are rejected (400).
//! 2. Any segment starting with `.` (except `.well-known`) is hidden: 404.
//! 3. The first segment ending in a configured extension (`.php`) whose file
//!    exists splits the path into `SCRIPT_NAME` and `PATH_INFO`. A path that
//!    names a script which does not exist is a 404, never a static file and
//!    never the front controller (so PHP source cannot leak and
//!    `/uploads/evil.jpg/x.php` cannot run `evil.jpg`).
//! 4. Scripts under a `deny_exec` prefix (default `/wp-content/uploads/`) are 404.
//! 5. Otherwise the static handler gets the first try. When it has nothing, a
//!    directory with an index script runs it, and anything else runs the
//!    front controller (`/index.php`) with the original `REQUEST_URI`.
//!
//! Symlinks inside the document root are followed (as in nginx/PHP-FPM);
//! keep untrusted users from creating them.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpConfig {
    /// Canonical document root on the machine running Vajra (used for `stat`).
    pub root: PathBuf,
    /// Document root as PHP-FPM sees it (differs only with containers/chroots).
    pub fpm_root: String,
    /// Index scripts tried for directory requests.
    pub index: Vec<String>,
    /// Script that handles every request that matches nothing else (`/index.php`).
    pub front_controller: Option<String>,
    /// Lower-case extensions including the dot.
    pub extensions: Vec<String>,
    /// Path prefixes (lower-case, leading `/`) under which scripts never run.
    pub deny_exec: Vec<String>,
}

impl PhpConfig {
    pub fn wordpress(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            fpm_root: root.to_string_lossy().into_owned(),
            index: vec!["index.php".into()],
            front_controller: Some("/index.php".into()),
            extensions: vec![".php".into()],
            deny_exec: vec!["/wp-content/uploads/".into()],
        }
    }

    fn has_ext(&self, seg: &str) -> bool {
        let l = seg.to_ascii_lowercase();
        self.extensions.iter().any(|e| l.len() > e.len() && l.ends_with(e.as_str()))
    }

    fn denied(&self, script: &str) -> bool {
        let l = script.to_ascii_lowercase();
        self.deny_exec.iter().any(|p| l.starts_with(p.as_str()))
    }

    fn is_file(&self, rel: &str) -> bool {
        std::fs::metadata(self.root.join(rel.trim_start_matches('/'))).map(|m| m.is_file()).unwrap_or(false)
    }

    fn is_dir(&self, rel: &str) -> bool {
        std::fs::metadata(self.root.join(rel.trim_start_matches('/'))).map(|m| m.is_dir()).unwrap_or(false)
    }
}

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Decoded path of the script below the root, e.g. `/wp-login.php`.
    pub script_name: String,
    /// Decoded remainder after the script (`""` or starting with `/`).
    pub path_info: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Class {
    /// Malformed or malicious path.
    Bad,
    /// Dotfile or a denied/missing script: answer 404.
    NotFound,
    /// Run this script.
    Script(Target),
    /// Not a script request; carries the normalised path (for [`fallback`]).
    Other(String),
}

/// Percent-decode; `None` on bad escapes or non-UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `raw` is the request path without the query string.
pub fn classify(cfg: &PhpConfig, raw: &str) -> Class {
    let Some(dec) = percent_decode(raw) else { return Class::Bad };
    if !dec.starts_with('/') || dec.contains('\0') || dec.contains('\\') {
        return Class::Bad;
    }
    let mut segs: Vec<&str> = Vec::new();
    for s in dec.split('/') {
        match s {
            "" | "." => {}
            ".." => return Class::Bad,
            s if s.starts_with('.') && s != ".well-known" => return Class::NotFound,
            s => segs.push(s),
        }
    }

    let mut saw_missing_script = false;
    for (i, s) in segs.iter().enumerate() {
        if !cfg.has_ext(s) {
            continue;
        }
        let name = format!("/{}", segs[..=i].join("/"));
        if cfg.is_file(&name) {
            if cfg.denied(&name) {
                return Class::NotFound;
            }
            let mut pi = String::new();
            if i + 1 < segs.len() {
                pi = format!("/{}", segs[i + 1..].join("/"));
                if dec.ends_with('/') {
                    pi.push('/');
                }
            }
            return Class::Script(Target { script_name: name, path_info: pi });
        }
        saw_missing_script = true;
    }
    if saw_missing_script {
        return Class::NotFound;
    }
    Class::Other(format!("/{}", segs.join("/")))
}

/// For a non-script path the static handler could not serve: directory index
/// script, else the front controller, else `None` (plain 404).
pub fn fallback(cfg: &PhpConfig, norm: &str) -> Option<Target> {
    if cfg.is_dir(norm) {
        let base = norm.trim_end_matches('/');
        for idx in &cfg.index {
            let name = format!("{base}/{idx}");
            if cfg.is_file(&name) && !cfg.denied(&name) {
                return Some(Target { script_name: name, path_info: String::new() });
            }
        }
    }
    let fc = cfg.front_controller.as_ref()?;
    if cfg.is_file(fc) && !cfg.denied(fc) {
        return Some(Target { script_name: fc.clone(), path_info: String::new() });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn site(name: &str) -> (PhpConfig, PathBuf) {
        let root = std::env::temp_dir().join(format!("vajra-php-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in ["wp-admin", "wp-content/uploads/2026", "blog", "empty", "assets", ".git"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in [
            "index.php", "wp-login.php", "wp-admin/index.php", "wp-admin/admin-ajax.php",
            "wp-content/uploads/2026/evil.php", "wp-content/uploads/2026/pic.jpg", "assets/app.css",
            "blog/index.php", ".git/config", ".env",
        ] {
            fs::write(root.join(f), b"x").unwrap();
        }
        (PhpConfig::wordpress(&root), root)
    }

    fn script(c: Class) -> (String, String) {
        match c {
            Class::Script(t) => (t.script_name, t.path_info),
            other => panic!("expected script, got {other:?}"),
        }
    }

    #[test]
    fn plain_script_and_path_info() {
        let (c, _) = site("a");
        assert_eq!(script(classify(&c, "/wp-login.php")), ("/wp-login.php".into(), "".into()));
        assert_eq!(script(classify(&c, "/index.php/2026/hello")), ("/index.php".into(), "/2026/hello".into()));
        assert_eq!(script(classify(&c, "/wp-admin/admin-ajax.php")).0, "/wp-admin/admin-ajax.php");
        assert_eq!(script(classify(&c, "/index.php/a/")).1, "/a/");
        assert_eq!(classify(&c, "/WP-LOGIN.PHP/x"), Class::NotFound, "file names are case-sensitive");
    }

    #[test]
    fn percent_escapes_are_decoded_once() {
        let (c, _) = site("b");
        assert_eq!(script(classify(&c, "/wp%2Dlogin.php")).0, "/wp-login.php");
        assert_eq!(classify(&c, "/%2e%2e/etc/passwd"), Class::Bad);
        assert_eq!(classify(&c, "/a%00.php"), Class::Bad);
        assert_eq!(classify(&c, "/a%5Cb"), Class::Bad);
        assert_eq!(classify(&c, "/%zz"), Class::Bad);
        assert_eq!(classify(&c, "/%ff"), Class::Bad, "not UTF-8");
        assert_eq!(classify(&c, "no-slash"), Class::Bad);
        // %252e stays literal "%2e" after one decode: not a traversal.
        assert!(matches!(classify(&c, "/%252e%252e/x"), Class::Other(_)));
    }

    #[test]
    fn missing_scripts_never_fall_through() {
        let (c, _) = site("c");
        assert_eq!(classify(&c, "/nope.php"), Class::NotFound);
        assert_eq!(classify(&c, "/nope.php/more"), Class::NotFound);
        assert_eq!(classify(&c, "/assets/app.css/x.php"), Class::NotFound, "must not run app.css");
        assert_eq!(classify(&c, "/wp-content/uploads/2026/pic.jpg/x.php"), Class::NotFound);
    }

    #[test]
    fn uploads_do_not_execute() {
        let (c, _) = site("d");
        assert_eq!(classify(&c, "/wp-content/uploads/2026/evil.php"), Class::NotFound);
        assert_eq!(classify(&c, "/WP-Content/Uploads/2026/evil.php"), Class::NotFound);
        assert!(matches!(classify(&c, "/wp-content/uploads/2026/pic.jpg"), Class::Other(_)));
    }

    #[test]
    fn dotfiles_are_hidden_but_well_known_is_not() {
        let (c, _) = site("e");
        assert_eq!(classify(&c, "/.git/config"), Class::NotFound);
        assert_eq!(classify(&c, "/.env"), Class::NotFound);
        assert_eq!(classify(&c, "/a/.hidden/b"), Class::NotFound);
        assert!(matches!(classify(&c, "/.well-known/acme-challenge/x"), Class::Other(_)));
    }

    #[test]
    fn dot_segments_and_slashes_normalise() {
        let (c, _) = site("f");
        assert_eq!(script(classify(&c, "//wp-admin/./admin-ajax.php")).0, "/wp-admin/admin-ajax.php");
        assert_eq!(classify(&c, "/wp-admin/../index.php"), Class::Bad);
    }

    #[test]
    fn fallback_directory_index_then_front_controller() {
        let (c, _) = site("g");
        let t = fallback(&c, "/").unwrap();
        assert_eq!((t.script_name.as_str(), t.path_info.as_str()), ("/index.php", ""));
        assert_eq!(fallback(&c, "/wp-admin").unwrap().script_name, "/wp-admin/index.php");
        assert_eq!(fallback(&c, "/blog").unwrap().script_name, "/blog/index.php");
        // Directory without an index, and pretty permalinks: front controller.
        assert_eq!(fallback(&c, "/empty").unwrap().script_name, "/index.php");
        assert_eq!(fallback(&c, "/2026/10/hello-world").unwrap().script_name, "/index.php");
    }

    #[test]
    fn fallback_without_front_controller() {
        let (mut c, _) = site("h");
        c.front_controller = None;
        assert!(fallback(&c, "/2026/10/hello-world").is_none());
        assert!(fallback(&c, "/empty").is_none());
        assert!(fallback(&c, "/blog").is_some());
    }

    #[test]
    fn custom_extensions_and_other_cases() {
        let (mut c, root) = site("i");
        fs::write(root.join("old.php5"), b"x").unwrap();
        c.extensions = vec![".php".into(), ".php5".into()];
        assert_eq!(script(classify(&c, "/old.php5")).0, "/old.php5");
        c.extensions = vec![".php".into()];
        assert!(matches!(classify(&c, "/old.php5"), Class::Other(_)));
        assert!(matches!(classify(&c, "/.php"), Class::NotFound), "dotfile rule wins");
    }

    #[test]
    fn mutation_fuzz_never_panics() {
        let (c, _) = site("j");
        let seeds = ["/wp-login.php", "/index.php/a/b", "/%2e%2e/x.php", "/a/./b//c.php/d", "/.git/x", "/x%00y"];
        let mut x = 0x2545f4914f6cdd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let mut b = seeds[(next() % seeds.len() as u64) as usize].as_bytes().to_vec();
            for _ in 0..(next() % 4) {
                let i = (next() as usize) % b.len();
                b[i] = (next() % 128) as u8;
            }
            if let Ok(s) = String::from_utf8(b) {
                if let Class::Other(n) = classify(&c, &s) {
                    let _ = fallback(&c, &n);
                }
            }
        }
    }
}
