//! Static file resolution: safe path mapping, MIME types, and a per-core cache
//! of *open file descriptors* with precomputed validators.
//!
//! ## Why cache open files?
//! Serving a file normally costs `open + fstat + close` syscalls per request.
//! Here each worker keeps `Rc<OpenFile>` entries keyed by the raw request path.
//! A hit costs a hash lookup and zero syscalls; the cached fd is handed straight
//! to `splice` by the worker. Entries are revalidated by re-opening after
//! `cache_ttl_secs`, which bounds how stale a replaced/modified file can look.
//! `Rc` (not `Arc`) because the cache is strictly per-core: share-nothing.
//!
//! ## Security model
//! * The request path is percent-decoded *first*, then split on `/`, so
//!   `%2e%2e`, `%2f` and friends cannot smuggle traversal past the checks.
//! * `..` segments => 400. Any segment beginning with `.` (dotfiles such as
//!   `.git`, `.env`) => 404.
//! * The resolved path is canonicalised and must stay under the canonical
//!   document root, which blocks symlink escapes.
//! * Only regular files are served (directories, FIFOs, devices => 404).
//!
//! Known limitation (Phase 6 item): canonicalize-then-open has a small TOCTOU
//! window against an attacker who can write inside the docroot.
//! `openat2(RESOLVE_BENEATH)` will close it.
//!
//! Also a deliberate Phase 2 deviation: on a cache *miss* the open/stat happen
//! synchronously on the event loop. They hit the dentry/page cache in the
//! common case. Moving them to `IORING_OP_OPENAT`/`STATX` is planned.

use crate::config::StaticSettings;
use crate::date::{format_http_date, DATE_LEN};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// An open regular file plus everything needed to answer a request about it
/// without touching the filesystem again.
#[derive(Debug)]
pub struct OpenFile {
    file: File, // closed automatically when the last Rc is dropped
    pub size: u64,
    pub ctype: &'static str,
    /// Strong validator, e.g. `"65f1c2a0-1f40"` (quotes included).
    pub etag: String,
    /// Pre-serialised `ETag: ..\r\nLast-Modified: ..\r\n` header lines (HTTP/1.1).
    pub head_extra: Vec<u8>,
    /// Last-Modified value, for HTTP/2 header fields.
    pub last_modified: [u8; DATE_LEN],
}

impl OpenFile {
    fn new(file: File, size: u64, mtime: i64, ctype: &'static str) -> Self {
        let etag = format!("\"{:x}-{:x}\"", mtime, size);
        let mut lm = [0u8; DATE_LEN];
        format_http_date(mtime.max(0) as u64, &mut lm);

        let mut head_extra = Vec::with_capacity(96);
        head_extra.extend_from_slice(b"ETag: ");
        head_extra.extend_from_slice(etag.as_bytes());
        head_extra.extend_from_slice(b"\r\nLast-Modified: ");
        head_extra.extend_from_slice(&lm);
        head_extra.extend_from_slice(b"\r\n");

        Self { file, size, ctype, etag, head_extra, last_modified: lm }
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[derive(Debug)]
pub enum Lookup {
    Found(Rc<OpenFile>),
    NotFound,
    /// Malformed or malicious path (bad escapes, `..`, NUL, no leading `/`).
    BadRequest,
}

struct Entry {
    file: Rc<OpenFile>,
    checked_at: u64,
}

pub struct FileCache {
    root: PathBuf,
    index: String,
    ttl: u64,
    max: usize,
    now: u64,
    map: HashMap<String, Entry>,
}

impl FileCache {
    pub fn new(cfg: &StaticSettings) -> Self {
        Self {
            root: cfg.root.clone(),
            index: cfg.index.clone(),
            ttl: cfg.cache_ttl_secs,
            max: cfg.max_cached_files,
            now: 0,
            map: HashMap::with_capacity(cfg.max_cached_files.min(1024)),
        }
    }

    /// Called once per event-loop batch with the current unix time (seconds),
    /// so lookups never read the clock themselves.
    #[inline]
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// Resolve a raw (still percent-encoded, query-less) request path.
    pub fn lookup(&mut self, raw: &str) -> Lookup {
        // Hot path: fresh cache hit. Keys are only ever inserted after full
        // validation, so a hit is safe by construction and skips decoding.
        if let Some(e) = self.map.get(raw) {
            if self.now.saturating_sub(e.checked_at) < self.ttl {
                return Lookup::Found(Rc::clone(&e.file));
            }
        }

        match self.resolve(raw) {
            Lookup::Found(f) => {
                if self.map.len() >= self.max && !self.map.contains_key(raw) {
                    // Crude but bounded. In-flight transfers keep their Rc alive.
                    self.map.clear();
                }
                self.map.insert(raw.to_owned(), Entry { file: Rc::clone(&f), checked_at: self.now });
                Lookup::Found(f)
            }
            other => {
                self.map.remove(raw); // gone or no longer valid
                other
            }
        }
    }

    /// Slow path: decode, sanitise, canonicalise, open.
    fn resolve(&self, raw: &str) -> Lookup {
        let decoded = match percent_decode(raw) {
            Some(d) => d,
            None => return Lookup::BadRequest,
        };
        if !decoded.starts_with('/') {
            return Lookup::BadRequest;
        }

        let mut rel = PathBuf::new();
        for seg in decoded.split('/') {
            if seg.is_empty() {
                continue;
            }
            if seg == ".." {
                return Lookup::BadRequest;
            }
            if seg.starts_with('.') {
                return Lookup::NotFound; // dotfiles and "."
            }
            rel.push(seg);
        }
        if decoded.ends_with('/') || rel.as_os_str().is_empty() {
            rel.push(&self.index);
        }

        let canon = match std::fs::canonicalize(self.root.join(&rel)) {
            Ok(p) => p,
            Err(_) => return Lookup::NotFound,
        };
        if !canon.starts_with(&self.root) {
            return Lookup::NotFound; // symlink pointing outside the root
        }
        // Check the type *before* open(): opening a FIFO would block the loop.
        match std::fs::metadata(&canon) {
            Ok(m) if m.is_file() => {}
            _ => return Lookup::NotFound,
        }
        let file = match File::open(&canon) {
            Ok(f) => f,
            Err(_) => return Lookup::NotFound,
        };
        let md = match file.metadata() {
            Ok(m) if m.is_file() => m,
            _ => return Lookup::NotFound,
        };

        Lookup::Found(Rc::new(OpenFile::new(file, md.len(), md.mtime(), mime_for(&canon))))
    }
}

/// Decode `%XX` escapes. Rejects invalid escapes, NUL bytes and non-UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // Both hex digits must exist: index i+2 has to be in bounds.
            if i + 2 >= b.len() {
                return None;
            }
            let hi = (b[i + 1] as char).to_digit(16)?;
            let lo = (b[i + 2] as char).to_digit(16)?;
            out.push((hi << 4 | lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    if out.contains(&0) {
        return None;
    }
    String::from_utf8(out).ok()
}

fn mime_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn setup(name: &str) -> (PathBuf, FileCache) {
        let root = std::env::temp_dir().join(format!("vajra-sf-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("index.html"), "<h1>root</h1>").unwrap();
        std::fs::write(root.join("a.txt"), "hello").unwrap();
        std::fs::write(root.join("sub/index.html"), "sub").unwrap();
        std::fs::write(root.join(".secret"), "nope").unwrap();
        let st = StaticSettings::new(&root).unwrap();
        (root, FileCache::new(&st))
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("/a%20b").unwrap(), "/a b");
        assert_eq!(percent_decode("/%2e%2e/x").unwrap(), "/../x");
        assert!(percent_decode("/bad%zz").is_none());
        assert!(percent_decode("/trunc%4").is_none());
        assert!(percent_decode("/end%").is_none());
        assert!(percent_decode("/nul%00").is_none());
        assert!(percent_decode("/%ff%fe").is_none()); // invalid UTF-8
    }

    #[test]
    fn mime_types() {
        assert_eq!(mime_for(Path::new("x.HTML")), "text/html; charset=utf-8");
        assert_eq!(mime_for(Path::new("x.png")), "image/png");
        assert_eq!(mime_for(Path::new("x.unknown")), "application/octet-stream");
        assert_eq!(mime_for(Path::new("noext")), "application/octet-stream");
    }

    #[test]
    fn finds_files_and_indexes() {
        let (_r, mut c) = setup("find");
        match c.lookup("/a.txt") {
            Lookup::Found(f) => {
                assert_eq!(f.size, 5);
                assert_eq!(f.ctype, "text/plain; charset=utf-8");
                assert!(f.etag.starts_with('"'));
                assert!(std::str::from_utf8(&f.head_extra).unwrap().contains("Last-Modified: "));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(c.lookup("/"), Lookup::Found(f) if f.size == 13));
        assert!(matches!(c.lookup("/sub/"), Lookup::Found(f) if f.size == 3));
    }

    #[test]
    fn missing_dirs_and_dotfiles_are_404() {
        let (_r, mut c) = setup("404");
        assert!(matches!(c.lookup("/missing"), Lookup::NotFound));
        assert!(matches!(c.lookup("/sub"), Lookup::NotFound)); // directory, no slash
        assert!(matches!(c.lookup("/.secret"), Lookup::NotFound));
        assert!(matches!(c.lookup("/%2esecret"), Lookup::NotFound));
    }

    #[test]
    fn traversal_is_rejected() {
        let (_r, mut c) = setup("trav");
        assert!(matches!(c.lookup("/../etc/passwd"), Lookup::BadRequest));
        assert!(matches!(c.lookup("/%2e%2e/etc/passwd"), Lookup::BadRequest));
        assert!(matches!(c.lookup("/sub/..%2f..%2fetc/passwd"), Lookup::BadRequest));
        assert!(matches!(c.lookup("/a%00.txt"), Lookup::BadRequest));
        assert!(matches!(c.lookup("no-leading-slash"), Lookup::BadRequest));
    }

    #[test]
    fn symlink_escape_is_blocked() {
        let (r, mut c) = setup("sym");
        symlink("/etc/hostname", r.join("escape.txt")).unwrap();
        symlink(r.join("a.txt"), r.join("inside.txt")).unwrap();
        assert!(matches!(c.lookup("/escape.txt"), Lookup::NotFound));
        assert!(matches!(c.lookup("/inside.txt"), Lookup::Found(_)));
    }

    #[test]
    fn cache_hits_share_the_same_open_file() {
        let (_r, mut c) = setup("hit");
        c.set_now(100);
        let a = match c.lookup("/a.txt") { Lookup::Found(f) => f, _ => panic!() };
        c.set_now(101); // within the 2s TTL
        let b = match c.lookup("/a.txt") { Lookup::Found(f) => f, _ => panic!() };
        assert!(Rc::ptr_eq(&a, &b));
        c.set_now(110); // expired: re-opened
        let d = match c.lookup("/a.txt") { Lookup::Found(f) => f, _ => panic!() };
        assert!(!Rc::ptr_eq(&a, &d));
    }

    #[test]
    fn deleted_file_disappears_after_ttl() {
        let (r, mut c) = setup("del");
        c.set_now(0);
        assert!(matches!(c.lookup("/a.txt"), Lookup::Found(_)));
        std::fs::remove_file(r.join("a.txt")).unwrap();
        c.set_now(10);
        assert!(matches!(c.lookup("/a.txt"), Lookup::NotFound));
    }
}
