//! Per-core response cache for proxied `GET` responses.
//!
//! Each worker owns a private cache (share-nothing): no locks, no atomics.
//! The trade-off is that N workers may each fetch an object once, and memory
//! use is N times the configured per-worker limits.
//!
//! * Strict LRU eviction (a `BTreeMap` of generation -> key), bounded by both
//!   entry count and total bytes.
//! * Freshness comes from `Cache-Control: s-maxage` / `max-age`, else the
//!   route's `cache_default_ttl_secs` (0 = only cache with explicit freshness).
//! * Never cached: responses with `Set-Cookie`, any `Vary`, or
//!   `Cache-Control: no-store | no-cache | private`; statuses outside
//!   200/203/204/301/404/410; objects over `max_object_bytes`.
//! * Requests bypass the cache when they carry `Authorization`, or
//!   `Cache-Control: no-cache|no-store`, or `Pragma: no-cache`.
//! * A successful unsafe method (POST/PUT/PATCH/DELETE) on a URL invalidates it.
//!
//! Not implemented (documented limitations): `Expires`, conditional
//! revalidation, stale-while-revalidate, request coalescing, `Vary`.

use crate::config::CacheSettings;
use crate::proxy::is_hop_by_hop;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

const MAX_TTL_SECS: u64 = 7 * 24 * 3600;
/// Approximate per-entry bookkeeping overhead counted against `max_bytes`.
const ENTRY_OVERHEAD: usize = 160;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub evictions: u64,
    pub invalidations: u64,
}

pub struct CachedResponse {
    pub status: u16,
    /// Already filtered: no hop-by-hop, Date, Server, Content-Length or Age.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Rc<Vec<u8>>,
    pub stored_at: u64,
    pub expires_at: u64,
}

/// What to do with the cache when a proxied request completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheMode {
    None,
    /// Store a cacheable response under this key.
    Store(String),
    /// A successful unsafe method: drop this key.
    Invalidate(String),
}

#[derive(Clone, Copy, Debug)]
pub struct CachePolicy {
    pub default_ttl: u64,
    pub max_object_bytes: usize,
}

struct Slot {
    resp: Rc<CachedResponse>,
    gen: u64,
    size: usize,
}

pub struct Cache {
    map: HashMap<Rc<str>, Slot>,
    order: BTreeMap<u64, Rc<str>>,
    gen: u64,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    pub stats: CacheStats,
}

impl Cache {
    pub fn new(cfg: &CacheSettings) -> Self {
        Self {
            map: HashMap::new(),
            order: BTreeMap::new(),
            gen: 0,
            bytes: 0,
            max_entries: cfg.max_entries,
            max_bytes: cfg.max_bytes,
            stats: CacheStats::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Look up a fresh entry (counts a hit or a miss). Expired entries are dropped.
    pub fn get(&mut self, key: &str, now: u64) -> Option<Rc<CachedResponse>> {
        let Some(slot) = self.map.get_mut(key) else {
            self.stats.misses += 1;
            return None;
        };
        if now >= slot.resp.expires_at {
            self.remove(key);
            self.stats.misses += 1;
            return None;
        }
        // Touch: move to the most-recently-used end.
        self.gen += 1;
        let k = self.order.remove(&slot.gen).expect("order in sync");
        slot.gen = self.gen;
        self.order.insert(self.gen, k);
        self.stats.hits += 1;
        Some(Rc::clone(&slot.resp))
    }

    pub fn put(&mut self, key: String, resp: CachedResponse) {
        let size = ENTRY_OVERHEAD
            + key.len()
            + resp.body.len()
            + resp.headers.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>();
        if self.max_entries == 0 || size > self.max_bytes {
            return;
        }
        self.remove(&key);
        while !self.map.is_empty() && (self.map.len() >= self.max_entries || self.bytes + size > self.max_bytes) {
            self.evict_lru();
        }
        self.gen += 1;
        let k: Rc<str> = Rc::from(key.as_str());
        self.order.insert(self.gen, Rc::clone(&k));
        self.map.insert(k, Slot { resp: Rc::new(resp), gen: self.gen, size });
        self.bytes += size;
        self.stats.stores += 1;
    }

    pub fn invalidate(&mut self, key: &str) {
        if self.remove(key) {
            self.stats.invalidations += 1;
        }
    }

    fn remove(&mut self, key: &str) -> bool {
        match self.map.remove(key) {
            Some(slot) => {
                self.order.remove(&slot.gen);
                self.bytes -= slot.size;
                true
            }
            None => false,
        }
    }

    fn evict_lru(&mut self) {
        if let Some((_, key)) = self.order.pop_first() {
            if let Some(slot) = self.map.remove(&*key) {
                self.bytes -= slot.size;
                self.stats.evictions += 1;
            }
        }
    }
}

// ───────────────────────── policy helpers ─────────────────────────

/// Cache key: lower-cased host + request target (path and query).
pub fn cache_key(host: &[u8], target: &str) -> String {
    format!("{}{}", String::from_utf8_lossy(host).to_ascii_lowercase(), target)
}

fn strip_ci<'a>(d: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (d.len() >= prefix.len() && d[..prefix.len()].eq_ignore_ascii_case(prefix)).then(|| &d[prefix.len()..])
}

fn parse_secs(v: &[u8]) -> Option<u64> {
    std::str::from_utf8(v).ok()?.trim().trim_matches('"').parse::<u64>().ok()
}

/// Does the *request* forbid serving from (or storing to) the cache?
pub fn request_bypasses(headers: &[(&[u8], &[u8])]) -> bool {
    headers.iter().any(|(n, v)| {
        if n.eq_ignore_ascii_case(b"authorization") {
            return true;
        }
        let is_cc = n.eq_ignore_ascii_case(b"cache-control");
        let is_pragma = n.eq_ignore_ascii_case(b"pragma");
        (is_cc || is_pragma)
            && v.split(|&b| b == b',').any(|d| {
                let d = d.trim_ascii();
                d.eq_ignore_ascii_case(b"no-cache") || d.eq_ignore_ascii_case(b"no-store")
            })
    })
}

/// Freshness lifetime in seconds if the response may be stored, else `None`.
pub fn ttl_for(
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body_len: usize,
    policy: &CachePolicy,
) -> Option<u64> {
    if !matches!(status, 200 | 203 | 204 | 301 | 404 | 410) || body_len > policy.max_object_bytes {
        return None;
    }
    let (mut s_maxage, mut max_age) = (None, None);
    for (n, v) in headers {
        if n.eq_ignore_ascii_case(b"set-cookie") {
            return None;
        }
        if n.eq_ignore_ascii_case(b"vary") && !v.trim_ascii().is_empty() {
            return None;
        }
        if n.eq_ignore_ascii_case(b"cache-control") {
            for d in v.split(|&b| b == b',') {
                let d = d.trim_ascii();
                if d.eq_ignore_ascii_case(b"no-store")
                    || d.eq_ignore_ascii_case(b"no-cache")
                    || d.eq_ignore_ascii_case(b"private")
                {
                    return None;
                }
                if let Some(rest) = strip_ci(d, b"s-maxage=") {
                    s_maxage = parse_secs(rest);
                } else if let Some(rest) = strip_ci(d, b"max-age=") {
                    max_age = parse_secs(rest);
                }
            }
        }
    }
    let ttl = s_maxage.or(max_age).unwrap_or(policy.default_ttl).min(MAX_TTL_SECS);
    (ttl > 0).then_some(ttl)
}

/// Headers worth keeping in the cache (drops hop-by-hop and per-response ones).
pub fn storable_headers(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    headers
        .iter()
        .filter(|(n, _)| {
            !is_hop_by_hop(n)
                && !n.eq_ignore_ascii_case(b"date")
                && !n.eq_ignore_ascii_case(b"server")
                && !n.eq_ignore_ascii_case(b"content-length")
                && !n.eq_ignore_ascii_case(b"age")
        })
        .cloned()
        .collect()
}

pub enum Lookup {
    Hit(Rc<CachedResponse>),
    Miss(CacheMode),
}

/// The one place that decides how a proxied request interacts with the cache.
/// Shared by the HTTP/1.1 and HTTP/2 paths.
pub fn lookup_for_request(
    cache: &mut Cache,
    enabled: bool,
    method: &str,
    host: &[u8],
    target: &str,
    headers: &[(&[u8], &[u8])],
    now: u64,
) -> Lookup {
    if !enabled {
        return Lookup::Miss(CacheMode::None);
    }
    match method {
        "GET" => {
            if request_bypasses(headers) {
                return Lookup::Miss(CacheMode::None);
            }
            let key = cache_key(host, target);
            match cache.get(&key, now) {
                Some(hit) => Lookup::Hit(hit),
                None => Lookup::Miss(CacheMode::Store(key)),
            }
        }
        "HEAD" | "OPTIONS" => Lookup::Miss(CacheMode::None),
        _ => Lookup::Miss(CacheMode::Invalidate(cache_key(host, target))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(entries: usize, bytes: usize) -> CacheSettings {
        CacheSettings { max_entries: entries, max_bytes: bytes, max_object_bytes: 1 << 20 }
    }

    fn resp(body: &str, expires_at: u64) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![],
            body: Rc::new(body.as_bytes().to_vec()),
            stored_at: 0,
            expires_at,
        }
    }

    fn h(n: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
        (n.as_bytes().to_vec(), v.as_bytes().to_vec())
    }

    const POLICY: CachePolicy = CachePolicy { default_ttl: 0, max_object_bytes: 1000 };

    #[test]
    fn hit_miss_and_expiry() {
        let mut c = Cache::new(&settings(10, 1 << 20));
        assert!(c.get("a", 0).is_none());
        c.put("a".into(), resp("x", 100));
        assert_eq!(c.get("a", 50).unwrap().body.as_slice(), b"x");
        assert!(c.get("a", 100).is_none(), "expired at exactly expires_at");
        assert_eq!(c.len(), 0);
        assert_eq!(c.stats, CacheStats { hits: 1, misses: 2, stores: 1, evictions: 0, invalidations: 0 });
    }

    #[test]
    fn lru_eviction_by_entry_count() {
        let mut c = Cache::new(&settings(2, 1 << 20));
        c.put("a".into(), resp("1", 1000));
        c.put("b".into(), resp("2", 1000));
        c.get("a", 0); // a is now most recent
        c.put("c".into(), resp("3", 1000)); // evicts b
        assert!(c.get("a", 0).is_some());
        assert!(c.get("b", 0).is_none());
        assert!(c.get("c", 0).is_some());
        assert_eq!(c.stats.evictions, 1);
    }

    #[test]
    fn eviction_by_bytes_and_oversize_rejected() {
        let one = ENTRY_OVERHEAD + 1 + 100; // key "k" + 100-byte body
        let mut c = Cache::new(&settings(100, one * 2 + 10));
        let body = "x".repeat(100);
        c.put("1".into(), resp(&body, 1000));
        c.put("2".into(), resp(&body, 1000));
        assert_eq!(c.len(), 2);
        c.put("3".into(), resp(&body, 1000));
        assert_eq!(c.len(), 2, "oldest evicted to stay under max_bytes");
        assert!(c.bytes() <= one * 2 + 10);

        c.put("huge".into(), resp(&"y".repeat(10_000), 1000));
        assert!(c.get("huge", 0).is_none());
    }

    #[test]
    fn replace_and_invalidate_keep_accounting_straight() {
        let mut c = Cache::new(&settings(10, 1 << 20));
        c.put("a".into(), resp("one", 1000));
        let b1 = c.bytes();
        c.put("a".into(), resp("three", 1000));
        assert_eq!(c.len(), 1);
        assert_eq!(c.bytes(), b1 + 2);
        c.invalidate("a");
        assert_eq!((c.len(), c.bytes()), (0, 0));
        assert_eq!(c.stats.invalidations, 1);
    }

    #[test]
    fn disabled_cache_stores_nothing() {
        let mut c = Cache::new(&settings(0, 0));
        c.put("a".into(), resp("x", 1000));
        assert!(c.is_empty());
    }

    #[test]
    fn ttl_rules() {
        let p = CachePolicy { default_ttl: 0, max_object_bytes: 1000 };
        assert_eq!(ttl_for(200, &[h("Cache-Control", "max-age=60")], 10, &p), Some(60));
        assert_eq!(ttl_for(200, &[h("cache-control", "public, max-age=60, s-maxage=5")], 10, &p), Some(5));
        assert_eq!(ttl_for(200, &[], 10, &p), None, "no freshness info and default 0");
        let p2 = CachePolicy { default_ttl: 30, ..p };
        assert_eq!(ttl_for(200, &[], 10, &p2), Some(30));
        assert_eq!(ttl_for(404, &[], 10, &p2), Some(30));
        assert_eq!(ttl_for(500, &[], 10, &p2), None);
        assert_eq!(ttl_for(200, &[], 5000, &p2), None, "too large");
        assert_eq!(ttl_for(200, &[h("Cache-Control", "max-age=0")], 10, &p2), None);
        assert_eq!(ttl_for(200, &[h("Cache-Control", "max-age=99999999999")], 10, &p), Some(MAX_TTL_SECS));
    }

    #[test]
    fn ttl_refusals() {
        for (n, v) in [
            ("Cache-Control", "no-store"),
            ("Cache-Control", "private, max-age=60"),
            ("Cache-Control", "no-cache"),
            ("Set-Cookie", "a=b"),
            ("Vary", "Accept-Encoding"),
        ] {
            let hs = [h("Cache-Control", "max-age=60"), h(n, v)];
            assert_eq!(ttl_for(200, &hs, 10, &POLICY), None, "{n}: {v}");
        }
        assert_eq!(ttl_for(200, &[h("Vary", ""), h("Cache-Control", "max-age=5")], 1, &POLICY), Some(5));
    }

    #[test]
    fn storable_headers_filtering() {
        let hs = vec![
            h("Content-Type", "text/plain"),
            h("Connection", "keep-alive"),
            h("Date", "x"),
            h("Server", "y"),
            h("Content-Length", "5"),
            h("Age", "9"),
            h("ETag", "\"e\""),
        ];
        let kept = storable_headers(&hs);
        let names: Vec<_> = kept.iter().map(|(n, _)| String::from_utf8_lossy(n).into_owned()).collect();
        assert_eq!(names, ["Content-Type", "ETag"]);
    }

    #[test]
    fn request_bypass_rules() {
        let b = |hs: &[(&[u8], &[u8])]| request_bypasses(hs);
        assert!(b(&[(b"Authorization", b"Bearer x")]));
        assert!(b(&[(b"cache-control", b"no-cache")]));
        assert!(b(&[(b"Cache-Control", b"max-age=0, no-store")]));
        assert!(b(&[(b"Pragma", b"no-cache")]));
        assert!(!b(&[(b"Accept", b"*/*"), (b"Cache-Control", b"max-age=0")]));
    }

    #[test]
    fn lookup_modes() {
        let mut c = Cache::new(&settings(10, 1 << 20));
        let none: &[(&[u8], &[u8])] = &[];
        // disabled route
        assert!(matches!(
            lookup_for_request(&mut c, false, "GET", b"h", "/x", none, 0),
            Lookup::Miss(CacheMode::None)
        ));
        // GET miss -> Store(key)
        let Lookup::Miss(CacheMode::Store(key)) = lookup_for_request(&mut c, true, "GET", b"Host", "/x?a=1", none, 0) else {
            panic!("expected store")
        };
        assert_eq!(key, "host/x?a=1");
        c.put(key, resp("cached", 100));
        assert!(matches!(lookup_for_request(&mut c, true, "GET", b"HOST", "/x?a=1", none, 5), Lookup::Hit(_)));
        // HEAD never touches the cache; POST invalidates.
        assert!(matches!(lookup_for_request(&mut c, true, "HEAD", b"host", "/x?a=1", none, 5), Lookup::Miss(CacheMode::None)));
        assert!(matches!(
            lookup_for_request(&mut c, true, "POST", b"host", "/x?a=1", none, 5),
            Lookup::Miss(CacheMode::Invalidate(_))
        ));
        // Authorization bypasses entirely.
        let auth: &[(&[u8], &[u8])] = &[(b"authorization", b"x")];
        assert!(matches!(lookup_for_request(&mut c, true, "GET", b"host", "/x?a=1", auth, 5), Lookup::Miss(CacheMode::None)));
    }
}
