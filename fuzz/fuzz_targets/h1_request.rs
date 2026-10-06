//! HTTP/1.1 request parsing, routing and response generation, fed like the
//! worker feeds it: arbitrary bytes split into two reads, pipelined requests,
//! proxy and cache paths enabled.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use vajra::cache::Cache;
use vajra::config::{CacheSettings, ProxySettings};
use vajra::date::DATE_LEN;
use vajra::http::{self, Ctx};
use vajra::observe::Observer;
use vajra::proxy::ProxyTable;

thread_local! {
    static STATE: RefCell<(ProxyTable, Cache, Observer)> = RefCell::new({
        let mut p = ProxySettings::simple("/api/", "127.0.0.1:9".parse().unwrap(), false, 5);
        p.cache = true;
        (
            ProxyTable::new(&[p], 1 << 20),
            Cache::new(&CacheSettings::default()),
            Observer::new(),
        )
    });
}

fuzz_target!(|data: &[u8]| {
    let date = [b'D'; DATE_LEN];
    STATE.with(|s| {
        let (table, cache, obs) = &mut *s.borrow_mut();
        let split = data.first().map_or(0, |&b| b as usize) % (data.len() + 1);
        let mut input: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        for part in [&data[..split], &data[split..]] {
            input.extend_from_slice(part);
            for _ in 0..16 {
                let mut ctx = Ctx {
                    files: None,
                    proxies: table,
                    cache,
                    obs,
                    now: 1_000,
                    max_body: 4096,
                    secure: false,
                    client_ip: Some("192.0.2.1".parse().unwrap()),
                };
                let o = http::process(&input, &mut out, &date, &mut ctx);
                assert!(o.consumed <= input.len());
                input.drain(..o.consumed);
                out.clear();
                if o.close || o.consumed == 0 || input.is_empty() {
                    break;
                }
            }
        }
    });
});
