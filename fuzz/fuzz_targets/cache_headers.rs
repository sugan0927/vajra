//! Cacheability decisions over arbitrary header sets.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::cache::{cache_key, request_bypasses, storable_headers, ttl_for, CachePolicy};

fuzz_target!(|data: &[u8]| {
    let headers: Vec<(Vec<u8>, Vec<u8>)> = data
        .split(|&b| b == b'\n')
        .map(|l| match l.iter().position(|&b| b == b':') {
            Some(i) => (l[..i].to_vec(), l[i + 1..].trim_ascii().to_vec()),
            None => (l.to_vec(), Vec::new()),
        })
        .collect();
    let status = [200u16, 204, 301, 404, 500][data.first().map_or(0, |&b| b as usize) % 5];
    let policy = CachePolicy { default_ttl: 30, max_object_bytes: 1 << 20 };
    let _ = ttl_for(status, &headers, data.len(), &policy);
    let _ = storable_headers(&headers);
    let borrowed: Vec<(&[u8], &[u8])> = headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
    let _ = request_bypasses(&borrowed);
    let _ = cache_key(data, &String::from_utf8_lossy(data));
});
