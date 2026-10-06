//! Upstream response parsing: status line and headers, framing decisions, chunked decoding.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::proxy::{parse_response_head, Chunked, Framing, HeadParse};

fuzz_target!(|data: &[u8]| {
    let head_req = data.first().is_some_and(|b| b & 1 == 1);
    if let HeadParse::Done(h) = parse_response_head(data, head_req) {
        assert!(h.head_len <= data.len());
        let raw = &data[h.head_len..];
        if h.framing == Framing::Chunked {
            let mut c = Chunked::default();
            // Feed progressively, as the worker does while bytes arrive.
            for end in (0..=raw.len()).step_by(7).chain([raw.len()]) {
                if c.advance(&raw[..end], 4096).is_err() || c.done {
                    break;
                }
            }
            assert!(c.consumed <= raw.len());
        }
    }
    // Chunked framing without a head.
    let mut c = Chunked::default();
    let _ = c.advance(data, 4096);
});
