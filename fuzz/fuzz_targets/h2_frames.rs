//! HTTP/2 connection state machine: arbitrary frames after a valid client preface.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::h2::{H2Body, H2Conn, H2Response};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    let mut h = H2Conn::new(1 << 16, &mut out);
    let mut input = PREFACE.to_vec();
    input.extend_from_slice(data);
    for _ in 0..64 {
        let fed = h.feed(&input, &mut out);
        assert!(fed.consumed <= input.len());
        input.drain(..fed.consumed);
        while let Some(req) = h.take_ready() {
            h.respond(
                req.stream,
                H2Response { status: 200, headers: vec![(b"x".to_vec(), b"y".to_vec())], body: H2Body::Mem(vec![7; 70_000]) },
                &mut out,
            );
        }
        while h.poll_output(&mut out).is_some() {}
        out.clear();
        if fed.fatal || fed.consumed == 0 || input.is_empty() {
            break;
        }
    }
});
