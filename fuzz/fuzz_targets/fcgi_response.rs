//! FastCGI record stream -> CGI response -> HTTP/1.1 rewrite, then the proxy
//! response parser on the result (what the worker does next).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::fastcgi::{cgi_to_http, decode_params, Decoder};
use vajra::proxy::parse_response_head;

fuzz_target!(|data: &[u8]| {
    let head_req = data.first().is_some_and(|b| b & 1 == 1);
    let cut = data.len() / 2;
    let mut d = Decoder::new();
    let _ = d.feed(&data[..cut], 1 << 20);
    let _ = d.feed(&data[cut..], 1 << 20);
    if let Ok(http) = d.take_http(head_req) {
        let _ = parse_response_head(&http, head_req);
    }
    if let Ok(http) = cgi_to_http(data, head_req) {
        let _ = parse_response_head(&http, head_req);
    }
    let _ = decode_params(data);
});
