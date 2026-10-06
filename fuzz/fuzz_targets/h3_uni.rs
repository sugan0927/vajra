//! HTTP/3 unidirectional streams (control, QPACK, unknown types).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::h3::UniStream;

fuzz_target!(|data: &[u8]| {
    let mut u = UniStream::new();
    for chunk in data.chunks(1 + data.first().map_or(0, |&b| (b % 17) as usize)) {
        if u.feed(chunk).is_err() {
            break;
        }
    }
});
