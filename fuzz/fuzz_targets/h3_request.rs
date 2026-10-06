//! HTTP/3 request stream: frame ordering, QPACK field sections, header validation.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::h3::{qpack, RequestStream};

fuzz_target!(|data: &[u8]| {
    let mut dec = qpack::Decoder::new(16 * 1024);
    let split = data.first().map_or(0, |&b| b as usize) % (data.len() + 1);
    // Two deliveries, FIN on the last (and once with FIN on the first).
    let mut a = RequestStream::new(4096);
    let _ = a.feed(&data[..split], false, &mut dec);
    let _ = a.feed(&data[split..], true, &mut dec);
    let _ = RequestStream::new(4096).feed(data, true, &mut dec);
});
