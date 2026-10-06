//! QPACK field-section decoding (static table, literals, Huffman strings).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vajra::h3::qpack::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut d = Decoder::new(16 * 1024);
    let _ = d.decode(data);
    // With a valid zero prefix, so the fuzzer reaches the field-line parser at once.
    let mut with_prefix = vec![0, 0];
    with_prefix.extend_from_slice(data);
    let _ = d.decode(&with_prefix);
});
