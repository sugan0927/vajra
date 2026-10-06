//! Configuration parsing and validation must reject, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;
use vajra::config::Settings;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Settings::from_toml_str(text, Path::new("/nonexistent-vajra-fuzz"));
    }
});
