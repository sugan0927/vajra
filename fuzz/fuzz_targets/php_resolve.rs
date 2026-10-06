//! PHP path classification: never panics, never yields a script path that
//! contains `..`, a dot segment or a NUL.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use vajra::php::{classify, fallback, Class, PhpConfig};

fn cfg() -> &'static PhpConfig {
    static C: OnceLock<PhpConfig> = OnceLock::new();
    C.get_or_init(|| {
        let root = std::env::temp_dir().join("vajra-fuzz-php");
        let _ = std::fs::create_dir_all(root.join("wp-content/uploads"));
        let _ = std::fs::write(root.join("index.php"), b"x");
        let _ = std::fs::write(root.join("a.php"), b"x");
        PhpConfig::wordpress(&root)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else { return };
    match classify(cfg(), path) {
        Class::Script(t) => {
            for p in [&t.script_name, &t.path_info] {
                assert!(!p.contains('\0') && !p.split('/').any(|s| s == ".." || s == "."));
            }
            assert!(t.script_name.starts_with('/'));
            assert!(t.path_info.is_empty() || t.path_info.starts_with('/'));
        }
        Class::Other(n) => {
            if let Some(t) = fallback(cfg(), &n) {
                assert!(t.script_name.starts_with('/') && !t.script_name.contains(".."));
            }
        }
        _ => {}
    }
});
