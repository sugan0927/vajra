//! Static-file path mapping: no input may escape the document root.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use vajra::config::StaticSettings;
use vajra::static_files::{FileCache, Lookup};

thread_local! {
    static FILES: RefCell<(FileCache, std::path::PathBuf)> = RefCell::new({
        let root = std::env::temp_dir().join(format!("vajra-fuzz-root-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("index.html"), "x").unwrap();
        std::fs::write(root.join("sub/a.txt"), "y").unwrap();
        // A secret *outside* the root that no lookup may ever return.
        std::fs::write(root.with_extension("secret"), "secret").unwrap();
        (FileCache::new(&StaticSettings::new(&root).unwrap()), root)
    });
}

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else { return };
    FILES.with(|f| {
        let (fc, root) = &mut *f.borrow_mut();
        if let Lookup::Found(file) = fc.lookup(path) {
            // Whatever was found must be inside the root: its size can only be one of ours.
            assert!(file.size <= 1, "served a file that is not in the document root");
            let _ = root;
        }
    });
});
