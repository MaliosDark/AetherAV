#![no_main]
//! Fuzz the container extraction layer (ZIP/GZIP/TAR/7z) on malformed archives.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aether_unpack::detect(data);
    let _ = aether_unpack::try_extract(data, aether_unpack::Limits::default());
});
