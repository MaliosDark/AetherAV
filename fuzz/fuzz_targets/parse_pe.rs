#![no_main]
//! Fuzz the PE parser + entropy on arbitrary bytes. Must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aether_parsers::FileFormat::detect(data);
    let _ = aether_parsers::pe::PeInfo::parse(data);
    let _ = aether_parsers::entropy::shannon(data);
});
