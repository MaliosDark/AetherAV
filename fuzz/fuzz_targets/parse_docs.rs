#![no_main]
//! Fuzz the document/script indicator scanners (PDF / Office / scripts).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aether_parsers::pdf::PdfIndicators::scan(data);
    let _ = aether_parsers::office::OfficeIndicators::scan(data);
    let _ = aether_parsers::script::ScriptIndicators::scan(data);
    let _ = aether_parsers::script::classify_lang(data);
});
