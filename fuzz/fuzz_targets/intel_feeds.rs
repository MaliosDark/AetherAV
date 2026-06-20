#![no_main]
//! Fuzz the threat-intel feed parsers on malformed CSV/JSON.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = aether_intel::Feed::from_threatfox_csv(text, 1);
        let _ = aether_intel::Feed::from_malwarebazaar_csv(text, 1);
        let _ = aether_intel::Feed::from_urlhaus_csv(text, 1);
        let _ = aether_intel::Feed::from_feodo_csv(text, 1);
        let _ = aether_intel::Feed::from_sha256_list(text, 1, "fuzz");
        let _ = aether_intel::Feed::from_misp_json(text, 1, "fuzz");
    }
});
