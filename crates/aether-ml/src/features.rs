//! Feature extraction for the static PE classifier.
//!
//! The schema is **fixed and ordered**: the model's weight vector lines up with
//! [`PE_FEATURES`] index-for-index. Keeping names alongside values makes a
//! prediction explainable ("the model leaned on `max_entropy` and `has_wx`")
//! and lets us validate that a loaded model matches the extractor at startup.

use aether_parsers::entropy::EntropyBand;
use aether_parsers::pe::PeInfo;

/// Ordered names of the PE feature vector. Index = position in the vector.
pub const PE_FEATURES: &[&str] = &[
    "section_count",
    "max_entropy",
    "mean_entropy",
    "has_wx",
    "import_count",
    "import_dll_count",
    "suspicious_import_count",
    "has_injection_combo",
    "is_dll",
    "high_entropy_ratio",
    "anonymous_section",
    "tiny_imports",
];

/// Number of features in the PE vector.
pub const PE_DIM: usize = PE_FEATURES.len();

/// Extract the fixed-length feature vector from a parsed PE.
pub fn pe_features(pe: &PeInfo) -> Vec<f32> {
    let n = pe.sections.len().max(1) as f64;
    let mean_entropy = pe.sections.iter().map(|s| s.entropy).sum::<f64>() / n;
    let high_entropy_ratio = pe
        .sections
        .iter()
        .filter(|s| matches!(s.band, EntropyBand::High | EntropyBand::VeryHigh))
        .count() as f64
        / n;

    let sus = pe.suspicious_imports();
    let has_injection_combo = sus.contains(&"virtualalloc")
        && (sus.contains(&"writeprocessmemory") || sus.contains(&"createremotethread"));
    let anonymous_section = pe
        .sections
        .iter()
        .any(|s| s.name.is_empty() || s.name == "<invalid>");
    let tiny_imports = pe.imports.len() <= 2 && pe.max_section_entropy() > 7.0;

    vec![
        pe.sections.len() as f32,
        pe.max_section_entropy() as f32,
        mean_entropy as f32,
        b2f(pe.has_wx_section()),
        pe.imports.len() as f32,
        pe.import_dll_count as f32,
        sus.len() as f32,
        b2f(has_injection_combo),
        b2f(pe.is_dll),
        high_entropy_ratio as f32,
        b2f(anonymous_section),
        b2f(tiny_imports),
    ]
}

#[inline]
fn b2f(b: bool) -> f32 {
    if b {
        1.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_dim_agree() {
        assert_eq!(PE_FEATURES.len(), PE_DIM);
    }
}
