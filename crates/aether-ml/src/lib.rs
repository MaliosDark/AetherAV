//! `aether-ml` - the static machine-learning detection layer.
//!
//! Turns parser features into a malicious-probability and an explainable
//! [`Verdict`]. The default path is a dependency-free logistic model; the
//! optional `onnx` feature swaps in ONNX Runtime for gradient-boosted or
//! transformer models exported from the Python training pipeline.

pub mod features;
pub mod model;

use aether_common::{EngineKind, Result, ThreatLevel, Verdict};
use aether_parsers::pe::PeInfo;
use model::LogisticModel;
use std::path::Path;

/// A loaded static-ML engine for PE files.
pub struct MlEngine {
    model: LogisticModel,
}

impl MlEngine {
    /// Load the PE model from disk and verify its schema matches the extractor.
    pub fn load(path: impl AsRef<Path>) -> Result<MlEngine> {
        let model = LogisticModel::load(path)?;
        if !model.matches_schema(features::PE_FEATURES) {
            tracing::warn!(
                "ML model feature schema does not match extractor; predictions may be invalid"
            );
        }
        tracing::info!(
            version = model.version,
            dim = model.features.len(),
            "static ML model loaded"
        );
        Ok(MlEngine { model })
    }

    /// Wrap an already-constructed model (used in tests / embedded defaults).
    pub fn from_model(model: LogisticModel) -> MlEngine {
        MlEngine { model }
    }

    /// The decision threshold the model was configured with.
    pub fn threshold(&self) -> f32 {
        self.model.threshold
    }

    /// Score a parsed PE. Returns a verdict only when the probability reaches
    /// the model threshold; otherwise `None` (the file looks benign to the model).
    pub fn classify_pe(&self, pe: &PeInfo) -> Option<Verdict> {
        let feats = features::pe_features(pe);
        let prob = self.model.predict(&feats);
        if prob < self.model.threshold {
            return None;
        }

        // High confidence escalates to Malicious; a soft hit stays Suspicious.
        let level = if prob >= 0.9 {
            ThreatLevel::Malicious
        } else {
            ThreatLevel::Suspicious
        };

        Some(Verdict {
            engine: EngineKind::Ml,
            level,
            signature: "pe.ml.logistic".to_string(),
            score: prob,
            mitre: Vec::new(),
            detail: Some(format!(
                "static-ML malicious probability {:.2} (threshold {:.2})",
                prob, self.model.threshold
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_parsers::section::SectionInfo;

    // Build a synthetic "packed" PE-like structure to exercise the engine
    // without needing a real binary on disk.
    fn packed_pe() -> PeInfo {
        let high = SectionInfo {
            name: ".text".into(),
            virtual_size: 4096,
            raw_size: 4096,
            entropy: 7.9,
            band: aether_parsers::entropy::EntropyBand::VeryHigh,
            writable: true,
            executable: true,
        };
        PeInfo {
            arch: aether_parsers::pe::Arch::X64,
            is_dll: false,
            entry: 0x1000,
            sections: vec![high],
            imports: vec![],
            import_dll_count: 0,
            signed: false,
            signer: None,
            imphash: None,
            pe_timestamp: 0,
        }
    }

    fn model() -> LogisticModel {
        // Mirrors assets/models/pe.json closely enough for a behavior test.
        LogisticModel {
            version: 1,
            features: features::PE_FEATURES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            mean: vec![
                4.0, 6.3, 6.0, 0.05, 80.0, 5.0, 0.5, 0.05, 0.3, 0.1, 0.02, 0.02,
            ],
            scale: vec![3.0, 0.8, 0.8, 1.0, 60.0, 4.0, 1.5, 1.0, 1.0, 0.3, 1.0, 1.0],
            weights: vec![
                0.1, 1.6, 0.6, 1.2, -0.4, -0.1, 0.5, 1.3, -0.2, 1.0, 0.6, 0.9,
            ],
            bias: -1.8,
            threshold: 0.6,
        }
    }

    #[test]
    fn flags_packed_pe() {
        let engine = MlEngine::from_model(model());
        let verdict = engine.classify_pe(&packed_pe());
        assert!(verdict.is_some(), "packed PE should score above threshold");
        assert_eq!(verdict.unwrap().engine, EngineKind::Ml);
    }

    #[test]
    fn schema_matches_extractor() {
        assert!(model().matches_schema(features::PE_FEATURES));
    }
}
