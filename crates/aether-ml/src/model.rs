//! Pure-Rust model inference (no native dependencies).
//!
//! Ships a standardized **logistic-regression** scorer whose parameters live in
//! a JSON file (`assets/models/pe.json`). This is deliberately simple and
//! dependency-free so the engine always has a working static-ML path; heavier
//! models (LightGBM/XGBoost/transformers) plug in through the optional `onnx`
//! backend without changing the calling code.

use aether_common::{Error, Result};
use serde::Deserialize;
use std::path::Path;

/// A trained logistic-regression model over a standardized feature vector.
///
/// Prediction: `p = sigmoid(bias + Σ wᵢ · (xᵢ − meanᵢ) / scaleᵢ)`.
#[derive(Debug, Clone, Deserialize)]
pub struct LogisticModel {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// Ordered feature names - must match the extractor's schema.
    pub features: Vec<String>,
    /// Per-feature standardization mean (centering).
    pub mean: Vec<f32>,
    /// Per-feature standardization scale (std-dev; must be non-zero).
    pub scale: Vec<f32>,
    /// Per-feature weights.
    pub weights: Vec<f32>,
    /// Intercept.
    pub bias: f32,
    /// Probability at/above which the sample is treated as a detection.
    pub threshold: f32,
}

impl LogisticModel {
    /// Load and validate a model from a JSON file.
    pub fn load(path: impl AsRef<Path>) -> Result<LogisticModel> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let model: LogisticModel =
            serde_json::from_str(&text).map_err(|e| Error::Config(format!("model parse: {e}")))?;
        model.validate()?;
        Ok(model)
    }

    /// Ensure all parameter vectors agree in length and scales are non-zero.
    pub fn validate(&self) -> Result<()> {
        let d = self.features.len();
        if self.mean.len() != d || self.scale.len() != d || self.weights.len() != d {
            return Err(Error::Config(format!(
                "model vectors disagree: features={d}, mean={}, scale={}, weights={}",
                self.mean.len(),
                self.scale.len(),
                self.weights.len()
            )));
        }
        if self.scale.contains(&0.0) {
            return Err(Error::Config("model scale contains zero".into()));
        }
        Ok(())
    }

    /// Check that this model's feature schema matches the extractor's.
    pub fn matches_schema(&self, expected: &[&str]) -> bool {
        self.features.len() == expected.len()
            && self.features.iter().zip(expected).all(|(a, b)| a == b)
    }

    /// Predict the malicious probability for a feature vector in `[0, 1]`.
    pub fn predict(&self, features: &[f32]) -> f32 {
        // zip stops at the shortest input, so length mismatches are tolerated
        // (validation should have caught them at load time anyway).
        let logit = self.bias
            + self
                .weights
                .iter()
                .zip(&self.mean)
                .zip(&self.scale)
                .zip(features)
                .map(|(((w, m), s), x)| w * (x - m) / s)
                .sum::<f32>();
        sigmoid(logit)
    }
}

#[inline]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy() -> LogisticModel {
        LogisticModel {
            version: 1,
            features: vec!["a".into(), "b".into()],
            mean: vec![0.0, 0.0],
            scale: vec![1.0, 1.0],
            weights: vec![2.0, -2.0],
            bias: 0.0,
            threshold: 0.5,
        }
    }

    #[test]
    fn sigmoid_is_centered() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(10.0) > 0.99);
        assert!(sigmoid(-10.0) < 0.01);
    }

    #[test]
    fn prediction_responds_to_weights() {
        let m = toy();
        // Positive on feature a -> high prob; positive on b -> low prob.
        assert!(m.predict(&[3.0, 0.0]) > 0.9);
        assert!(m.predict(&[0.0, 3.0]) < 0.1);
    }

    #[test]
    fn validation_catches_length_mismatch() {
        let mut m = toy();
        m.weights.push(1.0);
        assert!(m.validate().is_err());
    }

    #[test]
    fn validation_catches_zero_scale() {
        let mut m = toy();
        m.scale[0] = 0.0;
        assert!(m.validate().is_err());
    }
}
