//! Shannon entropy - the workhorse signal for detecting packed/encrypted data.
//!
//! Compiled code typically sits around 6.0-6.8 bits/byte; packed or encrypted
//! payloads push toward the 8.0 ceiling. The heuristic engine compares
//! per-section entropy against these bands.

/// Shannon entropy of `data` in bits per byte, in the range `[0.0, 8.0]`.
///
/// Returns `0.0` for empty input (no information).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Classify an entropy value into a coarse band for explainable verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyBand {
    /// Structured / low-information data (text, tables).
    Low,
    /// Typical native code.
    Normal,
    /// Compressed or obfuscated.
    High,
    /// Almost certainly encrypted or packed.
    VeryHigh,
}

impl EntropyBand {
    pub fn classify(entropy: f64) -> EntropyBand {
        match entropy {
            e if e < 5.0 => EntropyBand::Low,
            e if e < 6.8 => EntropyBand::Normal,
            e if e < 7.5 => EntropyBand::High,
            _ => EntropyBand::VeryHigh,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn single_byte_value_is_zero_entropy() {
        // All identical bytes carry no information.
        assert_eq!(shannon(&[0x41; 4096]), 0.0);
    }

    #[test]
    fn uniform_distribution_is_max_entropy() {
        // Every byte value exactly once -> 8 bits/byte.
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon(&data);
        assert!((e - 8.0).abs() < 1e-9, "expected ~8.0, got {e}");
        assert_eq!(EntropyBand::classify(e), EntropyBand::VeryHigh);
    }

    #[test]
    fn bands_make_sense() {
        assert_eq!(EntropyBand::classify(2.0), EntropyBand::Low);
        assert_eq!(EntropyBand::classify(6.5), EntropyBand::Normal);
        assert_eq!(EntropyBand::classify(7.2), EntropyBand::High);
        assert_eq!(EntropyBand::classify(7.9), EntropyBand::VeryHigh);
    }
}
