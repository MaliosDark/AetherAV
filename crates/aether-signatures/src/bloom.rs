//! A small, dependency-free Bloom filter used as a negative pre-filter in front
//! of the exact hash database.
//!
//! With millions of signatures, the common case is "this file is clean". A
//! Bloom filter answers "definitely not present" in a handful of bit tests,
//! so we only touch the big hash map on a (rare) possible hit. False positives
//! are fine here - they just trigger an exact lookup that then says "no".

/// A classic bit-array Bloom filter with `k` hash probes.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    /// Number of addressable bits (`bits.len() * 64`).
    num_bits: usize,
    /// Number of hash probes per item.
    k: u32,
}

impl BloomFilter {
    /// Build a filter sized for `expected_items` at a target false-positive
    /// rate `fpr` (e.g. `0.001`). Both `m` (bits) and `k` (probes) are derived
    /// from the standard Bloom formulas.
    pub fn new(expected_items: usize, fpr: f64) -> BloomFilter {
        let n = expected_items.max(1) as f64;
        let fpr = fpr.clamp(1e-9, 0.5);
        // m = -n*ln(p) / (ln2)^2 ; k = (m/n)*ln2
        let m = (-(n * fpr.ln()) / (std::f64::consts::LN_2.powi(2))).ceil();
        let num_bits = (m as usize).max(64);
        let words = num_bits.div_ceil(64);
        let k = ((num_bits as f64 / n) * std::f64::consts::LN_2)
            .round()
            .max(1.0) as u32;
        BloomFilter {
            bits: vec![0u64; words],
            num_bits: words * 64,
            k,
        }
    }

    /// Two independent 64-bit hashes via FNV-1a over the item and a salt; the
    /// `k` probes are combined as `h1 + i*h2` (Kirsch-Mitzenmacher double hashing).
    fn hashes(&self, item: &[u8]) -> (u64, u64) {
        (fnv1a(item, 0xcbf29ce484222325), fnv1a(item, 0x100000001b3))
    }

    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = self.hashes(item);
        for i in 0..self.k as u64 {
            let bit = (h1.wrapping_add(i.wrapping_mul(h2))) as usize % self.num_bits;
            self.bits[bit / 64] |= 1u64 << (bit % 64);
        }
    }

    /// `false` => definitely not present. `true` => possibly present.
    pub fn might_contain(&self, item: &[u8]) -> bool {
        let (h1, h2) = self.hashes(item);
        for i in 0..self.k as u64 {
            let bit = (h1.wrapping_add(i.wrapping_mul(h2))) as usize % self.num_bits;
            if self.bits[bit / 64] & (1u64 << (bit % 64)) == 0 {
                return false;
            }
        }
        true
    }
}

/// FNV-1a 64-bit with a configurable basis, used as a cheap independent hash.
fn fnv1a(data: &[u8], basis: u64) -> u64 {
    let mut hash = basis;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_false_negatives() {
        let mut bf = BloomFilter::new(1000, 0.001);
        for i in 0..1000u32 {
            bf.insert(&i.to_le_bytes());
        }
        // Everything inserted must report present.
        for i in 0..1000u32 {
            assert!(bf.might_contain(&i.to_le_bytes()), "missing {i}");
        }
    }

    #[test]
    fn false_positive_rate_is_reasonable() {
        let mut bf = BloomFilter::new(10_000, 0.01);
        for i in 0..10_000u32 {
            bf.insert(&i.to_le_bytes());
        }
        // Probe 10k never-inserted items; expect well under 5% to collide.
        let mut fp = 0;
        for i in 100_000u32..110_000 {
            if bf.might_contain(&i.to_le_bytes()) {
                fp += 1;
            }
        }
        assert!(fp < 500, "too many false positives: {fp}");
    }
}
