//! TLSH fuzzy hashing - catches malware VARIANTS / polymorphic samples that
//! exact hashes miss.
//!
//! Exact hashes change completely if a single byte changes; TLSH produces a
//! similarity digest where related files land close together (low "distance").
//! We keep a database of known-malware TLSH digests; a file whose TLSH is within
//! a small distance of one is flagged as a variant of that family.
//!
//! Distance scale (TLSH): 0 = identical, <=30 very close (same family), <=80
//! likely related, large = unrelated. Built on the `tlsh2` crate.

use tlsh2::{Tlsh128_1, TlshBuilder128_1};

/// Compute the TLSH digest of a buffer. Returns None for inputs that are too
/// small or too uniform for a stable digest (TLSH needs ~50+ varied bytes).
pub fn tlsh(data: &[u8]) -> Option<String> {
    let mut b = TlshBuilder128_1::new();
    b.update(data);
    b.build()
        .map(|t| String::from_utf8_lossy(&t.hash()).into_owned())
}

/// A database of known-malware TLSH digests for nearest-neighbor variant lookup.
#[derive(Default)]
pub struct TlshDb {
    entries: Vec<(Tlsh128_1, String)>,
}

impl TlshDb {
    pub fn new() -> TlshDb {
        TlshDb {
            entries: Vec::new(),
        }
    }

    /// Load `TLSH_HASH<sep>threat_name` lines (sep = space / tab / comma).
    /// Lines that are blank, comments, or not a valid TLSH are skipped.
    pub fn from_text(text: &str) -> TlshDb {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Split into the hash and an optional threat label (separator may be
            // whitespace and/or a comma, with runs of either).
            let (hash, rest) = match line.find([' ', '\t', ',']) {
                Some(i) => (&line[..i], line[i..].trim_matches([' ', '\t', ','])),
                None => (line, ""),
            };
            if let Ok(t) = hash.parse::<Tlsh128_1>() {
                let threat = if rest.is_empty() { "Variant" } else { rest };
                entries.push((t, threat.to_string()));
            }
        }
        TlshDb { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Nearest known-malware digest within `max_distance`. Returns the threat
    /// name and the TLSH distance (lower = more similar).
    pub fn nearest(&self, data: &[u8], max_distance: i32) -> Option<(String, i32)> {
        if self.entries.is_empty() {
            return None;
        }
        let mut b = TlshBuilder128_1::new();
        b.update(data);
        let q = b.build()?;
        let mut best: Option<(&str, i32)> = None;
        for (t, name) in &self.entries {
            let d = q.diff(t, true);
            if d <= max_distance && best.is_none_or(|(_, bd)| d < bd) {
                best = Some((name.as_str(), d));
            }
        }
        best.map(|(n, d)| (n.to_string(), d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(seed: u32, n: usize) -> Vec<u8> {
        (0..n as u32)
            .map(|i| ((i.wrapping_mul(seed).wrapping_add(seed)) % 251) as u8)
            .collect()
    }

    #[test]
    fn computes_and_parses_roundtrip() {
        let h = tlsh(&buf(7, 2048)).expect("tlsh");
        assert!(h.starts_with("T1") && h.len() == 72);
        // The stored string must parse back (so a precomputed DB works).
        assert!(h.parse::<Tlsh128_1>().is_ok());
        // Too small -> no digest.
        assert!(tlsh(b"hi").is_none());
    }

    #[test]
    fn matches_variant_not_unrelated() {
        let base = buf(7, 4096);
        // A "variant": same file with a small fraction of bytes changed.
        let mut variant = base.clone();
        for i in 0..30 {
            variant[i * 80] = variant[i * 80].wrapping_add(13);
        }
        let unrelated = buf(131, 4096);

        // DB holds the base sample's TLSH.
        let db = TlshDb::from_text(&format!("{} Family.Test", tlsh(&base).unwrap()));
        assert_eq!(db.len(), 1);

        // The variant is found within a small distance...
        let (name, dist) = db.nearest(&variant, 120).expect("variant should match");
        assert_eq!(name, "Family.Test");
        // ...and the unrelated file is much farther than the variant.
        let unrelated_dist = db.nearest(&unrelated, i32::MAX).map(|(_, d)| d).unwrap();
        assert!(
            unrelated_dist > dist,
            "unrelated ({unrelated_dist}) should be farther than variant ({dist})"
        );
    }
}
