//! Exact-match hash signature database with a Bloom pre-filter.
//!
//! Database file format (one signature per line, `#` comments allowed):
//! ```text
//! # <sha256-hex> <threat-name>
//! 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f Test.EICAR
//! ```

use crate::bloom::BloomFilter;
use aether_common::{Error, Result};
use std::collections::HashMap;
use std::path::Path;

/// In-memory hash blacklist keyed by lowercase SHA-256 hex.
pub struct HashDb {
    /// sha256-hex -> threat name.
    map: HashMap<String, String>,
    /// Negative pre-filter to skip the map on the common clean path.
    bloom: BloomFilter,
}

impl HashDb {
    /// An empty database that matches nothing.
    pub fn empty() -> HashDb {
        HashDb {
            map: HashMap::new(),
            bloom: BloomFilter::new(1, 0.001),
        }
    }

    /// Load a database from disk. Missing files yield an empty DB with a warning
    /// rather than an error, so a fresh install still scans (heuristics/YARA).
    pub fn load(path: impl AsRef<Path>) -> Result<HashDb> {
        let path = path.as_ref();
        if !path.exists() {
            tracing::warn!(path = %path.display(), "hash database not found; continuing without it");
            return Ok(HashDb::empty());
        }
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_text(&text)
    }

    /// Parse a database from its textual form.
    pub fn from_text(text: &str) -> Result<HashDb> {
        let mut entries: Vec<(String, String)> = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let hash = parts.next().unwrap().to_lowercase();
            let name = parts
                .next()
                .unwrap_or("Unknown.Signature")
                .trim()
                .to_string();
            // Accept MD5 (32), SHA-1 (40) or SHA-256 (64) hex digests so the DB
            // can ingest ClamAV (.hdb/.hsb) and abuse.ch md5/sha1/sha256 feeds.
            let valid_len = matches!(hash.len(), 32 | 40 | 64);
            if !valid_len || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Signature(format!(
                    "line {}: invalid hash {:?} (expected md5/sha1/sha256 hex)",
                    lineno + 1,
                    hash
                )));
            }
            entries.push((hash, name));
        }

        let mut bloom = BloomFilter::new(entries.len().max(1), 0.001);
        let mut map = HashMap::with_capacity(entries.len());
        for (hash, name) in entries {
            bloom.insert(hash.as_bytes());
            map.insert(hash, name);
        }
        Ok(HashDb { map, bloom })
    }

    /// Number of signatures loaded.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up a SHA-256 hex digest. Returns the threat name on a hit.
    ///
    /// The Bloom filter short-circuits the (vast majority) of clean lookups
    /// without touching the hash map.
    pub fn lookup(&self, sha256_hex: &str) -> Option<&str> {
        let key = sha256_hex.to_lowercase();
        if !self.bloom.might_contain(key.as_bytes()) {
            return None; // definitely clean
        }
        self.map.get(&key).map(String::as_str)
    }

    /// Look up a file by *any* of its digests - SHA-256 first, then MD5, then
    /// SHA-1 - so a sample matches whichever digest the signature was published
    /// under (abuse.ch sha256, ClamAV md5, legacy sha1 IOCs).
    pub fn lookup_any(&self, h: &aether_common::FileHashes) -> Option<&str> {
        self.lookup(&h.sha256)
            .or_else(|| self.lookup(&h.md5))
            .or_else(|| self.lookup(&h.sha1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn parses_and_matches() {
        let db = HashDb::from_text(&format!("# header\n{EICAR_SHA256} Test.EICAR\n")).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db.lookup(EICAR_SHA256), Some("Test.EICAR"));
        // Uppercase input still matches.
        assert_eq!(db.lookup(&EICAR_SHA256.to_uppercase()), Some("Test.EICAR"));
    }

    #[test]
    fn unknown_hash_is_clean() {
        let db = HashDb::from_text(&format!("{EICAR_SHA256} Test.EICAR\n")).unwrap();
        let other = "0".repeat(64);
        assert_eq!(db.lookup(&other), None);
    }

    #[test]
    fn rejects_malformed_hash() {
        assert!(matches!(
            HashDb::from_text("deadbeef Short.Hash\n"),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn missing_name_defaults() {
        let db = HashDb::from_text(&format!("{EICAR_SHA256}\n")).unwrap();
        assert_eq!(db.lookup(EICAR_SHA256), Some("Unknown.Signature"));
    }
}
