//! `aether-signatures` - the Static + Signature Engine.
//!
//! Two complementary primitives:
//!   * [`hashdb::HashDb`] - exact-match SHA-256 blacklist with a Bloom pre-filter
//!     so the overwhelmingly common "clean" case costs a few bit lookups.
//!   * [`yara::YaraEngine`] - compiled YARA-X rules for pattern detection
//!     (feature `yara`, on by default).

pub mod bloom;
pub mod fuzzy;
pub mod hashdb;
pub mod ndb;

#[cfg(feature = "yara")]
pub mod yara;

use aether_common::FileHashes;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Compute the cryptographic identity of a buffer (SHA-256 + MD5 + SHA-1 +
/// BLAKE3 + size).
///
/// BLAKE3 is included because it is dramatically faster and is what the cloud
/// reputation layer will key on; SHA-256/MD5/SHA-1 stay for interop with IOC
/// feeds (VirusTotal, MISP, abuse.ch) and the ClamAV hash signature database
/// (predominantly MD5-keyed), so we can match a sample by any of its digests.
pub fn hash_bytes(data: &[u8]) -> FileHashes {
    let sha256 = {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    };
    let md5 = {
        let mut h = Md5::new();
        h.update(data);
        hex::encode(h.finalize())
    };
    let sha1 = {
        let mut h = Sha1::new();
        h.update(data);
        hex::encode(h.finalize())
    };
    let blake3 = blake3::hash(data).to_hex().to_string();
    FileHashes {
        sha256,
        md5,
        sha1,
        blake3,
        size: data.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_known_vectors() {
        // SHA-256 of empty input is a well-known constant.
        let h = hash_bytes(b"");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.size, 0);
    }
}
