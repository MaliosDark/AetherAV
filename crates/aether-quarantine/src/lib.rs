//! `aether-quarantine` - encrypted vault, remediation and forensics.
//!
//! When an engine convicts a file, the responder must neutralize it without
//! destroying evidence. This vault:
//!   * encrypts the sample with ChaCha20-Poly1305 (AEAD) so it can never
//!     execute or be read in place, yet stays recoverable for analysis;
//!   * records a tamper-evident metadata index (hash, origin, threat, time);
//!   * supports restore, deletion, an incident timeline and IOC export.
//!
//! Layout under `<root>/`:
//! ```text
//!   key            32-byte vault master key (generated on first open)
//!   index.json     metadata for every quarantined item
//!   blobs/<id>     nonce(12) || ciphertext for each item
//! ```

use aether_common::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata for one quarantined artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Vault id = SHA-256 of the original content (also de-dupes re-quarantine).
    pub id: String,
    /// Where the file came from.
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    /// Threat name / signature that convicted it.
    pub threat: String,
    /// Unix seconds when it was quarantined.
    pub quarantined_at: u64,
    /// Hex nonce used for this item's encryption.
    nonce: String,
}

/// An encrypted, on-disk quarantine vault.
pub struct Vault {
    root: PathBuf,
    key: [u8; 32],
    index: HashMap<String, QuarantineEntry>,
}

impl Vault {
    /// Open (creating if needed) a vault rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Vault> {
        let root = root.as_ref().to_path_buf();
        let blobs = root.join("blobs");
        std::fs::create_dir_all(&blobs).map_err(|source| Error::Io {
            path: blobs.clone(),
            source,
        })?;

        let key = Self::load_or_create_key(&root)?;
        let index = Self::load_index(&root)?;
        Ok(Vault { root, key, index })
    }

    fn key_path(root: &Path) -> PathBuf {
        root.join("key")
    }
    fn index_path(root: &Path) -> PathBuf {
        root.join("index.json")
    }
    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join("blobs").join(id)
    }

    fn load_or_create_key(root: &Path) -> Result<[u8; 32]> {
        let path = Self::key_path(root);
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            if bytes.len() != 32 {
                return Err(Error::Quarantine("vault key is corrupt".into()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        } else {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).map_err(|e| Error::Quarantine(format!("rng: {e}")))?;
            std::fs::write(&path, key).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            Ok(key)
        }
    }

    fn load_index(root: &Path) -> Result<HashMap<String, QuarantineEntry>> {
        let path = Self::index_path(root);
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|e| Error::Quarantine(format!("index parse: {e}")))
    }

    fn save_index(&self) -> Result<()> {
        let path = Self::index_path(&self.root);
        let text = serde_json::to_string_pretty(&self.index)
            .map_err(|e| Error::Quarantine(e.to_string()))?;
        std::fs::write(&path, text).map_err(|source| Error::Io { path, source })
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new_from_slice(&self.key).expect("32-byte key")
    }

    /// Quarantine raw bytes that originated at `original_path`.
    pub fn quarantine_bytes(
        &mut self,
        original_path: &str,
        data: &[u8],
        threat: &str,
    ) -> Result<QuarantineEntry> {
        let sha256 = {
            let mut h = Sha256::new();
            h.update(data);
            hex::encode(h.finalize())
        };

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| Error::Quarantine(format!("rng: {e}")))?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, data)
            .map_err(|e| Error::Quarantine(format!("encrypt: {e}")))?;

        // blob = nonce || ciphertext
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&ciphertext);
        let id = sha256.clone();
        let blob_path = self.blob_path(&id);
        std::fs::write(&blob_path, &blob).map_err(|source| Error::Io {
            path: blob_path,
            source,
        })?;

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: original_path.to_string(),
            sha256,
            size: data.len() as u64,
            threat: threat.to_string(),
            quarantined_at: now_secs(),
            nonce: hex::encode(nonce_bytes),
        };
        self.index.insert(id, entry.clone());
        self.save_index()?;
        tracing::info!(threat, path = original_path, "file quarantined");
        Ok(entry)
    }

    /// Read a file, secure it in the vault, then remove the original.
    pub fn quarantine_file(&mut self, path: &Path, threat: &str) -> Result<QuarantineEntry> {
        let data = std::fs::read(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let entry = self.quarantine_bytes(&path.to_string_lossy(), &data, threat)?;
        std::fs::remove_file(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(entry)
    }

    /// Decrypt a quarantined item and return its original bytes.
    pub fn recover(&self, id: &str) -> Result<Vec<u8>> {
        let entry = self
            .index
            .get(id)
            .ok_or_else(|| Error::Quarantine(format!("no such item: {id}")))?;
        let blob = std::fs::read(self.blob_path(id)).map_err(|source| Error::Io {
            path: self.blob_path(id),
            source,
        })?;
        if blob.len() < 12 {
            return Err(Error::Quarantine("blob too small".into()));
        }
        let (nonce_slice, ciphertext) = blob.split_at(12);
        debug_assert_eq!(hex::encode(nonce_slice), entry.nonce);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(nonce_slice);
        let nonce = Nonce::from(nonce_bytes);
        self.cipher()
            .decrypt(&nonce, ciphertext)
            .map_err(|e| Error::Quarantine(format!("decrypt/verify failed: {e}")))
    }

    /// Restore a quarantined item to `dest` (decrypts and writes it out).
    pub fn restore(&self, id: &str, dest: &Path) -> Result<()> {
        let data = self.recover(id)?;
        std::fs::write(dest, data).map_err(|source| Error::Io {
            path: dest.to_path_buf(),
            source,
        })
    }

    /// Permanently delete a quarantined item (blob + index entry).
    pub fn remove(&mut self, id: &str) -> Result<()> {
        if self.index.remove(id).is_none() {
            return Err(Error::Quarantine(format!("no such item: {id}")));
        }
        let _ = std::fs::remove_file(self.blob_path(id));
        self.save_index()
    }

    /// All entries (unordered).
    pub fn list(&self) -> Vec<&QuarantineEntry> {
        self.index.values().collect()
    }

    /// Incident timeline: entries sorted by quarantine time (oldest first).
    pub fn timeline(&self) -> Vec<&QuarantineEntry> {
        let mut v: Vec<&QuarantineEntry> = self.index.values().collect();
        v.sort_by_key(|e| e.quarantined_at);
        v
    }

    /// Export indicators of compromise as CSV (sha256,threat,path,time).
    pub fn export_iocs(&self) -> String {
        let mut out = String::from("sha256,threat,original_path,quarantined_at\n");
        for e in self.timeline() {
            out.push_str(&format!(
                "{},{},{},{}\n",
                e.sha256, e.threat, e.original_path, e.quarantined_at
            ));
        }
        out
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_recover_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path()).unwrap();
        let payload = b"X5O!P%@AP eicar-like payload";
        let entry = vault
            .quarantine_bytes("/tmp/evil.exe", payload, "Test.EICAR")
            .unwrap();

        // The on-disk blob must NOT contain the plaintext.
        let blob = std::fs::read(dir.path().join("blobs").join(&entry.id)).unwrap();
        assert!(!blob.windows(payload.len()).any(|w| w == payload));

        // …but it must decrypt back exactly.
        let recovered = vault.recover(&entry.id).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let mut vault = Vault::open(dir.path()).unwrap();
            vault
                .quarantine_bytes("/tmp/a", b"data", "Mal.A")
                .unwrap()
                .id
        };
        // Reopen: key + index reload, recovery still works.
        let vault = Vault::open(dir.path()).unwrap();
        assert_eq!(vault.list().len(), 1);
        assert_eq!(vault.recover(&id).unwrap(), b"data");
    }

    #[test]
    fn quarantine_file_removes_original() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("malware.bin");
        std::fs::write(&victim, b"bad bytes").unwrap();
        let mut vault = Vault::open(dir.path().join("vault")).unwrap();
        vault.quarantine_file(&victim, "Mal.B").unwrap();
        assert!(!victim.exists(), "original should be removed");
    }

    #[test]
    fn restore_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path()).unwrap();
        let entry = vault.quarantine_bytes("/tmp/c", b"hello", "Mal.C").unwrap();
        let dest = dir.path().join("restored");
        vault.restore(&entry.id, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");

        vault.remove(&entry.id).unwrap();
        assert!(vault.recover(&entry.id).is_err());
    }

    #[test]
    fn ioc_export_has_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(dir.path()).unwrap();
        vault.quarantine_bytes("/tmp/d", b"x", "Mal.D").unwrap();
        let csv = vault.export_iocs();
        assert!(csv.contains("Mal.D"));
        assert!(csv.lines().count() >= 2);
    }
}
