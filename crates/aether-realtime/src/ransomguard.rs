//! Ransomware shield with **rollback**.
//!
//! Top endpoint products survive ransomware by *recovering*, not just detecting.
//! This arms a protected directory by (1) snapshotting its files into a vault and
//! (2) planting **canary** files. It then watches for the encryption signature -
//! a canary being modified, or many files rewritten with high-entropy
//! (encrypted) content in a short window - and on trigger **restores every file
//! from the snapshot**, undoing the damage.

use crate::FileWatcher;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Shannon entropy (bits/byte) of a buffer; ~8.0 means encrypted/compressed.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub reason: String,
    pub modified: usize,
    pub restored: usize,
}

pub struct RansomGuard {
    dir: PathBuf,
    vault: PathBuf,
    canaries: Vec<PathBuf>,
    /// Mass-modification trigger: this many files changed within the window.
    burst: usize,
    window: Duration,
}

const CANARY_BODY: &[u8] =
    b"AetherAV canary file. Do not modify. If you can read this it is intact.\n";
const MAX_SNAPSHOT_FILE: u64 = 25 * 1024 * 1024;

impl RansomGuard {
    /// Snapshot `dir` into `vault` and plant canaries. Existing vault contents
    /// for this dir are refreshed.
    pub fn arm(dir: impl AsRef<Path>, vault: impl AsRef<Path>) -> Result<RansomGuard, String> {
        let dir = dir.as_ref().to_path_buf();
        let vault = vault.as_ref().to_path_buf();
        fs::create_dir_all(&vault).map_err(|e| e.to_string())?;

        // Snapshot every regular file (bounded) under dir into vault/<name>.
        let mut count = 0usize;
        for entry in fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(meta) = p.metadata() {
                    if meta.len() <= MAX_SNAPSHOT_FILE {
                        if let Some(name) = p.file_name() {
                            let _ = fs::copy(&p, vault.join(name));
                            count += 1;
                        }
                    }
                }
            }
        }

        // Plant canaries (named to sort first/last so attackers hit them early).
        let mut canaries = Vec::new();
        for name in ["__aether_canary_0001.txt", "zzz__aether_canary_9999.txt"] {
            let cp = dir.join(name);
            if fs::write(&cp, CANARY_BODY).is_ok() {
                let _ = fs::copy(&cp, vault.join(name));
                canaries.push(cp);
            }
        }

        tracing::info!(
            files = count,
            canaries = canaries.len(),
            "ransomguard armed"
        );
        Ok(RansomGuard {
            dir,
            vault,
            canaries,
            burst: 8,
            window: Duration::from_secs(5),
        })
    }

    fn canary_intact(&self) -> bool {
        self.canaries
            .iter()
            .all(|c| fs::read(c).map(|b| b == CANARY_BODY).unwrap_or(false))
    }

    /// Keep restoring until the attacker goes quiet (no change for one window) -
    /// a single restore loses the race against a still-running encryptor.
    /// Returns the number of files in the snapshot (what protection covers).
    fn mitigate(&self, watcher: &FileWatcher) -> usize {
        let restored = self.restore();
        // Drain further tampering, re-restoring, until quiet for one window.
        while watcher.next_changed(self.window).is_some() {
            self.restore();
        }
        restored
    }

    /// Restore every snapshotted file back into the protected directory.
    pub fn restore(&self) -> usize {
        let mut n = 0;
        if let Ok(rd) = fs::read_dir(&self.vault) {
            for e in rd.flatten() {
                if e.path().is_file() {
                    if let Some(name) = e.path().file_name() {
                        if fs::copy(e.path(), self.dir.join(name)).is_ok() {
                            n += 1;
                        }
                    }
                }
            }
        }
        n
    }

    /// Watch until ransomware behaviour is detected, then roll back. Returns the
    /// incident. `on_event` is called for each change (for live UIs/logging).
    pub fn run<F: FnMut(&Path)>(&self, mut on_event: F) -> Result<Incident, String> {
        let watcher = FileWatcher::watch(&self.dir)?;
        let mut recent: HashMap<PathBuf, Instant> = HashMap::new();

        loop {
            let Some(path) = watcher.next_changed(Duration::from_secs(3600)) else {
                continue;
            };
            on_event(&path);

            // Strongest signal: a canary was touched.
            if !self.canary_intact() {
                let restored = self.mitigate(&watcher);
                return Ok(Incident {
                    reason: "canary file modified - ransomware behaviour".into(),
                    modified: recent.len() + 1,
                    restored,
                });
            }

            // Track recent modifications inside the sliding window.
            let now = Instant::now();
            recent.retain(|_, t| now.duration_since(*t) < self.window);
            recent.insert(path.clone(), now);

            if recent.len() >= self.burst {
                // Mass change - confirm it's encryption by sampling entropy.
                let high = recent
                    .keys()
                    .filter(|p| {
                        fs::read(p)
                            .ok()
                            .map(|b| !b.is_empty() && entropy(&b) > 7.5)
                            .unwrap_or(false)
                    })
                    .count();
                if high * 2 >= recent.len() {
                    let restored = self.mitigate(&watcher);
                    return Ok(Incident {
                        reason: format!(
                            "{} files rewritten with high-entropy data in {:?}",
                            recent.len(),
                            self.window
                        ),
                        modified: recent.len(),
                        restored,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_distinguishes_text_from_random() {
        assert!(entropy(b"aaaaaaaaaaaaaaaaaaaaaaaa") < 1.0);
        let random: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(entropy(&random) > 7.5);
    }

    #[test]
    fn arm_snapshots_and_restores() {
        let dir = std::env::temp_dir().join(format!("rg_test_{}", std::process::id()));
        let vault = dir.join(".vault");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("doc.txt"), b"important original content").unwrap();

        let g = RansomGuard::arm(&dir, &vault).unwrap();
        // Simulate encryption of the document.
        fs::write(dir.join("doc.txt"), b"\x01\x02\x03encrypted\xff\xfe").unwrap();
        assert_eq!(
            fs::read(dir.join("doc.txt")).unwrap(),
            b"\x01\x02\x03encrypted\xff\xfe"
        );
        // Roll back.
        let n = g.restore();
        assert!(n >= 1);
        assert_eq!(
            fs::read(dir.join("doc.txt")).unwrap(),
            b"important original content"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
