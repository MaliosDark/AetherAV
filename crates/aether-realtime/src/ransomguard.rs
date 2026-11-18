//! Ransomware shield with **rollback**.
//!
//! Top endpoint products survive ransomware by *recovering*, not just detecting.
//! This arms a protected directory by (1) snapshotting its files into a vault and
//! (2) planting **canary** files. It then watches for the encryption signature -
//! a canary being modified, or many files rewritten with high-entropy content.
//! Approved rollback uses the available snapshot once after detection.

use crate::FileWatcher;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
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
    snapshot: Vec<std::ffi::OsString>,
    /// Mass-modification trigger: this many files changed within the window.
    burst: usize,
    window: Duration,
}

const CANARY_BODY: &[u8] =
    b"AetherAV canary file. Do not modify. If you can read this it is intact.\n";
const MAX_SNAPSHOT_FILE: u64 = 25 * 1024 * 1024;

impl RansomGuard {
    /// Snapshot direct regular files and plant canaries without reusing an
    /// existing snapshot directory or overwriting existing canaries.
    pub fn arm(dir: impl AsRef<Path>, vault: impl AsRef<Path>) -> Result<RansomGuard, String> {
        let dir = fs::canonicalize(dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(vault.as_ref()).map_err(|e| e.to_string())?;
        let vault = fs::canonicalize(vault).map_err(|e| e.to_string())?;
        if dir.starts_with(&vault) {
            return Err("snapshot vault cannot contain the protected directory".into());
        }
        if fs::read_dir(&vault)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("snapshot vault must be empty".into());
        }
        let canaries: Vec<_> = ["__aether_canary_0001.txt", "zzz__aether_canary_9999.txt"]
            .into_iter()
            .map(|name| dir.join(name))
            .collect();
        if canaries
            .iter()
            .any(|path| fs::symlink_metadata(path).is_ok())
        {
            return Err(
                "preexisting canary path. Archive the previous snapshot and review the canaries"
                    .into(),
            );
        }

        let mut snapshot = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if meta.is_file() && meta.len() <= MAX_SNAPSHOT_FILE {
                fs::copy(entry.path(), vault.join(entry.file_name())).map_err(|e| e.to_string())?;
                snapshot.push(entry.file_name());
            }
        }
        for path in &canaries {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| file.write_all(CANARY_BODY))
                .map_err(|e| e.to_string())?;
        }

        tracing::info!(
            files = snapshot.len(),
            canaries = canaries.len(),
            "ransomguard armed"
        );
        Ok(RansomGuard {
            dir,
            vault,
            canaries,
            snapshot,
            burst: 8,
            window: Duration::from_secs(5),
        })
    }

    fn canary_intact(&self) -> bool {
        self.canaries.iter().all(|c| {
            fs::symlink_metadata(c).is_ok_and(|meta| meta.is_file())
                && read_bounded(c, CANARY_BODY.len() as u64).is_ok_and(|b| b == CANARY_BODY)
        })
    }

    /// Restore only missing or altered regular files from the snapshot.
    pub fn restore(&self) -> usize {
        self.snapshot
            .iter()
            .filter(|name| {
                let source = self.vault.join(name);
                let target = self.dir.join(name);
                let Ok(meta) = fs::symlink_metadata(&source) else {
                    return false;
                };
                if !meta.is_file() || meta.len() > MAX_SNAPSHOT_FILE {
                    return false;
                }
                let Ok(original) = read_bounded(&source, MAX_SNAPSHOT_FILE) else {
                    return false;
                };
                match fs::symlink_metadata(&target) {
                    Ok(meta) if !meta.is_file() => return false,
                    Ok(_)
                        if read_bounded(&target, MAX_SNAPSHOT_FILE)
                            .is_ok_and(|bytes| bytes == original) =>
                    {
                        return false
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return false,
                }
                let result = (|| -> std::io::Result<()> {
                    let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
                    tmp.write_all(&original)?;
                    tmp.as_file().set_permissions(meta.permissions())?;
                    tmp.as_file().sync_all()?;
                    tmp.persist(&target)?;
                    Ok(())
                })();
                if let Err(error) = &result {
                    tracing::warn!(path=%target.display(), %error, "snapshot recovery failed");
                }
                result.is_ok()
            })
            .count()
    }

    /// Watch with snapshot recovery enabled.
    pub fn run<F: FnMut(&Path)>(&self, on_event: F) -> Result<Incident, String> {
        self.watch(true, on_event)
    }

    /// Watch and optionally perform one approved rollback after detection.
    pub fn watch<F: FnMut(&Path)>(
        &self,
        restore_approved: bool,
        mut on_event: F,
    ) -> Result<Incident, String> {
        let watcher = FileWatcher::watch_with_removals(&self.dir, true)?;
        let mut recent: HashMap<PathBuf, Instant> = HashMap::new();

        loop {
            let Some(path) = watcher.next_changed(Duration::from_secs(3600)) else {
                continue;
            };
            if path.starts_with(&self.vault) {
                continue;
            }
            on_event(&path);

            // Strongest signal: a canary was touched.
            if !self.canary_intact() {
                let restored = if restore_approved { self.restore() } else { 0 };
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
                        if !fs::symlink_metadata(p).is_ok_and(|meta| meta.is_file()) {
                            return false;
                        }
                        read_bounded(p, MAX_SNAPSHOT_FILE)
                            .ok()
                            .map(|b| !b.is_empty() && entropy(&b) > 7.5)
                            .unwrap_or(false)
                    })
                    .count();
                if high * 2 >= recent.len() {
                    let restored = if restore_approved { self.restore() } else { 0 };
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

fn read_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    fs::File::open(path)?.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::other("snapshot sample exceeds file limit"));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_does_not_overwrite_symlink_targets() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let protected = dir.path().join("protected");
            fs::create_dir(&protected).unwrap();
            let target = protected.join("doc.txt");
            fs::write(&target, b"original").unwrap();
            let outside = dir.path().join("outside.txt");
            fs::write(&outside, b"outside").unwrap();
            let shield = RansomGuard::arm(&protected, dir.path().join("vault")).unwrap();
            assert_eq!(shield.restore(), 0);
            fs::remove_file(&target).unwrap();
            std::os::unix::fs::symlink(&outside, &target).unwrap();
            assert_eq!(shield.restore(), 0);
            assert_eq!(fs::read(outside).unwrap(), b"outside");
        }
    }

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
