//! The per-host behavioral baseline.
//!
//! A compact statistical profile of "normal" for one host: which programs run,
//! which parent->child spawn pairs occur, where the host talks on the network,
//! how long command lines tend to be, and which autostart locations exist. It
//! is updated online from event traces and serialized to JSON so learning
//! survives restarts (`load` -> keep `update`-ing -> `save`).

use crate::stats::RunningStats;
use aether_behavior::event::{basename, Action, Event};
use aether_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Learned profile of normal behavior for a host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// image basename -> times spawned.
    pub process_freq: HashMap<String, u64>,
    /// "parent_image>child_image" -> times observed.
    pub spawn_pairs: HashMap<String, u64>,
    /// remote endpoint -> times connected.
    pub net_dests: HashMap<String, u64>,
    /// Known autostart registry keys (lowercased).
    pub autostart_keys: HashSet<String>,
    /// Distribution of spawn command-line lengths.
    pub cmdline_len: RunningStats,
    pub total_spawns: u64,
    pub total_nets: u64,
}

/// `true` if a registry key is an autostart (persistence) location.
pub fn is_autostart(key: &str) -> bool {
    let k = key.to_lowercase();
    k.contains("currentversion\\run")
        || k.contains("currentversion\\runonce")
        || k.contains("\\userinit")
        || k.contains("\\winlogon\\shell")
}

/// Build a pid -> image-basename map from the spawn events in a trace.
fn images_of(events: &[Event]) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    for ev in events {
        if let Action::ProcessSpawn {
            child_pid, image, ..
        } = &ev.action
        {
            m.insert(*child_pid, basename(image));
        }
    }
    m
}

impl Baseline {
    /// Fold an event trace into the baseline (online update).
    pub fn update(&mut self, events: &[Event]) {
        let images = images_of(events);
        for ev in events {
            match &ev.action {
                Action::ProcessSpawn { image, cmdline, .. } => {
                    let child = basename(image);
                    *self.process_freq.entry(child.clone()).or_default() += 1;
                    let parent = images
                        .get(&ev.pid)
                        .cloned()
                        .unwrap_or_else(|| "?".to_string());
                    *self
                        .spawn_pairs
                        .entry(format!("{parent}>{child}"))
                        .or_default() += 1;
                    self.cmdline_len.observe(cmdline.len() as f64);
                    self.total_spawns += 1;
                }
                Action::NetConnect { remote, .. } => {
                    *self.net_dests.entry(remote.clone()).or_default() += 1;
                    self.total_nets += 1;
                }
                Action::RegistrySet { key, .. } if is_autostart(key) => {
                    self.autostart_keys.insert(key.to_lowercase());
                }
                _ => {}
            }
        }
    }

    /// Whether the baseline has seen enough spawns to score without cold-start
    /// false positives.
    pub fn is_trained(&self) -> bool {
        self.total_spawns >= 15
    }

    /// Relative frequency of a process image (0.0 if never seen).
    pub fn process_rarity(&self, image: &str) -> f64 {
        if self.total_spawns == 0 {
            return 1.0;
        }
        let c = self.process_freq.get(image).copied().unwrap_or(0);
        c as f64 / self.total_spawns as f64
    }

    /// Load a baseline from JSON, or start fresh if the file does not exist.
    pub fn load_or_new(path: impl AsRef<Path>) -> Result<Baseline> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Baseline::default());
        }
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|e| Error::Config(format!("baseline parse: {e}")))
    }

    /// Persist the baseline to JSON.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let text = serde_json::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(path, text).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_and_persists() {
        let json = r#"[
            {"pid":1,"action":"process_spawn","child_pid":2,"image":"explorer.exe"},
            {"pid":2,"action":"process_spawn","child_pid":3,"image":"chrome.exe","cmdline":"--type=renderer"},
            {"pid":3,"action":"net_connect","remote":"142.250.1.1","port":443}
        ]"#;
        let events = Event::from_json(json).unwrap();
        let mut b = Baseline::default();
        b.update(&events);
        assert_eq!(b.process_freq.get("chrome.exe"), Some(&1));
        assert!(b.spawn_pairs.contains_key("explorer.exe>chrome.exe"));
        assert_eq!(b.net_dests.get("142.250.1.1"), Some(&1));

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("baseline.json");
        b.save(&p).unwrap();
        let loaded = Baseline::load_or_new(&p).unwrap();
        assert_eq!(loaded.total_spawns, b.total_spawns);
        assert_eq!(loaded.process_freq.get("chrome.exe"), Some(&1));
    }

    #[test]
    fn autostart_classification() {
        assert!(is_autostart(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X"
        ));
        assert!(!is_autostart("HKLM\\Software\\Vendor\\Settings"));
    }
}
