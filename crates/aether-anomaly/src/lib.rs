//! `aether-anomaly` - per-host behavioral baseline + anomaly detection.
//!
//! Complements the signature/heuristic/ML/behavioral layers by flagging the
//! *unknown*: activity that deviates from what this host normally does. It
//! learns a [`Baseline`] online from benign telemetry, then scores new event
//! traces for novelty (never-seen programs, lineages, network destinations,
//! autostart locations) and statistical outliers (command-line length).
//!
//! Anomalies are advisory by nature, so verdicts are `Suspicious`: they surface
//! leads a signature can't, for correlation with the other engines.

pub mod model;
pub mod stats;

pub use model::Baseline;

use aether_behavior::event::{basename, Action, Event};
use aether_common::{EngineKind, ThreatLevel, Verdict};
use std::collections::{HashMap, HashSet};

/// Z-score above which a command-line length counts as an outlier.
const CMDLINE_Z_THRESHOLD: f64 = 3.5;
/// Process relative-frequency below which (but non-zero) it is "rare".
const RARE_THRESHOLD: f64 = 0.01;

/// Holds a learned baseline and scores traces against it.
#[derive(Default)]
pub struct AnomalyEngine {
    baseline: Baseline,
}

impl AnomalyEngine {
    pub fn new(baseline: Baseline) -> AnomalyEngine {
        AnomalyEngine { baseline }
    }

    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Online-learn from a benign (or simply observed) trace.
    pub fn learn(&mut self, events: &[Event]) {
        self.baseline.update(events);
    }

    /// Score a trace for anomalies relative to the learned baseline.
    ///
    /// Returns nothing until the baseline is trained, so a cold start never
    /// floods the analyst with false positives.
    pub fn score(&self, events: &[Event]) -> Vec<Verdict> {
        if !self.baseline.is_trained() {
            tracing::debug!(
                spawns = self.baseline.total_spawns,
                "baseline not yet trained"
            );
            return Vec::new();
        }

        let images = images_of(events);
        let mut seen = HashSet::new();
        let mut verdicts = Vec::new();

        for ev in events {
            match &ev.action {
                Action::ProcessSpawn { image, cmdline, .. } => {
                    let child = basename(image);
                    let parent = images
                        .get(&ev.pid)
                        .cloned()
                        .unwrap_or_else(|| "?".to_string());

                    // Novel / rare program for this host.
                    let rarity = self.baseline.process_rarity(&child);
                    if rarity == 0.0 && seen.insert(format!("proc:{child}")) {
                        verdicts.push(anomaly(
                            "anomaly.novel_process",
                            0.75,
                            format!("never-before-seen program on this host: {child}"),
                        ));
                    } else if rarity < RARE_THRESHOLD && seen.insert(format!("proc:{child}")) {
                        verdicts.push(anomaly(
                            "anomaly.rare_process",
                            0.5,
                            format!("rarely-seen program: {child} (freq {:.4})", rarity),
                        ));
                    }

                    // Novel parent->child lineage (e.g. office spawning a shell).
                    let pair = format!("{parent}>{child}");
                    if !self.baseline.spawn_pairs.contains_key(&pair)
                        && seen.insert(format!("pair:{pair}"))
                    {
                        verdicts.push(anomaly(
                            "anomaly.novel_lineage",
                            0.7,
                            format!("unusual process lineage: {pair}"),
                        ));
                    }

                    // Command-line length outlier (encoded blobs are very long).
                    let z = self.baseline.cmdline_len.zscore(cmdline.len() as f64);
                    if z > CMDLINE_Z_THRESHOLD && seen.insert(format!("cmd:{}", ev.pid)) {
                        verdicts.push(anomaly(
                            "anomaly.cmdline_outlier",
                            0.6,
                            format!("command-line length anomaly (z={:.1}) for {child}", z),
                        ));
                    }
                }
                Action::NetConnect { remote, port } => {
                    if !self.baseline.net_dests.contains_key(remote)
                        && seen.insert(format!("net:{remote}"))
                    {
                        verdicts.push(anomaly(
                            "anomaly.novel_network",
                            0.65,
                            format!("connection to never-seen destination {remote}:{port}"),
                        ));
                    }
                }
                Action::RegistrySet { key, .. }
                    if model::is_autostart(key)
                        && !self.baseline.autostart_keys.contains(&key.to_lowercase())
                        && seen.insert(format!("auto:{key}")) =>
                {
                    verdicts.push(anomaly(
                        "anomaly.new_autostart",
                        0.7,
                        format!("new autostart/persistence location: {key}"),
                    ));
                }
                _ => {}
            }
        }
        verdicts
    }
}

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

fn anomaly(signature: &str, score: f32, detail: String) -> Verdict {
    Verdict {
        engine: EngineKind::Anomaly,
        level: ThreatLevel::Suspicious,
        signature: signature.to_string(),
        score,
        mitre: Vec::new(),
        detail: Some(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A benign baseline: explorer launches the usual apps many times, talking
    /// only to an internal host.
    fn trained_engine() -> AnomalyEngine {
        let mut engine = AnomalyEngine::default();
        let mut trace = String::from("[");
        for i in 0..20 {
            let pid = 100 + i;
            trace.push_str(&format!(
                r#"{{"pid":1,"action":"process_spawn","child_pid":{pid},"image":"explorer.exe"}},
                   {{"pid":{pid},"action":"process_spawn","child_pid":{},"image":"chrome.exe","cmdline":"--tab"}},
                   {{"pid":{pid},"action":"net_connect","remote":"10.0.0.5","port":443}},"#,
                pid + 1000
            ));
        }
        trace.push_str(
            r#"{"pid":1,"action":"process_spawn","child_pid":99,"image":"explorer.exe"}]"#,
        );
        let events = Event::from_json(&trace).unwrap();
        engine.learn(&events);
        assert!(engine.baseline().is_trained());
        engine
    }

    #[test]
    fn flags_novel_process_and_network_and_autostart() {
        let engine = trained_engine();
        let malicious = r#"[
            {"pid":50,"action":"process_spawn","child_pid":60,"image":"explorer.exe"},
            {"pid":60,"action":"process_spawn","child_pid":61,"image":"powershell.exe","cmdline":"-enc AAAA"},
            {"pid":61,"action":"net_connect","remote":"185.220.101.42","port":443},
            {"pid":61,"action":"registry_set","key":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Eviltask","value":"x"}
        ]"#;
        let events = Event::from_json(malicious).unwrap();
        let v = engine.score(&events);
        let sigs: Vec<&str> = v.iter().map(|v| v.signature.as_str()).collect();
        assert!(sigs.contains(&"anomaly.novel_process"), "got {sigs:?}");
        assert!(sigs.contains(&"anomaly.novel_network"), "got {sigs:?}");
        assert!(sigs.contains(&"anomaly.new_autostart"), "got {sigs:?}");
        assert!(v.iter().all(|v| v.engine == EngineKind::Anomaly));
    }

    #[test]
    fn known_good_activity_is_quiet() {
        let engine = trained_engine();
        let benign = r#"[
            {"pid":7,"action":"process_spawn","child_pid":8,"image":"explorer.exe"},
            {"pid":8,"action":"process_spawn","child_pid":9,"image":"chrome.exe","cmdline":"--tab"},
            {"pid":9,"action":"net_connect","remote":"10.0.0.5","port":443}
        ]"#;
        let events = Event::from_json(benign).unwrap();
        assert!(engine.score(&events).is_empty());
    }

    #[test]
    fn cold_start_does_not_flag() {
        let engine = AnomalyEngine::default();
        let events = Event::from_json(
            r#"[{"pid":1,"action":"process_spawn","child_pid":2,"image":"weird.exe"}]"#,
        )
        .unwrap();
        assert!(engine.score(&events).is_empty());
    }
}
