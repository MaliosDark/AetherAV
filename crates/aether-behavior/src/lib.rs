//! `aether-behavior` - the Behavioral + Graph detection engine.
//!
//! Consumes a stream of [`Event`]s (from the dynamic sandbox, or the real-time
//! eBPF/ETW/EndpointSecurity sensors), builds a process/file/network relationship
//! [`BehaviorGraph`], and runs MITRE ATT&CK-mapped [`rules`] over both the events
//! and the graph. The result is a set of explainable, technique-tagged verdicts.
//!
//! This layer is signature-independent: it detects malicious *behavior*, which
//! is what catches polymorphic, fileless and living-off-the-land threats that
//! the static engines cannot.

pub mod event;
pub mod graph;
pub mod rules;

pub use event::{Action, Event};
pub use graph::BehaviorGraph;

use aether_common::{ThreatLevel, Verdict};

/// Outcome of analyzing an event trace.
#[derive(Debug, Clone)]
pub struct BehaviorReport {
    pub verdicts: Vec<Verdict>,
    pub nodes: usize,
    pub edges: usize,
}

impl BehaviorReport {
    /// Worst severity across all behavioral verdicts.
    pub fn disposition(&self) -> ThreatLevel {
        self.verdicts
            .iter()
            .map(|v| v.level)
            .max()
            .unwrap_or(ThreatLevel::Clean)
    }

    /// Give local triage the shape of the activity without including trace
    /// fields such as command lines, file paths, process names or addresses.
    pub fn triage_summary(&self, events: &[Event]) -> String {
        let mut kinds = [0; 5];
        for event in events {
            let kind = match event.action {
                Action::ProcessSpawn { .. } => 0,
                Action::FileWrite { .. }
                | Action::FileDelete { .. }
                | Action::FileRename { .. } => 1,
                Action::NetConnect { .. } => 2,
                Action::MemAlloc { .. }
                | Action::RemoteThread { .. }
                | Action::ModuleLoad { .. } => 3,
                Action::RegistrySet { .. } => 4,
            };
            kinds[kind] += 1;
        }
        let [spawns, filesystem, network, memory, registry] = kinds;
        let mut detectors: Vec<_> = self.verdicts.iter().map(|v| v.signature.as_str()).collect();
        detectors.sort_unstable();
        detectors.dedup();
        format!(
            "events={} entities={} relationships={} activity=spawn:{spawns},file:{filesystem},net:{network},memory:{memory},registry:{registry} detectors={}",
            events.len(), self.nodes, self.edges, detectors.join(", ")
        )
    }

    /// Distinct MITRE ATT&CK techniques observed, sorted and de-duplicated.
    pub fn techniques(&self) -> Vec<String> {
        let mut t: Vec<String> = self
            .verdicts
            .iter()
            .flat_map(|v| v.mitre.iter().cloned())
            .collect();
        t.sort();
        t.dedup();
        t
    }
}

/// The behavioral engine. Stateless today; will hold per-host baselines and the
/// online-learning anomaly model in Phase 6.
#[derive(Default)]
pub struct BehaviorEngine;

impl BehaviorEngine {
    pub fn new() -> BehaviorEngine {
        BehaviorEngine
    }

    /// Analyze a full event trace.
    pub fn analyze(&self, events: &[Event]) -> BehaviorReport {
        let graph = BehaviorGraph::build(events);
        let verdicts = rules::evaluate(events, &graph);
        tracing::debug!(
            verdicts = verdicts.len(),
            nodes = graph.node_count(),
            edges = graph.edge_count(),
            "behavioral analysis complete"
        );
        BehaviorReport {
            verdicts,
            nodes: graph.node_count(),
            edges: graph.edge_count(),
        }
    }

    /// Load a JSON event trace from a string and analyze it.
    pub fn analyze_json(&self, json: &str) -> Result<BehaviorReport, String> {
        let events = Event::from_json(json)?;
        Ok(self.analyze(&events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_payload_requires_same_child_and_order() {
        let mut events = Event::from_json(
            r#"[
            {"pid":12,"action":"file_write","path":"/tmp/example"},
            {"pid":12,"action":"process_spawn","child_pid":34,"image":"/tmp/example"},
            {"pid":34,"action":"net_connect","remote":"8.8.8.8","port":443}
        ]"#,
        )
        .unwrap();
        let engine = BehaviorEngine::new();
        let matched = |events: &[Event]| {
            engine.analyze(events).verdicts.iter().any(|v| {
                v.signature == "behavior.temporary_payload_connection"
                    && v.level == ThreatLevel::Suspicious
            })
        };
        assert!(matched(&events));
        events[2].pid = 35;
        assert!(!matched(&events));
        events[2].pid = 34;
        events.swap(1, 2);
        assert!(!matched(&events));
    }

    #[test]
    fn staged_process_writing_autostart_is_suspicious() {
        let mut events = Event::from_json(r#"[
            {"pid":12,"action":"file_write","path":"/tmp/local-only-value"},
            {"pid":12,"action":"process_spawn","child_pid":34,"image":"/tmp/local-only-value","cmdline":"private-argument"},
            {"pid":34,"action":"file_write","path":"/etc/systemd/system/example.service"}
        ]"#).unwrap();
        let engine = BehaviorEngine::new();
        let report = engine.analyze(&events);
        assert!(report.techniques().contains(&"T1543.002".to_string()));
        assert_eq!(report.disposition(), ThreatLevel::Suspicious);
        let summary = report.triage_summary(&events);
        assert!(summary.contains("activity=spawn:1,file:2,net:0,memory:0,registry:0"));
        assert!(summary.contains("behavior.temporary_payload_persistence"));
        assert!(!summary.contains("local-only-value"));
        assert!(!summary.contains("private-argument"));
        assert!(!summary.contains("example.service"));
        events[2].pid = 35;
        assert!(!engine
            .analyze(&events)
            .techniques()
            .contains(&"T1543.002".to_string()));
    }

    #[test]
    fn report_aggregates_techniques() {
        let json = r#"[
            {"pid":1,"action":"process_spawn","child_pid":20,"image":"winword.exe"},
            {"pid":20,"action":"process_spawn","child_pid":30,"image":"powershell.exe","cmdline":"-enc AAAA"},
            {"pid":30,"action":"net_connect","remote":"45.9.1.2","port":443}
        ]"#;
        let report = BehaviorEngine::new().analyze_json(json).unwrap();
        assert_eq!(report.disposition(), ThreatLevel::Malicious);
        let techniques = report.techniques();
        assert!(techniques.contains(&"T1059".to_string()));
        assert!(techniques.contains(&"T1071".to_string()));
        assert!(report.nodes > 0 && report.edges > 0);
    }
}
