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
