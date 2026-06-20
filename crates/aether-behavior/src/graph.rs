//! The behavioral relationship graph.
//!
//! Nodes are entities (processes, files, network hosts); directed edges are the
//! actions that relate them. The graph powers detections that pure per-event
//! matching misses - most importantly *process ancestry* ("a script host whose
//! lineage traces back to an Office app"), which is how phishing chains are
//! caught even when there are intermediate hops (winword -> cmd -> powershell).

use crate::event::{basename, Action, Event};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::HashMap;

/// A node in the behavior graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entity {
    /// A process, keyed by pid, with its image basename (empty if unknown).
    Process {
        pid: u32,
        image: String,
    },
    File {
        path: String,
    },
    Host {
        remote: String,
    },
}

/// The relationship an edge represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rel {
    Spawned,
    Wrote,
    Deleted,
    Renamed,
    Connected,
    Injected,
    Loaded,
    ModifiedRegistry,
}

/// Incrementally-built graph plus lookup indices.
pub struct BehaviorGraph {
    g: DiGraph<Entity, Rel>,
    process_node: HashMap<u32, NodeIndex>,
    images: HashMap<u32, String>,
}

impl BehaviorGraph {
    /// Build a graph from a full event trace.
    pub fn build(events: &[Event]) -> BehaviorGraph {
        let mut bg = BehaviorGraph {
            g: DiGraph::new(),
            process_node: HashMap::new(),
            images: HashMap::new(),
        };
        for ev in events {
            bg.ingest(ev);
        }
        bg
    }

    /// Get (creating if needed) the node for a process.
    fn process(&mut self, pid: u32) -> NodeIndex {
        if let Some(&idx) = self.process_node.get(&pid) {
            return idx;
        }
        let image = self.images.get(&pid).cloned().unwrap_or_default();
        let idx = self.g.add_node(Entity::Process { pid, image });
        self.process_node.insert(pid, idx);
        idx
    }

    fn ingest(&mut self, ev: &Event) {
        let actor = self.process(ev.pid);
        match &ev.action {
            Action::ProcessSpawn {
                child_pid, image, ..
            } => {
                self.images.insert(*child_pid, basename(image));
                let child = self.process(*child_pid);
                // Refresh the child's stored image now that we know it.
                if let Some(Entity::Process { image: img, .. }) = self.g.node_weight_mut(child) {
                    *img = basename(image);
                }
                self.g.add_edge(actor, child, Rel::Spawned);
            }
            Action::FileWrite { path, .. } => {
                let f = self.g.add_node(Entity::File { path: path.clone() });
                self.g.add_edge(actor, f, Rel::Wrote);
            }
            Action::FileDelete { path } => {
                let f = self.g.add_node(Entity::File { path: path.clone() });
                self.g.add_edge(actor, f, Rel::Deleted);
            }
            Action::FileRename { to, .. } => {
                let f = self.g.add_node(Entity::File { path: to.clone() });
                self.g.add_edge(actor, f, Rel::Renamed);
            }
            Action::NetConnect { remote, .. } => {
                let h = self.g.add_node(Entity::Host {
                    remote: remote.clone(),
                });
                self.g.add_edge(actor, h, Rel::Connected);
            }
            Action::MemAlloc { target_pid, .. } | Action::RemoteThread { target_pid } => {
                let target = self.process(*target_pid);
                self.g.add_edge(actor, target, Rel::Injected);
            }
            Action::ModuleLoad { module } => {
                let m = self.g.add_node(Entity::File {
                    path: module.clone(),
                });
                self.g.add_edge(actor, m, Rel::Loaded);
            }
            Action::RegistrySet { key, .. } => {
                let k = self.g.add_node(Entity::File { path: key.clone() });
                self.g.add_edge(actor, k, Rel::ModifiedRegistry);
            }
        }
    }

    /// Image basename of a process (empty string if never observed).
    pub fn image_of(&self, pid: u32) -> &str {
        self.images.get(&pid).map(String::as_str).unwrap_or("")
    }

    /// Walk the spawn ancestry of `pid` (nearest parent first), returning each
    /// ancestor's image basename. Cycle-safe.
    pub fn ancestor_images(&self, pid: u32) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current = match self.process_node.get(&pid) {
            Some(&idx) => idx,
            None => return out,
        };
        while seen.insert(current) {
            // Find a parent via an incoming Spawned edge.
            let parent = self
                .g
                .edges_directed(current, Direction::Incoming)
                .find(|e| *petgraph::visit::EdgeRef::weight(e) == Rel::Spawned)
                .map(|e| petgraph::visit::EdgeRef::source(&e));
            match parent {
                Some(p) => {
                    if let Some(Entity::Process { image, .. }) = self.g.node_weight(p) {
                        out.push(image.clone());
                    }
                    current = p;
                }
                None => break,
            }
        }
        out
    }

    /// `true` if any ancestor's image matches one of `images` (basenames).
    pub fn has_ancestor_in(&self, pid: u32, images: &[&str]) -> bool {
        self.ancestor_images(pid)
            .iter()
            .any(|a| images.contains(&a.as_str()))
    }

    /// Counts for the summary line / debugging.
    pub fn node_count(&self) -> usize {
        self.g.node_count()
    }
    pub fn edge_count(&self) -> usize {
        self.g.edge_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_ancestry_through_intermediate_hop() {
        // explorer(10) -> winword(20) -> cmd(30) -> powershell(40)
        let json = r#"[
            {"pid":10,"action":"process_spawn","child_pid":20,"image":"winword.exe"},
            {"pid":20,"action":"process_spawn","child_pid":30,"image":"cmd.exe"},
            {"pid":30,"action":"process_spawn","child_pid":40,"image":"powershell.exe"}
        ]"#;
        let events = Event::from_json(json).unwrap();
        let g = BehaviorGraph::build(&events);
        assert_eq!(g.image_of(40), "powershell.exe");
        assert!(g.has_ancestor_in(40, &["winword.exe"]));
        assert!(!g.has_ancestor_in(40, &["outlook.exe"]));
    }
}
