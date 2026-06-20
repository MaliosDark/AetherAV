//! `aether-realtime` - live event sources feeding the behavioral engines.
//!
//! On-access / real-time protection needs a stream of system events. The
//! production sources are kernel-level (eBPF on Linux, ETW + minifilter on
//! Windows, EndpointSecurity on macOS); those require privileges and are
//! platform-specific. This crate provides the *framework* - an [`EventSource`]
//! trait and a [`Collector`] that maintains a rolling window and runs the
//! Phase-5 [`BehaviorEngine`] - plus a dependency-free userspace
//! [`ProcMonitor`] (Linux `/proc`) that emits real process-spawn events without
//! root. Kernel sources implement the same trait and drop straight in.

pub mod clipguard;
pub mod dns;
#[cfg(target_os = "linux")]
pub mod exectrace;
pub mod memscan;
pub mod netmon;
#[cfg(target_os = "linux")]
pub mod onaccess;
pub mod ransomguard;
pub mod secrets;
#[cfg(target_os = "linux")]
pub mod selfprotect;
pub mod sentinel;
pub mod stealerguard;
pub mod timestomp;

use aether_behavior::event::{Action, Event};
use aether_behavior::BehaviorEngine;
use aether_common::Verdict;
use std::collections::HashSet;

/// Cross-platform real-time file monitor (inotify on Linux, FSEvents on macOS,
/// ReadDirectoryChanges on Windows - all via the `notify` crate). Yields the
/// paths of files created or modified under a watched directory, so the engine
/// can scan them on-access. No root required for user-readable directories.
pub struct FileWatcher {
    rx: std::sync::mpsc::Receiver<std::path::PathBuf>,
    _watcher: notify::RecommendedWatcher,
}

impl FileWatcher {
    /// Begin watching `dir` recursively for create/modify events.
    pub fn watch(dir: &std::path::Path) -> Result<FileWatcher, String> {
        use notify::{EventKind, RecursiveMode, Watcher};
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for p in ev.paths {
                        let _ = tx.send(p);
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
        watcher
            .watch(dir, RecursiveMode::Recursive)
            .map_err(|e| e.to_string())?;
        Ok(FileWatcher {
            rx,
            _watcher: watcher,
        })
    }

    /// Block until the next changed file path (or `None` after `timeout`).
    pub fn next_changed(&self, timeout: std::time::Duration) -> Option<std::path::PathBuf> {
        self.rx.recv_timeout(timeout).ok()
    }
}

/// A source of live behavioral events.
pub trait EventSource {
    /// Human-readable source name.
    fn name(&self) -> &str;
    /// Return events observed since the previous poll.
    fn poll(&mut self) -> Vec<Event>;
}

/// Parse a `/proc/<pid>/stat` line into `(comm, ppid)`.
///
/// `comm` can contain spaces and parentheses, so we anchor on the first `(`
/// and the *last* `)`; the fields after it are space-separated, with `state`
/// first and `ppid` second.
pub fn parse_stat(content: &str) -> Option<(String, u32)> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = content[open + 1..close].to_string();
    let tail: Vec<&str> = content[close + 1..].split_whitespace().collect();
    let ppid = tail.get(1)?.parse().ok()?;
    Some((comm, ppid))
}

/// A userspace process monitor backed by `/proc` (Linux). Emits a
/// `ProcessSpawn` event the first time it observes each pid.
#[derive(Default)]
pub struct ProcMonitor {
    seen: HashSet<u32>,
    tick: u64,
}

impl ProcMonitor {
    pub fn new() -> ProcMonitor {
        ProcMonitor::default()
    }

    /// Mark the currently-running processes as already-seen, so the next
    /// `poll` reports only *new* spawns rather than the whole process table.
    pub fn prime(&mut self) {
        let _ = self.poll();
    }
}

impl EventSource for ProcMonitor {
    fn name(&self) -> &str {
        "proc"
    }

    #[cfg(target_os = "linux")]
    fn poll(&mut self) -> Vec<Event> {
        self.tick += 1;
        let mut events = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return events;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid: u32 = match name.to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue, // non-pid entries (e.g. /proc/cpuinfo)
            };
            if !self.seen.insert(pid) {
                continue; // already known
            }
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let (comm, ppid) = parse_stat(&stat).unwrap_or_else(|| ("?".to_string(), 0));
            let cmdline = read_cmdline(pid);
            events.push(Event {
                ts: self.tick,
                pid: ppid,
                action: Action::ProcessSpawn {
                    child_pid: pid,
                    image: comm,
                    cmdline,
                },
            });
        }
        events
    }

    #[cfg(not(target_os = "linux"))]
    fn poll(&mut self) -> Vec<Event> {
        // Non-Linux: kernel sources (ETW/EndpointSecurity) plug in here.
        self.tick += 1;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> String {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => bytes
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s))
            .collect::<Vec<_>>()
            .join(" "),
        Err(_) => String::new(),
    }
}

/// Maintains a rolling window of recent events and runs the behavioral engine
/// over it. A sliding window bounds memory for a long-running monitor.
pub struct Collector {
    window: Vec<Event>,
    capacity: usize,
    engine: BehaviorEngine,
}

impl Collector {
    pub fn new(capacity: usize) -> Collector {
        Collector {
            window: Vec::new(),
            capacity: capacity.max(1),
            engine: BehaviorEngine::new(),
        }
    }

    /// Add freshly-polled events, evicting the oldest beyond the capacity.
    pub fn ingest(&mut self, mut events: Vec<Event>) {
        self.window.append(&mut events);
        if self.window.len() > self.capacity {
            let overflow = self.window.len() - self.capacity;
            self.window.drain(0..overflow);
        }
    }

    /// Behavioral verdicts over the current window.
    pub fn analyze(&self) -> Vec<Verdict> {
        self.engine.analyze(&self.window).verdicts
    }

    pub fn window(&self) -> &[Event] {
        &self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_stat() {
        let line = "1234 (bash) S 1000 1234 1234 0 -1 4194304";
        let (comm, ppid) = parse_stat(line).unwrap();
        assert_eq!(comm, "bash");
        assert_eq!(ppid, 1000);
    }

    #[test]
    fn parses_comm_with_spaces_and_parens() {
        // comm = "Web Content (tab)" - exercises the first-'(' / last-')' rule.
        let line = "42 (Web Content (tab)) R 7 42 42 0 -1 0 0";
        let (comm, ppid) = parse_stat(line).unwrap();
        assert_eq!(comm, "Web Content (tab)");
        assert_eq!(ppid, 7);
    }

    #[test]
    fn collector_windows_and_analyzes() {
        let mut c = Collector::new(100);
        // Feed an injection sequence; the behavior engine should flag T1055.
        let evs = aether_behavior::Event::from_json(
            r#"[
                {"pid":500,"action":"mem_alloc","target_pid":900,"protection":"RWX"},
                {"pid":500,"action":"remote_thread","target_pid":900}
            ]"#,
        )
        .unwrap();
        c.ingest(evs);
        let verdicts = c.analyze();
        assert!(verdicts
            .iter()
            .any(|v| v.signature == "behavior.process_injection"));
    }

    #[test]
    fn collector_respects_capacity() {
        let mut c = Collector::new(3);
        for _ in 0..10 {
            c.ingest(
                aether_behavior::Event::from_json(
                    r#"[{"pid":1,"action":"file_write","path":"/x","entropy":1.0}]"#,
                )
                .unwrap(),
            );
        }
        assert_eq!(c.window().len(), 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_monitor_sees_live_processes() {
        let mut m = ProcMonitor::new();
        let first = m.poll();
        assert!(
            !first.is_empty(),
            "should observe running processes on Linux"
        );
        // Everything already seen -> a second poll reports no *new* known pids
        // (modulo races with the OS spawning processes, which only adds noise).
        let second = m.poll();
        assert!(second.len() <= first.len());
    }
}
