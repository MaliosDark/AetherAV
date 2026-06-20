//! The behavioral event model.
//!
//! An event is a single observed action by a process. In production these come
//! from the real-time sensors (eBPF on Linux, ETW + minifilter on Windows,
//! EndpointSecurity on macOS) or from the dynamic sandbox (Phase 4). For now
//! they can also be loaded from a JSON trace, which makes the whole engine
//! testable and demonstrable offline.
//!
//! JSON shape (one object per event):
//! ```json
//! {"ts": 3, "pid": 200, "action": "process_spawn",
//!  "child_pid": 201, "image": "powershell.exe", "cmdline": "-enc SQBFAFgA"}
//! ```

use serde::{Deserialize, Serialize};

/// A timestamped action performed by process `pid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Logical timestamp (monotonic ordering; units are source-defined).
    #[serde(default)]
    pub ts: u64,
    /// The acting process.
    pub pid: u32,
    /// What it did.
    #[serde(flatten)]
    pub action: Action,
}

/// The set of actions the engine reasons about. Internally tagged on `action`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// `pid` created a new process `child_pid` running `image`.
    ProcessSpawn {
        child_pid: u32,
        image: String,
        #[serde(default)]
        cmdline: String,
    },
    /// `pid` wrote `path`. `entropy` (bits/byte) lets us spot encryption.
    FileWrite {
        path: String,
        #[serde(default)]
        entropy: f64,
    },
    /// `pid` deleted `path`.
    FileDelete { path: String },
    /// `pid` renamed `from` -> `to` (ransomware often appends an extension).
    FileRename { from: String, to: String },
    /// `pid` opened an outbound network connection.
    NetConnect { remote: String, port: u16 },
    /// `pid` allocated memory in `target_pid` with `protection` (e.g. "RWX").
    MemAlloc { target_pid: u32, protection: String },
    /// `pid` started a thread in `target_pid` (classic injection finisher).
    RemoteThread { target_pid: u32 },
    /// `pid` loaded a module / library.
    ModuleLoad { module: String },
    /// `pid` set a registry value (Windows persistence surface).
    RegistrySet { key: String, value: String },
}

impl Event {
    /// Parse a JSON array of events.
    pub fn from_json(text: &str) -> Result<Vec<Event>, String> {
        serde_json::from_str(text).map_err(|e| format!("trace parse error: {e}"))
    }
}

/// Lowercase basename of a process image path (`C:\\…\\PowerShell.EXE` -> `powershell.exe`).
pub fn basename(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trace_json() {
        let json = r#"[
            {"ts":1,"pid":100,"action":"process_spawn","child_pid":200,"image":"C:\\Windows\\System32\\cmd.exe","cmdline":"/c x"},
            {"ts":2,"pid":200,"action":"net_connect","remote":"45.9.1.2","port":443}
        ]"#;
        let events = Event::from_json(json).unwrap();
        assert_eq!(events.len(), 2);
        match &events[0].action {
            Action::ProcessSpawn { child_pid, .. } => assert_eq!(*child_pid, 200),
            _ => panic!("expected spawn"),
        }
    }

    #[test]
    fn basename_normalizes() {
        assert_eq!(
            basename("C:\\Windows\\System32\\PowerShell.EXE"),
            "powershell.exe"
        );
        assert_eq!(basename("/usr/bin/Python3"), "python3");
        assert_eq!(basename("winword.exe"), "winword.exe");
    }
}
