//! Process Sentinel - spots anything NEW running (regardless of name/vendor)
//! and catches processes that try to HIDE.
//!
//! Two pillars:
//!   1. **Novelty** - identify each process by its executable *path + content
//!      hash*, not its (spoofable) name. Anything whose path/hash isn't in the
//!      learned baseline is "something new running you didn't install".
//!   2. **Anti-stealth (cross-view)** - enumerate live PIDs by two independent
//!      methods (`/proc` readdir vs. `kill(pid,0)` probing) and flag any PID
//!      that exists but is missing from the directory listing - the signature of
//!      a userland rootkit hooking `readdir`/`ps`. Plus per-process stealth tells
//!      (executable deleted, running from a temp dir).
//!
//! Honest limit: a *kernel* rootkit can lie to all of userland; closing that gap
//! needs an eBPF/kernel `exec` tracer (phase 2). Cross-view catches userland
//! rootkits, masquerade, fileless and exe-deleted cases now.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// A live process as the sentinel sees it.
#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: i32,
    pub name: String,
    /// Resolved executable path (target of /proc/<pid>/exe), if readable.
    pub exe: Option<PathBuf>,
    /// The executable file was deleted while still running (classic stealth).
    pub exe_deleted: bool,
    /// Running from a world-writable / volatile directory (tmp, shm, …).
    pub from_temp: bool,
}

const TEMP_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/"];

pub fn proc_name(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// PIDs visible via the normal `/proc` directory listing (what `ps` sees).
pub fn pids_readdir() -> BTreeSet<i32> {
    let mut s = BTreeSet::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(n) = e.file_name().to_string_lossy().parse::<i32>() {
                s.insert(n);
            }
        }
    }
    s
}

/// Build a snapshot of the visible processes with their executable identity.
pub fn snapshot() -> Vec<Proc> {
    pids_readdir()
        .into_iter()
        .map(|pid| {
            let (exe, exe_deleted) = match std::fs::read_link(format!("/proc/{pid}/exe")) {
                Ok(p) => {
                    let s = p.to_string_lossy();
                    // The kernel appends " (deleted)" when the backing file is gone.
                    if let Some(stripped) = s.strip_suffix(" (deleted)") {
                        (Some(PathBuf::from(stripped)), true)
                    } else {
                        (Some(p), false)
                    }
                }
                Err(_) => (None, false),
            };
            let from_temp = exe
                .as_ref()
                .map(|p| {
                    let s = p.to_string_lossy();
                    TEMP_DIRS.iter().any(|d| s.starts_with(d))
                })
                .unwrap_or(false);
            Proc {
                pid,
                name: proc_name(pid),
                exe,
                exe_deleted,
                from_temp,
            }
        })
        .collect()
}

/// Upper bound for the brute-force PID probe (capped so the sweep stays fast).
fn probe_cap() -> i32 {
    let configured = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(32768);
    configured.min(262_144)
}

/// Does a PID exist, per `kill(pid, 0)` (independent of `/proc` readdir, so a
/// readdir-hooking rootkit can't hide it from this view)?
#[cfg(target_os = "linux")]
fn pid_exists(pid: i32) -> bool {
    let r = unsafe { libc::kill(pid, 0) };
    if r == 0 {
        return true;
    }
    // EPERM means it exists but we lack permission to signal it.
    unsafe { *libc::__errno_location() == libc::EPERM }
}

/// True only for a thread-group LEADER (a real process), not an individual
/// thread. `/proc/<tid>` is directly reachable for every thread but threads are
/// not listed in `readdir(/proc)`, so without this filter every thread would
/// look "hidden". A process has `Tgid == Pid`.
fn is_real_process(pid: i32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Tgid:") {
            return v.trim().parse::<i32>().map(|t| t == pid).unwrap_or(false);
        }
    }
    false
}

/// Cross-view: PIDs that are directly reachable under `/proc/<pid>` (and exist
/// per `kill(pid,0)`) yet are MISSING from the `/proc` directory listing - the
/// signature of a userland rootkit hooking `readdir`. Uses double-confirmation
/// against a fresh listing so normal processes that merely *start during* the
/// (necessarily long) sweep aren't mistaken for hidden ones.
#[cfg(target_os = "linux")]
pub fn hidden_pids() -> Vec<i32> {
    let direct = |p: i32| std::path::Path::new(&format!("/proc/{p}")).exists();
    let cap = probe_cap();

    // Pass 1: suspects = directly reachable + existing, but not in the listing.
    let vis1 = pids_readdir();
    let mut suspects = Vec::new();
    for pid in 1..=cap {
        if !vis1.contains(&pid) && direct(pid) && pid_exists(pid) && is_real_process(pid) {
            suspects.push(pid);
        }
    }
    if suspects.is_empty() {
        return Vec::new();
    }

    // Confirm against a FRESH listing: a process that started during the sweep
    // is now in the listing (-> dropped); a truly hidden PID stays directly
    // reachable yet still absent from readdir.
    let vis2 = pids_readdir();
    suspects
        .into_iter()
        .filter(|&p| !vis2.contains(&p) && direct(p))
        .collect()
}

#[cfg(not(target_os = "linux"))]
pub fn hidden_pids() -> Vec<i32> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_sees_self_with_exe() {
        let me = std::process::id() as i32;
        let snap = snapshot();
        let mine = snap.iter().find(|p| p.pid == me).expect("see self");
        assert!(mine.exe.is_some(), "own exe path should resolve");
        assert!(!mine.exe_deleted);
    }

    #[test]
    fn readdir_and_kill_views_agree_on_self() {
        // No rootkit in the test env: our own PID is visible both ways, so it
        // must NOT appear in the hidden set.
        let me = std::process::id() as i32;
        assert!(pids_readdir().contains(&me));
        #[cfg(target_os = "linux")]
        assert!(!hidden_pids().contains(&me));
    }
}
