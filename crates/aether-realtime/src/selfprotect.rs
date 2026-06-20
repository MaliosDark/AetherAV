//! Process self-protection (Linux) - make the AV resistant to tampering, the
//! way commercial agents protect themselves from being dumped or killed by the
//! malware they're hunting.
//!
//! * `PR_SET_DUMPABLE = 0` - the process becomes non-dumpable: other non-root
//!   processes can no longer `ptrace`-attach or read `/proc/<pid>/mem`, so
//!   malware can't scrape our memory or patch us live.
//! * OOM protection - bias the kernel against killing us under memory pressure.

#![cfg(target_os = "linux")]

use std::io::Write;

/// Harden the current process. Best-effort: returns an error only if the core
/// anti-debug step fails.
pub fn harden() -> Result<(), String> {
    // SAFETY: prctl with PR_SET_DUMPABLE is a simple, well-defined syscall.
    let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if r != 0 {
        return Err("prctl(PR_SET_DUMPABLE) failed".into());
    }
    // Best-effort: resist the OOM killer.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/oom_score_adj")
    {
        let _ = f.write_all(b"-900");
    }
    Ok(())
}

/// Whether this process is currently non-dumpable (i.e. hardened).
pub fn is_hardened() -> bool {
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 }
}
