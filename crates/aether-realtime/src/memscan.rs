//! Live process memory scanning - catches *fileless* and *injected* malware
//! that never touches disk (reflective DLLs, process hollowing, shellcode
//! injected into a benign process), which a file scanner alone cannot see.
//!
//! It reads `/proc/<pid>/maps` and flags anomalous regions:
//!   * **W^X violation** - memory that is writable *and* executable. Legitimate
//!     code is almost never both; this is the hallmark of code injection and
//!     JIT-spray.
//!   * **Executable anonymous mapping** - runnable memory not backed by any
//!     file on disk (classic reflective / fileless payload).
//!
//! For flagged regions it can read the bytes from `/proc/<pid>/mem` and run a
//! caller-supplied scanner (e.g. YARA) over them, so an in-memory payload is
//! identified by content, not just by its suspicious mapping.

use std::fs;
use std::io::{Read, Seek, SeekFrom};

/// One suspicious memory region found in a process.
#[derive(Debug, Clone)]
pub struct MemFinding {
    pub pid: i32,
    pub process: String,
    pub region: String,
    pub perms: String,
    pub backing: String,
    pub severity: &'static str,
    pub detail: String,
    /// Names of any content rules (YARA) that matched the region's bytes.
    pub matches: Vec<String>,
}

struct MapRegion {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

/// Largest slice of a single region we will read for content scanning.
const MAX_REGION_READ: u64 = 4 * 1024 * 1024;

/// Process command name (`/proc/<pid>/comm`).
pub fn process_name(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Every numeric PID currently under `/proc`.
pub fn list_pids() -> Vec<i32> {
    let mut pids = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc") {
        for e in rd.flatten() {
            if let Ok(n) = e.file_name().to_string_lossy().parse::<i32>() {
                pids.push(n);
            }
        }
    }
    pids.sort_unstable();
    pids
}

fn parse_maps(pid: i32) -> Vec<MapRegion> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return out;
    };
    for line in text.lines() {
        // Format: start-end perms offset dev inode pathname
        let mut it = line.split_whitespace();
        let (Some(addr), Some(perms)) = (it.next(), it.next()) else {
            continue;
        };
        let (_off, _dev, _inode) = (it.next(), it.next(), it.next());
        let path = it.collect::<Vec<_>>().join(" ");
        let mut a = addr.split('-');
        let (Some(s), Some(e)) = (a.next(), a.next()) else {
            continue;
        };
        if let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) {
            out.push(MapRegion {
                start,
                end,
                perms: perms.to_string(),
                path,
            });
        }
    }
    out
}

/// Scan one process. `content_scan` is invoked with the bytes of each flagged
/// region (e.g. a YARA closure) and returns the names of any matches; pass
/// `|_| Vec::new()` to do structural detection only.
pub fn scan_pid<F>(pid: i32, mut content_scan: F) -> Vec<MemFinding>
where
    F: FnMut(&[u8]) -> Vec<String>,
{
    let mut findings = Vec::new();
    let name = process_name(pid);
    let mut mem = fs::File::open(format!("/proc/{pid}/mem")).ok();

    for r in parse_maps(pid) {
        let exec = r.perms.contains('x');
        let write = r.perms.contains('w');
        let anon = r.path.is_empty() || r.path.starts_with("[anon");
        // Skip the special pseudo-regions we can never read meaningfully.
        if r.path.starts_with("[v") {
            continue; // [vdso] [vvar] [vsyscall]
        }

        let (mut severity, detail): (&'static str, String) = if exec && write {
            (
                "high",
                "writable+executable memory (W^X violation - code injection / JIT-spray)".into(),
            )
        } else if exec && anon {
            ("medium", "executable anonymous mapping not backed by a file (possible reflective/fileless code)".into())
        } else {
            continue;
        };

        // Content-scan the region's bytes when possible.
        let mut matches = Vec::new();
        if let Some(m) = mem.as_mut() {
            let len = (r.end - r.start).min(MAX_REGION_READ) as usize;
            if len > 0 && m.seek(SeekFrom::Start(r.start)).is_ok() {
                let mut buf = vec![0u8; len];
                if let Ok(n) = m.read(&mut buf) {
                    if n > 0 {
                        matches = content_scan(&buf[..n]);
                    }
                }
            }
        }
        if !matches.is_empty() {
            severity = "high";
        }

        findings.push(MemFinding {
            pid,
            process: name.clone(),
            region: format!("{:x}-{:x}", r.start, r.end),
            perms: r.perms.clone(),
            backing: if anon {
                "[anonymous]".into()
            } else {
                r.path.clone()
            },
            severity,
            detail,
            matches,
        });
    }
    findings
}

/// Scan every accessible process. Regions we cannot read are silently skipped.
pub fn scan_all<F>(mut content_scan: F) -> Vec<MemFinding>
where
    F: FnMut(&[u8]) -> Vec<String>,
{
    let mut all = Vec::new();
    for pid in list_pids() {
        all.extend(scan_pid(pid, &mut content_scan));
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_own_maps_and_finds_executable_regions() {
        // Our own process always has at least one r-xp code mapping; ensure the
        // maps parser yields regions without panicking.
        let me = std::process::id() as i32;
        let regions = parse_maps(me);
        assert!(!regions.is_empty(), "should parse /proc/self/maps");
        assert!(regions.iter().any(|r| r.perms.contains('x')));
    }

    #[test]
    fn list_pids_includes_self() {
        let me = std::process::id() as i32;
        assert!(list_pids().contains(&me));
    }
}
