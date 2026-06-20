//! Timestomping detection (MITRE ATT&CK T1070.006 - Indicator Removal: Timestomp).
//!
//! Malware fakes file timestamps to blend in with system files or defeat
//! forensic timelines. Common tells:
//!   - timestamp-faking tools write whole-second values, zeroing the sub-second
//!     (nanosecond) field that real filesystem writes almost always populate;
//!   - a creation/birth time LATER than the modification time (impossible for a
//!     normally-written file);
//!   - a PE compile timestamp in the future, or wildly far from the file's age.
//!
//! The evaluation is pure and unit-tested; `from_metadata` adapts a live file.

use std::fs::Metadata;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestompIndicator {
    /// Both mtime and atime have a zero nanosecond component (tool artifact).
    ZeroSubsecond,
    /// Birth/creation time is later than the modification time.
    CreatedAfterModified,
    /// The PE compile timestamp is in the future.
    PeTimestampFuture,
    /// The PE compile timestamp is far (this many days) from the file's mtime.
    PeAgeMismatch(i64),
}

impl TimestompIndicator {
    pub fn describe(self) -> String {
        match self {
            TimestompIndicator::ZeroSubsecond => {
                "timestamps have a zeroed sub-second field (timestomp tool artifact)".into()
            }
            TimestompIndicator::CreatedAfterModified => {
                "modification time is years older than the creation time (possible backdating)"
                    .into()
            }
            TimestompIndicator::PeTimestampFuture => "PE compile time is in the future".into(),
            TimestompIndicator::PeAgeMismatch(d) => {
                format!("PE compile time is {d} days from the file date")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimestompReport {
    pub indicators: Vec<TimestompIndicator>,
    /// True if a high-confidence timestomping signal is present.
    pub suspicious: bool,
}

/// Timestamp fields extracted from a file (unix seconds + sub-second nanos).
#[derive(Debug, Clone, Copy)]
pub struct Times {
    pub mtime: i64,
    pub mtime_ns: u32,
    pub atime_ns: u32,
    /// Birth/creation time, if the filesystem records it.
    pub btime: Option<i64>,
}

fn unix(t: SystemTime) -> Option<(i64, u32)> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
}

/// Extract timestamps from live file metadata.
pub fn from_metadata(m: &Metadata) -> Times {
    let (mtime, mtime_ns) = m.modified().ok().and_then(unix).unwrap_or((0, 0));
    let atime_ns = m
        .accessed()
        .ok()
        .and_then(unix)
        .map(|(_, n)| n)
        .unwrap_or(0);
    let btime = m.created().ok().and_then(unix).map(|(s, _)| s);
    Times {
        mtime,
        mtime_ns,
        atime_ns,
        btime,
    }
}

const DAY: i64 = 86_400;
const PE_AGE_MISMATCH_DAYS: i64 = 1095; // ~3 years

/// Evaluate timestamps (+ optional PE compile timestamp) for timestomping.
pub fn evaluate(t: &Times, pe_timestamp: Option<u32>, now_unix: i64) -> TimestompReport {
    let mut ind = Vec::new();

    // Zeroed sub-second on both mtime and atime: a real write almost never does
    // this; timestomp tools that set whole seconds do. (Require mtime present.)
    if t.mtime != 0 && t.mtime_ns == 0 && t.atime_ns == 0 {
        ind.push(TimestompIndicator::ZeroSubsecond);
    }
    // Only flag a LARGE gap (creation > 2y after modification): a fresh install
    // legitimately has a creation time weeks/months after the upstream mtime, so
    // a small gap is normal noise; a multi-year gap suggests a backdated mtime.
    if let Some(b) = t.btime {
        if b > t.mtime + 730 * DAY {
            ind.push(TimestompIndicator::CreatedAfterModified);
        }
    }
    if let Some(ts) = pe_timestamp {
        if ts != 0 {
            let ts = ts as i64;
            if ts > now_unix + DAY {
                ind.push(TimestompIndicator::PeTimestampFuture);
            } else if t.mtime != 0 {
                let d = (t.mtime - ts).abs() / DAY;
                if d > PE_AGE_MISMATCH_DAYS {
                    ind.push(TimestompIndicator::PeAgeMismatch(d));
                }
            }
        }
    }

    // Only a PE timestamp in the FUTURE is high-confidence and low-FP. The FS
    // heuristics (zero sub-second, created-after-modified, age mismatch) are
    // INFORMATIONAL: they are common for legitimately installed software (e.g.
    // a package preserves the upstream mtime but gets a fresh creation time on
    // install, and tar/old filesystems store whole-second times). Forensic-grade
    // timestomping detection needs NTFS $STANDARD_INFORMATION vs $FILE_NAME
    // comparison (Windows, raw MFT) - a future addition.
    let suspicious = ind
        .iter()
        .any(|i| matches!(i, TimestompIndicator::PeTimestampFuture));
    TimestompReport {
        indicators: ind,
        suspicious,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_780_000_000; // a fixed "now" for deterministic tests

    #[test]
    fn reports_zero_subsecond_as_informational() {
        let t = Times {
            mtime: NOW - 100,
            mtime_ns: 0,
            atime_ns: 0,
            btime: Some(NOW - 200),
        };
        let r = evaluate(&t, None, NOW);
        assert!(r.indicators.contains(&TimestompIndicator::ZeroSubsecond));
        assert!(!r.suspicious); // common on installed software -> not auto-flagged
    }

    #[test]
    fn small_install_gap_is_not_flagged() {
        // mtime a few months before creation = normal install -> no indicator.
        let t = Times {
            mtime: NOW - 90 * DAY,
            mtime_ns: 123,
            atime_ns: 5,
            btime: Some(NOW),
        };
        assert!(evaluate(&t, None, NOW).indicators.is_empty());
    }

    #[test]
    fn multi_year_backdating_is_reported() {
        // mtime backdated 4 years before creation -> informational backdating note.
        let t = Times {
            mtime: NOW - 4 * 365 * DAY,
            mtime_ns: 123,
            atime_ns: 5,
            btime: Some(NOW),
        };
        let r = evaluate(&t, None, NOW);
        assert!(r
            .indicators
            .contains(&TimestompIndicator::CreatedAfterModified));
        assert!(!r.suspicious);
    }

    #[test]
    fn flags_future_pe_timestamp() {
        let t = Times {
            mtime: NOW - 50,
            mtime_ns: 99,
            atime_ns: 99,
            btime: None,
        };
        assert!(evaluate(&t, Some((NOW + 10 * DAY) as u32), NOW).suspicious);
    }

    #[test]
    fn pe_age_mismatch_is_informational_not_suspicious() {
        let t = Times {
            mtime: NOW,
            mtime_ns: 42,
            atime_ns: 42,
            btime: Some(NOW - 10),
        };
        // PE compiled ~5 years before the file: noted, but not flagged alone.
        let r = evaluate(&t, Some((NOW - 5 * 365 * DAY) as u32), NOW);
        assert!(matches!(
            r.indicators.first(),
            Some(TimestompIndicator::PeAgeMismatch(_))
        ));
        assert!(!r.suspicious);
    }

    #[test]
    fn clean_file_is_quiet() {
        let t = Times {
            mtime: NOW - 500,
            mtime_ns: 731_004_210,
            atime_ns: 12_345,
            btime: Some(NOW - 600),
        };
        let r = evaluate(&t, Some((NOW - 30 * DAY) as u32), NOW);
        assert!(r.indicators.is_empty());
        assert!(!r.suspicious);
    }
}
