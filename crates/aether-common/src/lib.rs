//! `aether-common` - the vocabulary shared by every layer of AetherAV.
//!
//! Keeping verdicts, threat levels and errors in one dependency-light crate
//! lets the parser, signature, heuristic and (future) ML engines all speak the
//! same language without depending on each other.

pub mod logging;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Severity of a single finding, ordered so `max()` picks the worst.
///
/// The ordering is meaningful: `Clean < Suspicious < Malicious`, which lets the
/// orchestrator fold many engine verdicts into one final disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    /// Nothing of interest was found.
    Clean,
    /// Heuristics tripped, but no high-confidence signature matched.
    Suspicious,
    /// A high-confidence signature / rule / model fired.
    Malicious,
}

impl ThreatLevel {
    /// Numeric weight used when aggregating multiple engine scores.
    pub fn weight(self) -> u8 {
        match self {
            ThreatLevel::Clean => 0,
            ThreatLevel::Suspicious => 1,
            ThreatLevel::Malicious => 2,
        }
    }
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ThreatLevel::Clean => "CLEAN",
            ThreatLevel::Suspicious => "SUSPICIOUS",
            ThreatLevel::Malicious => "MALICIOUS",
        };
        f.write_str(s)
    }
}

/// Which engine produced a verdict. Used for explainability and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    Hash,
    Yara,
    Heuristic,
    /// Reserved for the upcoming ML / behavioral layers.
    Ml,
    Behavioral,
    /// Dynamic sandbox / emulation layer.
    Sandbox,
    /// Anomaly-detection layer (learned per-host baseline).
    Anomaly,
    /// A third-party detector plugin.
    Plugin,
    /// Threat-intel IOC match (URL / domain / IP found in content).
    Intel,
    /// On-device LLM classifier (compact model embedded as a detection engine).
    Llm,
}

/// A single detection produced by one engine.
///
/// A scan can yield many verdicts; the final disposition is the worst of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// Which engine fired.
    pub engine: EngineKind,
    /// Severity of this finding.
    pub level: ThreatLevel,
    /// Signature / rule name, e.g. `Win.Trojan.Emotet` or `pe_high_entropy`.
    pub signature: String,
    /// Confidence in `[0.0, 1.0]`. Hash hits are `1.0`; heuristics vary.
    pub score: f32,
    /// Optional MITRE ATT&CK technique IDs (e.g. `T1055` process injection).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<String>,
    /// Human-readable explanation of why this fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Verdict {
    /// Convenience constructor for a high-confidence malicious hit.
    pub fn malicious(engine: EngineKind, signature: impl Into<String>, score: f32) -> Self {
        Verdict {
            engine,
            level: ThreatLevel::Malicious,
            signature: signature.into(),
            score,
            mitre: Vec::new(),
            detail: None,
        }
    }

    /// Convenience constructor for a heuristic / low-confidence hit.
    pub fn suspicious(engine: EngineKind, signature: impl Into<String>, score: f32) -> Self {
        Verdict {
            engine,
            level: ThreatLevel::Suspicious,
            signature: signature.into(),
            score,
            mitre: Vec::new(),
            detail: None,
        }
    }

    /// Builder-style attachment of an explanation.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Builder-style attachment of MITRE ATT&CK technique IDs.
    pub fn with_mitre(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.mitre = ids.into_iter().map(Into::into).collect();
        self
    }
}

/// Cryptographic identity of a scanned artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileHashes {
    pub sha256: String,
    /// MD5 / SHA-1 are kept for interop with legacy IOC feeds and the ClamAV
    /// hash signature database (which is predominantly MD5-keyed).
    #[serde(default)]
    pub md5: String,
    #[serde(default)]
    pub sha1: String,
    pub blake3: String,
    pub size: u64,
}

/// The complete result of scanning one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub path: PathBuf,
    pub hashes: FileHashes,
    /// All findings, in the order engines produced them.
    pub verdicts: Vec<Verdict>,
    /// Wall-clock time spent scanning this file.
    #[serde(with = "duration_millis")]
    pub elapsed: Duration,
}

impl ScanReport {
    /// The final disposition: the worst level any engine reported.
    pub fn disposition(&self) -> ThreatLevel {
        self.verdicts
            .iter()
            .map(|v| v.level)
            .max()
            .unwrap_or(ThreatLevel::Clean)
    }

    /// Whether anything actionable was found.
    pub fn is_threat(&self) -> bool {
        self.disposition() >= ThreatLevel::Suspicious
    }
}

/// Aggregate statistics for a multi-file scan run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned: u64,
    pub clean: u64,
    pub suspicious: u64,
    pub malicious: u64,
    pub errors: u64,
    #[serde(with = "duration_millis")]
    pub elapsed: Duration,
}

impl ScanSummary {
    /// Fold a single report into the running totals.
    pub fn record(&mut self, report: &ScanReport) {
        self.scanned += 1;
        match report.disposition() {
            ThreatLevel::Clean => self.clean += 1,
            ThreatLevel::Suspicious => self.suspicious += 1,
            ThreatLevel::Malicious => self.malicious += 1,
        }
    }
}

/// Errors surfaced to the caller. Each engine maps its internal failures here.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("signature database error: {0}")]
    Signature(String),

    #[error("parser error: {0}")]
    Parser(String),

    #[error("yara engine error: {0}")]
    Yara(String),

    #[error("quarantine error: {0}")]
    Quarantine(String),
}

/// Serialize `Duration` as integer milliseconds for stable JSON output.
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u128(d.as_millis())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(d)?;
        Ok(Duration::from_millis(millis))
    }
}

/// Build a [`std::process::Command`] that never flashes a console window on
/// Windows. AetherAV runs as a background watcher and a GUI app, so every helper
/// process it spawns (netstat, the LLM runner, unpackers, …) must stay invisible
/// instead of popping a `cmd`/console window. No-op on non-Windows platforms.
pub fn quiet_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = std::process::Command::new(program);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new(program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_levels_order_worst_last() {
        assert!(ThreatLevel::Clean < ThreatLevel::Suspicious);
        assert!(ThreatLevel::Suspicious < ThreatLevel::Malicious);
        let worst = [
            ThreatLevel::Clean,
            ThreatLevel::Malicious,
            ThreatLevel::Suspicious,
        ]
        .into_iter()
        .max()
        .unwrap();
        assert_eq!(worst, ThreatLevel::Malicious);
    }

    #[test]
    fn disposition_picks_worst_verdict() {
        let report = ScanReport {
            path: PathBuf::from("/tmp/x"),
            hashes: FileHashes::default(),
            verdicts: vec![
                Verdict::suspicious(EngineKind::Heuristic, "pe_high_entropy", 0.6),
                Verdict::malicious(EngineKind::Hash, "Win.Test.EICAR", 1.0),
            ],
            elapsed: Duration::from_millis(3),
        };
        assert_eq!(report.disposition(), ThreatLevel::Malicious);
        assert!(report.is_threat());
    }

    #[test]
    fn clean_report_is_not_a_threat() {
        let report = ScanReport {
            path: PathBuf::from("/tmp/x"),
            hashes: FileHashes::default(),
            verdicts: vec![],
            elapsed: Duration::ZERO,
        };
        assert_eq!(report.disposition(), ThreatLevel::Clean);
        assert!(!report.is_threat());
    }
}
