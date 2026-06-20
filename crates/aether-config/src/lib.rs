//! Layered configuration for AetherAV.
//!
//! Resolution order (lowest -> highest precedence):
//!   1. Built-in defaults (`Config::default`)
//!   2. A TOML file (`--config` / `aether.toml`)
//!   3. (future) environment overrides handled at the CLI layer
//!
//! Every field has a sane default so a zero-config `aether scan <file>` works.

use aether_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level configuration document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub engines: EngineConfig,
    pub scan: ScanConfig,
    pub logging: LoggingConfig,
    pub update: UpdateConfig,
}

/// Automatic signed-feed updates, so detection never falls behind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    /// Enable automatic background updates.
    pub enabled: bool,
    /// URL of the Ed25519-signed feed JSON to pull (must be HTTPS in production).
    pub url: String,
    /// URL of the signed model manifest (`aegis.manifest.json`) for AI updates.
    pub model_url: String,
    /// How often to check, in hours.
    pub interval_hours: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig {
            enabled: true,
            url: String::new(),       // set to your published signed-feed URL
            model_url: String::new(), // set to your published model manifest URL
            interval_hours: 1,
        }
    }
}

/// Which detection engines are enabled and where their data lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    /// Enable the SHA-256 hash-database engine.
    pub hash: bool,
    /// Path to the hash signature database (`<hex sha256> <name>` per line).
    pub hash_db: PathBuf,
    /// Enable the YARA-X engine.
    pub yara: bool,
    /// Directory containing `.yar` / `.yara` rule files (scanned recursively).
    pub yara_rules: PathBuf,
    /// Enable the ClamAV-style hex pattern engine (`.ndb` body signatures).
    pub ndb: bool,
    /// Path to a ClamAV-style `.ndb` signature file.
    pub ndb_db: PathBuf,
    /// Enable TLSH fuzzy-hash variant detection (catches polymorphic relatives).
    pub tlsh: bool,
    /// Path to a TLSH database (`TLSH_HASH threat` per line). Opt-in: absent = off.
    pub tlsh_db: PathBuf,
    /// Enable static heuristics (entropy, packer hints, anomalous PE).
    pub heuristics: bool,
    /// Enable the static machine-learning classifier.
    pub ml: bool,
    /// Path to the static-ML model (JSON logistic model).
    pub ml_model: PathBuf,
    /// Enable third-party detector plugins.
    pub plugins: bool,
    /// Directory of plugin manifests (`*.toml`).
    pub plugins_dir: PathBuf,
    /// Enable threat-intel IOC matching (URLs / domains / IPs in content).
    pub intel: bool,
    /// Path to the threat-intel store (JSON).
    pub intel_store: PathBuf,
    /// Enable the dynamic sandbox / emulation engine (anti-evasion + shellcode).
    pub sandbox: bool,
    /// Enable the online reputation allowlist (CIRCL hashlookup) to suppress
    /// false positives on known-good files. Off by default (keeps scans offline).
    pub reputation: bool,
    /// Enable the on-device LLM classifier engine (needs a GGUF model + runner).
    pub llm: bool,
    /// Runner executable for the LLM (e.g. `llama-cli`).
    pub llm_runner: String,
    /// Path to the GGUF model.
    pub llm_model: PathBuf,
    /// Optional persistent llama.cpp server URL (e.g. `http://127.0.0.1:8080`).
    /// When set, classifications are sent to the already-loaded server instead
    /// of spawning a fresh process per artifact - far better on slow/HDD hosts.
    #[serde(default)]
    pub llm_server_url: String,
}

/// Behavior of a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Recurse into directories.
    pub recursive: bool,
    /// Skip files larger than this many bytes (0 = no limit). Default 256 MiB.
    pub max_file_size: u64,
    /// Worker threads for parallel scanning (0 = one per logical core).
    pub threads: usize,
    /// Suspicion score in `[0,1]` at/above which heuristics flag a file.
    pub heuristic_threshold: f32,
    /// Maximum recursion depth when scanning inside archives (0 = don't unpack).
    pub max_archive_depth: u32,
    /// Cache results by content hash to skip re-scanning identical files.
    pub cache: bool,
}

/// Logging preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `RUST_LOG`-style directive, e.g. `info` or `aether_core=debug`.
    pub level: String,
    /// Emit JSON logs (for the daemon) instead of pretty console output.
    pub json: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            hash: true,
            hash_db: PathBuf::from("assets/signatures/hashes.db"),
            yara: true,
            yara_rules: PathBuf::from("assets/rules"),
            ndb: true,
            ndb_db: PathBuf::from("assets/signatures/patterns.ndb"),
            tlsh: true,
            tlsh_db: PathBuf::from("assets/signatures/tlsh.db"),
            heuristics: true,
            ml: true,
            ml_model: PathBuf::from("assets/models/pe.json"),
            plugins: false,
            plugins_dir: PathBuf::from("assets/plugins"),
            intel: true,
            intel_store: PathBuf::from("assets/models/intel.json"),
            sandbox: true,
            reputation: false,
            llm: false,
            llm_runner: "llama-completion".to_string(),
            llm_model: PathBuf::from("assets/models/aegis-50m.gguf"),
            llm_server_url: String::new(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            recursive: false,
            max_file_size: 256 * 1024 * 1024,
            threads: 0,
            heuristic_threshold: 0.75,
            max_archive_depth: 3,
            cache: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level: "info".to_string(),
            json: false,
        }
    }
}

impl Config {
    /// Load configuration from a TOML file. Unknown keys are rejected so typos
    /// surface loudly instead of being silently ignored.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| Error::Config(e.to_string()))
    }

    /// Load from `path` if it exists, otherwise return built-in defaults.
    pub fn load_or_default(path: Option<impl AsRef<Path>>) -> Result<Self> {
        match path {
            Some(p) if p.as_ref().exists() => Self::from_path(p),
            _ => Ok(Self::default()),
        }
    }

    /// Render the current configuration back to TOML (used by `aether config init`).
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_coherent() {
        let cfg = Config::default();
        assert!(cfg.engines.hash);
        assert!(cfg.engines.yara);
        assert_eq!(cfg.scan.max_file_size, 256 * 1024 * 1024);
        assert!((0.0..=1.0).contains(&cfg.scan.heuristic_threshold));
    }

    #[test]
    fn roundtrips_through_toml() {
        let cfg = Config::default();
        let text = cfg.to_toml().unwrap();
        let parsed = Config::from_toml(&text).unwrap();
        assert_eq!(parsed.engines.hash, cfg.engines.hash);
        assert_eq!(parsed.scan.threads, cfg.scan.threads);
    }

    #[test]
    fn partial_toml_fills_in_defaults() {
        let parsed = Config::from_toml("[scan]\nrecursive = true\n").unwrap();
        assert!(parsed.scan.recursive);
        // Untouched fields keep their defaults.
        assert!(parsed.engines.yara);
        assert_eq!(parsed.logging.level, "info");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_toml("[scan]\nnope = 1\n").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn load_or_default_without_file() {
        let cfg = Config::load_or_default(None::<&str>).unwrap();
        assert!(cfg.engines.heuristics);
    }
}
