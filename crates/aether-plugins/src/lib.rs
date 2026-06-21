//! `aether-plugins` - third-party detector plugins without recompiling the core.
//!
//! A plugin is any executable that speaks a tiny stdin/stdout JSON protocol:
//! the engine writes the sample bytes to the plugin's **stdin**, and the plugin
//! writes a JSON object to **stdout**:
//!
//! ```json
//! { "verdicts": [
//!     { "signature": "MyRule.Foo", "level": "malicious", "score": 0.9,
//!       "detail": "matched X", "mitre": ["T1059"] }
//! ] }
//! ```
//!
//! Plugins are declared by TOML manifests in a plugins directory:
//!
//! ```toml
//! name = "yextend"
//! command = "/usr/local/bin/my-detector"
//! args = ["--scan"]
//! enabled = true
//! ```
//!
//! This keeps the trust boundary explicit (the engine only runs declared
//! executables) and language-agnostic (write detectors in anything). Each call
//! is isolated to a child process; a future revision adds resource limits.

use aether_common::{EngineKind, Error, Result, ThreatLevel, Verdict};
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// A declared plugin.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// The plugin's stdout schema.
#[derive(Debug, Deserialize)]
struct PluginOutput {
    #[serde(default)]
    verdicts: Vec<PluginVerdict>,
}

#[derive(Debug, Deserialize)]
struct PluginVerdict {
    signature: String,
    #[serde(default)]
    level: String,
    #[serde(default)]
    score: f32,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    mitre: Vec<String>,
}

fn parse_level(s: &str) -> ThreatLevel {
    match s.to_ascii_lowercase().as_str() {
        "malicious" => ThreatLevel::Malicious,
        "suspicious" => ThreatLevel::Suspicious,
        _ => ThreatLevel::Clean,
    }
}

impl PluginManifest {
    /// Run this plugin against `data`, returning the verdicts it reports.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<Verdict>> {
        let mut child = aether_common::quiet_command(&self.command)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Config(format!("plugin '{}' spawn failed: {e}", self.name)))?;

        // Stream the sample to the plugin's stdin, then close it.
        child
            .stdin
            .take()
            .ok_or_else(|| Error::Config("plugin stdin unavailable".into()))?
            .write_all(data)
            .map_err(|e| Error::Config(format!("plugin '{}' write failed: {e}", self.name)))?;

        let output = child
            .wait_with_output()
            .map_err(|e| Error::Config(format!("plugin '{}' wait failed: {e}", self.name)))?;

        let parsed: PluginOutput = serde_json::from_slice(&output.stdout)
            .map_err(|e| Error::Config(format!("plugin '{}' bad output: {e}", self.name)))?;

        Ok(parsed
            .verdicts
            .into_iter()
            .map(|v| Verdict {
                engine: EngineKind::Plugin,
                level: parse_level(&v.level),
                // Namespace the signature with the plugin name for provenance.
                signature: format!("{}:{}", self.name, v.signature),
                score: v.score,
                mitre: v.mitre,
                detail: v.detail,
            })
            .collect())
    }
}

/// A collection of loaded plugins.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<PluginManifest>,
}

impl PluginRegistry {
    /// Load every `*.toml` manifest under `dir`. A missing directory yields an
    /// empty registry (plugins are optional).
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<PluginRegistry> {
        let dir = dir.as_ref();
        let mut plugins = Vec::new();
        if !dir.exists() {
            return Ok(PluginRegistry { plugins });
        }
        let entries = std::fs::read_dir(dir).map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            let manifest: PluginManifest = toml::from_str(&text)
                .map_err(|e| Error::Config(format!("plugin manifest {}: {e}", path.display())))?;
            plugins.push(manifest);
        }
        tracing::info!(count = plugins.len(), "loaded plugins");
        Ok(PluginRegistry { plugins })
    }

    /// Construct from explicit manifests (tests / embedding).
    pub fn from_manifests(plugins: Vec<PluginManifest>) -> PluginRegistry {
        PluginRegistry { plugins }
    }

    pub fn len(&self) -> usize {
        self.plugins.iter().filter(|p| p.enabled).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run all enabled plugins against `data`, aggregating their verdicts.
    /// A failing plugin is logged and skipped - it never breaks the scan.
    pub fn scan_all(&self, data: &[u8]) -> Vec<Verdict> {
        let mut out = Vec::new();
        for p in self.plugins.iter().filter(|p| p.enabled) {
            match p.scan(data) {
                Ok(mut v) => out.append(&mut v),
                Err(e) => tracing::warn!(plugin = %p.name, error = %e, "plugin failed"),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest() {
        let m: PluginManifest = toml::from_str(
            r#"name = "demo"
               command = "/bin/echo"
               args = ["hi"]"#,
        )
        .unwrap();
        assert_eq!(m.name, "demo");
        assert!(m.enabled); // defaults to true
    }

    // Subprocess plugins use a shell script; gate on Unix.
    #[cfg(unix)]
    #[test]
    fn runs_a_subprocess_plugin() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("detector.sh");
        // Plugin: if stdin contains "EVIL", report a malicious verdict.
        std::fs::write(
            &script,
            r#"#!/bin/sh
input=$(cat)
case "$input" in
  *EVIL*) echo '{"verdicts":[{"signature":"Demo.Evil","level":"malicious","score":1.0,"detail":"found EVIL"}]}' ;;
  *) echo '{"verdicts":[]}' ;;
esac
"#,
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let registry = PluginRegistry::from_manifests(vec![PluginManifest {
            name: "demo".into(),
            command: script.to_string_lossy().into_owned(),
            args: vec![],
            enabled: true,
        }]);

        let hits = registry.scan_all(b"this is EVIL content");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].signature, "demo:Demo.Evil");
        assert_eq!(hits[0].level, ThreatLevel::Malicious);
        assert_eq!(hits[0].engine, EngineKind::Plugin);

        let clean = registry.scan_all(b"harmless");
        assert!(clean.is_empty());
    }
}
