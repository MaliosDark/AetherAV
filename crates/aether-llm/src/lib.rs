//! `aether-llm` - a compact on-device LLM embedded as a detection engine.
//!
//! This is the novel layer: a tiny (~50M) model, fine-tuned on AetherAV's
//! classifier dataset, reads an artifact (a command line, a script, a behavior
//! summary) and emits a one-line verdict the scanner consumes. It runs on CPU
//! anywhere via a GGUF model + a llama.cpp-style runner - no GPU, no cloud.
//!
//! The crate is runner-agnostic and *inert by default*: with no model/runner
//! configured it produces no verdicts (the rest of the engine is unaffected).
//! The verdict **parser** is the deterministic, tested core; the model is just
//! a producer of `verdict | technique | reason` lines.

use aether_common::{EngineKind, ThreatLevel, Verdict};
use std::path::PathBuf;
use std::process::Command;

/// Configuration for the embedded model.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub enabled: bool,
    /// Runner executable, e.g. `llama-cli` (llama.cpp). Receives `-m <model> -p <prompt>`.
    pub runner: String,
    /// Path to the GGUF model file.
    pub model: PathBuf,
    /// Max tokens to generate (verdicts are short).
    pub max_tokens: u32,
    /// Truncate artifacts to this many chars before prompting (keeps it fast).
    pub max_chars: usize,
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            enabled: false,
            runner: "llama-completion".to_string(),
            model: PathBuf::from("assets/models/aegis-50m.gguf"),
            max_tokens: 48,
            max_chars: 1200,
        }
    }
}

/// The embedded classifier.
pub struct LlmClassifier {
    cfg: LlmConfig,
    available: bool,
}

impl LlmClassifier {
    pub fn new(cfg: LlmConfig) -> LlmClassifier {
        let available = cfg.enabled && cfg.model.exists();
        if cfg.enabled && !available {
            tracing::warn!(model = %cfg.model.display(), "LLM engine enabled but model not found; inert");
        }
        LlmClassifier { cfg, available }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    /// The instruction prompt - must mirror the training template so the model
    /// answers in the `Verdict | MITRE | reason` form the parser expects.
    fn prompt(&self, artifact: &str) -> String {
        let mut a = artifact.trim().to_string();
        if a.len() > self.cfg.max_chars {
            a.truncate(self.cfg.max_chars);
        }
        format!(
            "Classify this command line. Reply: verdict, MITRE technique (or -), one-line reason.\n{a}\n"
        )
    }

    /// Classify an artifact; returns a verdict only on malicious/suspicious.
    pub fn classify(&self, artifact: &str) -> Option<Verdict> {
        if !self.available {
            return None;
        }
        let out = Command::new(&self.cfg.runner)
            .arg("-m")
            .arg(&self.cfg.model)
            .args([
                "-n",
                &self.cfg.max_tokens.to_string(),
                "--temp",
                "0", // greedy -> deterministic verdicts
                "--no-display-prompt",
                "-p",
            ])
            .arg(self.prompt(artifact))
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        parse_verdict(&text)
    }
}

/// Parse a model completion into a [`Verdict`]. Scans for a
/// `Verdict | MITRE | reason` line; `benign`/`clean` yield `None`.
pub fn parse_verdict(output: &str) -> Option<Verdict> {
    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(3, '|').map(|s| s.trim()).collect();
        if parts.len() < 2 {
            continue;
        }
        let level = match parts[0].to_ascii_lowercase().as_str() {
            "malicious" => ThreatLevel::Malicious,
            "suspicious" => ThreatLevel::Suspicious,
            "benign" | "clean" => return None,
            _ => continue,
        };
        let mitre: Vec<String> = parts
            .get(1)
            .map(|m| {
                m.split([',', ' '])
                    .map(str::trim)
                    .filter(|t| t.starts_with('T') && t.len() >= 3)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let reason = parts
            .get(2)
            .copied()
            .unwrap_or("on-device model detection")
            // strip llama.cpp end-of-generation markers from the tail.
            .replace("[end of text]", "")
            .replace("</s>", "");
        let reason = reason.trim();
        return Some(Verdict {
            engine: EngineKind::Llm,
            level,
            signature: "aegis.classifier".to_string(),
            score: if level == ThreatLevel::Malicious {
                0.88
            } else {
                0.7
            },
            mitre,
            detail: Some(format!("Aegis-50M: {reason}")),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_malicious_verdict() {
        let v = parse_verdict("Malicious | T1059.001 | encoded PowerShell cradle").unwrap();
        assert_eq!(v.level, ThreatLevel::Malicious);
        assert_eq!(v.engine, EngineKind::Llm);
        assert_eq!(v.mitre, vec!["T1059.001".to_string()]);
        assert!(v.detail.unwrap().contains("PowerShell"));
    }

    #[test]
    fn parses_suspicious_and_ignores_prose() {
        let out = "loading model...\nSuspicious | T1071 | possible C2 beacon\n";
        let v = parse_verdict(out).unwrap();
        assert_eq!(v.level, ThreatLevel::Suspicious);
        assert_eq!(v.mitre, vec!["T1071".to_string()]);
    }

    #[test]
    fn benign_yields_no_verdict() {
        assert!(parse_verdict("Benign | - | developer activity").is_none());
        assert!(parse_verdict("no verdict line here").is_none());
    }

    #[test]
    fn handles_multiple_techniques() {
        let v =
            parse_verdict("Malicious | T1486, T1490 | ransomware + recovery inhibition").unwrap();
        assert_eq!(v.mitre, vec!["T1486".to_string(), "T1490".to_string()]);
    }

    #[test]
    fn inert_without_model() {
        let c = LlmClassifier::new(LlmConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(!c.is_available());
        assert!(c.classify("powershell -enc AAAA").is_none());
    }
}
