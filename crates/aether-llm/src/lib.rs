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
    /// Optional persistent llama.cpp server URL (e.g. `http://127.0.0.1:8080`).
    /// When set, classify a prompt over HTTP against the already-loaded server
    /// instead of spawning a fresh process per artifact - the model is read from
    /// disk once, so it's far better on slow/HDD hosts (no per-call re-init).
    pub server_url: String,
    /// Auto-disable the LLM on low-end hosts (few CPU cores / little RAM), where
    /// CPU inference would hurt scan latency. The other engines keep protecting.
    pub auto_tune: bool,
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            enabled: false,
            runner: "llama-completion".to_string(),
            model: PathBuf::from("assets/models/aegis-50m.gguf"),
            max_tokens: 48,
            max_chars: 1200,
            server_url: String::new(),
            auto_tune: true,
        }
    }
}

/// Heuristic for a low-end host where on-device CPU inference would hurt UX:
/// a single CPU core, or under ~2 GB of RAM. Best-effort and cheap; returns a
/// human-readable reason when the LLM should be skipped. RAM check is Linux-only
/// (`/proc/meminfo`); elsewhere it relies on the core count.
pub fn host_is_low_end() -> Option<String> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if cores < 2 {
        return Some(format!("only {cores} CPU core"));
    }
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        let mem_kb = s
            .lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok());
        if let Some(kb) = mem_kb {
            if kb < 2_000_000 {
                return Some(format!("{} MB RAM", kb / 1024));
            }
        }
    }
    None
}

/// The embedded classifier.
pub struct LlmClassifier {
    cfg: LlmConfig,
    available: bool,
}

impl LlmClassifier {
    pub fn new(cfg: LlmConfig) -> LlmClassifier {
        // A persistent server doesn't need the model file locally; the CLI path does.
        let has_backend = !cfg.server_url.is_empty() || cfg.model.exists();
        let mut available = cfg.enabled && has_backend;
        if cfg.enabled && !has_backend {
            tracing::warn!(model = %cfg.model.display(), "LLM engine enabled but no model/server; inert");
        }
        // Auto-tune: on a weak host, skip CPU inference so scans stay snappy.
        if available && cfg.auto_tune && cfg.server_url.is_empty() {
            if let Some(why) = host_is_low_end() {
                tracing::info!(reason = %why, "LLM auto-disabled on low-end host (other engines stay active)");
                available = false;
            }
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
    /// Uses the persistent server when configured, else spawns the CLI runner.
    pub fn classify(&self, artifact: &str) -> Option<Verdict> {
        if !self.available {
            return None;
        }
        let text = if self.cfg.server_url.is_empty() {
            self.classify_cli(artifact)?
        } else {
            self.classify_server(artifact)?
        };
        parse_verdict(&text)
    }

    /// Spawn a fresh llama.cpp process for one classification (no server).
    fn classify_cli(&self, artifact: &str) -> Option<String> {
        let out = aether_common::quiet_command(&self.cfg.runner)
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
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Send the prompt to a persistent llama.cpp server (`/completion`). The
    /// model stays resident, so there is no per-call load - ideal on HDDs.
    fn classify_server(&self, artifact: &str) -> Option<String> {
        let url = format!("{}/completion", self.cfg.server_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "prompt": self.prompt(artifact),
            "n_predict": self.cfg.max_tokens,
            "temperature": 0.0,
            "stop": ["\n", "[end of text]", "</s>"],
        });
        let resp = ureq::post(&url)
            .timeout(std::time::Duration::from_secs(20))
            .send_json(body)
            .ok()?;
        let v: serde_json::Value = resp.into_json().ok()?;
        v.get("content").and_then(|c| c.as_str()).map(str::to_string)
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
