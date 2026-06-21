//! YARA-X engine wrapper.
//!
//! YARA-X is the pure-Rust rewrite of YARA - no libyara/C dependency, faster
//! compilation, and a safer scanning core. We compile every `.yar`/`.yara` file
//! under the configured rules directory into a single ruleset at startup and
//! reuse one compiled `Rules` object across all scanned files.

use aether_common::{Error, Result};
use std::path::Path;
use walkdir::WalkDir;

/// A compiled set of YARA rules ready to scan buffers.
pub struct YaraEngine {
    rules: yara_x::Rules,
    rule_count: usize,
}

impl YaraEngine {
    /// Compile rules from inline source (handy for tests and embedded defaults).
    pub fn from_source(source: &str) -> Result<YaraEngine> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| Error::Yara(format!("compile error: {e}")))?;
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        Ok(YaraEngine { rules, rule_count })
    }

    /// Like [`from_dir`](Self::from_dir) but caches the *compiled* ruleset to
    /// `cache` so subsequent startups deserialize it (≈instant) instead of
    /// recompiling thousands of rules (~15s). The cache is rebuilt automatically
    /// whenever any rule file is newer than it.
    pub fn from_dir_cached(dir: impl AsRef<Path>, cache: impl AsRef<Path>) -> Result<YaraEngine> {
        let dir = dir.as_ref();
        let cache = cache.as_ref();

        // Newest rule-file mtime under `dir` (0 if none).
        let newest = WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x.eq_ignore_ascii_case("yar") || x.eq_ignore_ascii_case("yara"))
                    .unwrap_or(false)
            })
            .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
            .max();

        // Use the cache if it exists and is at least as new as every rule file.
        if let (Ok(cm), Some(newest)) = (std::fs::metadata(cache), newest) {
            if cm.modified().map(|t| t >= newest).unwrap_or(false) {
                if let Ok(file) = std::fs::File::open(cache) {
                    match yara_x::Rules::deserialize_from(std::io::BufReader::new(file)) {
                        Ok(rules) => {
                            let rule_count = rules.iter().count();
                            tracing::info!(rules = rule_count, "loaded compiled YARA cache");
                            return Ok(YaraEngine { rules, rule_count });
                        }
                        Err(e) => tracing::warn!(error = %e, "YARA cache invalid; recompiling"),
                    }
                }
            }
        }

        // Compile fresh, then persist the compiled ruleset for next time.
        let engine = Self::from_dir(dir)?;
        if let Ok(file) = std::fs::File::create(cache) {
            if let Err(e) = engine.rules.serialize_into(std::io::BufWriter::new(file)) {
                tracing::warn!(error = %e, "failed to write YARA cache");
            }
        }
        Ok(engine)
    }

    /// Compile every `.yar`/`.yara` file found under `dir` (recursively).
    ///
    /// A missing directory is not fatal - it yields an engine with zero rules
    /// so a fresh install still runs the other engines.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<YaraEngine> {
        let dir = dir.as_ref();
        if !dir.exists() {
            tracing::warn!(path = %dir.display(), "yara rules directory not found; no rules loaded");
            return YaraEngine::from_source("");
        }

        let mut compiler = yara_x::Compiler::new();
        let (mut files, mut skipped) = (0usize, 0usize);
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            let is_rule = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
                .unwrap_or(false);
            if !entry.file_type().is_file() || !is_rule {
                continue;
            }
            let src = std::fs::read_to_string(path).map_err(|source| Error::Io {
                path: path.to_path_buf(),
                source,
            })?;
            // Fault-tolerant: validate each file with a throwaway compiler so a
            // single bad rule from a large community pack can't sink the set.
            // Only sources that compile cleanly are folded into the real engine.
            let mut probe = yara_x::Compiler::new();
            match probe.add_source(src.as_str()) {
                Ok(_) => {
                    let _ = compiler.add_source(src.as_str());
                    files += 1;
                }
                Err(e) => {
                    skipped += 1;
                    tracing::debug!(path = %path.display(), error = %e, "skipping uncompilable YARA file");
                }
            }
        }

        let rules = compiler.build();
        let rule_count = rules.iter().count();
        tracing::info!(files, skipped, rules = rule_count, "compiled YARA-X rules");
        Ok(YaraEngine { rules, rule_count })
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Scan a buffer; return the identifiers of every matching rule.
    ///
    /// A fresh `Scanner` is created per call so the engine is `Sync` and can be
    /// shared across rayon worker threads without locking.
    /// Returns each matching rule as `(identifier, severity)`. `severity` is the
    /// rule's `meta: severity = "..."` value (e.g. low/medium/high/critical),
    /// defaulting to `"high"` when absent. The caller maps it to a threat level
    /// so heuristic (medium/low) rules don't all read as outright malicious.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<(String, String)>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| Error::Yara(format!("scan error: {e}")))?;
        Ok(results
            .matching_rules()
            .map(|r| {
                let severity = r
                    .metadata()
                    .into_iter()
                    .find(|(k, _)| *k == "severity")
                    .and_then(|(_, v)| match v {
                        yara_x::MetaValue::String(s) => Some(s.to_string()),
                        _ => None,
                    })
                    .unwrap_or_else(|| "high".to_string());
                (r.identifier().to_string(), severity)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
rule contains_evil {
    strings:
        $a = "EVIL_PAYLOAD"
    condition:
        $a
}
"#;

    #[test]
    fn compiles_and_matches() {
        let engine = YaraEngine::from_source(RULE).unwrap();
        assert_eq!(engine.rule_count(), 1);

        let hits = engine.scan(b"prefix EVIL_PAYLOAD suffix").unwrap();
        // (rule, severity) - no severity meta declared -> defaults to "high".
        assert_eq!(
            hits,
            vec![("contains_evil".to_string(), "high".to_string())]
        );

        let clean = engine.scan(b"nothing to see here").unwrap();
        assert!(clean.is_empty());
    }

    #[test]
    fn bad_rule_is_an_error() {
        assert!(matches!(
            YaraEngine::from_source("rule broken { condition }"),
            Err(Error::Yara(_))
        ));
    }
}
