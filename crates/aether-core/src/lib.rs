//! `aether-core` - the scan orchestrator.
//!
//! Owns the loaded engines and runs each artifact through the Phase-1 pipeline:
//!
//! ```text
//!   bytes --▶ [hash] --hit?--▶ Malicious (stop, exact match wins)
//!     |
//!     +------▶ [YARA-X] -----▶ Malicious verdicts (rule matches)
//!     |
//!     +-format?-▶ [PE parse] -▶ [static heuristics] -▶ Suspicious verdict
//! ```
//!
//! The hash engine short-circuits because an exact signature match is the
//! highest-confidence, cheapest possible result. YARA and heuristics still run
//! for non-matches and contribute their own verdicts; the final disposition is
//! the worst level across all of them.

pub mod heuristics;

use aether_common::{EngineKind, Error, Result, ScanReport, ScanSummary, Verdict};
use aether_config::Config;
use aether_ml::MlEngine;
use aether_parsers::elf::ElfInfo;
use aether_parsers::macho::MachoInfo;
use aether_parsers::office::OfficeIndicators;
use aether_parsers::pdf::PdfIndicators;
use aether_parsers::script::ScriptIndicators;
use aether_parsers::{pe::PeInfo, FileFormat};
use aether_plugins::PluginRegistry;
use aether_signatures::hashdb::HashDb;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

#[cfg(feature = "yara")]
use aether_signatures::yara::YaraEngine;

/// A fully-initialized scanner: configuration plus every loaded engine.
///
/// Cheap to share by reference across threads (`scan` takes `&self`), which is
/// what the rayon-based [`Scanner::scan_path`] relies on.
pub struct Scanner {
    config: Config,
    hashdb: HashDb,
    #[cfg(feature = "yara")]
    yara: YaraEngine,
    /// ClamAV-style hex pattern engine (`.ndb`); empty if disabled/absent.
    ndb: aether_signatures::ndb::NdbEngine,
    /// TLSH fuzzy-hash variant database; empty if disabled/absent.
    tlsh: aether_signatures::fuzzy::TlshDb,
    /// Static-ML classifier; `None` if disabled or the model failed to load.
    ml: Option<MlEngine>,
    /// Third-party detector plugins (empty unless enabled).
    plugins: PluginRegistry,
    /// Threat-intel store for URL/domain/IP content matching (None if disabled).
    intel: Option<aether_intel::IntelStore>,
    /// On-device LLM classifier (inert unless a model is configured + present).
    llm: aether_llm::LlmClassifier,
    /// Results cache keyed by content SHA-256 -> (hashes, verdicts); skips
    /// re-scanning identical bytes (big win for on-access + repeat scans).
    cache: std::sync::Mutex<
        std::collections::HashMap<String, (aether_common::FileHashes, Vec<Verdict>)>,
    >,
    /// Optional reputation allowlist: returns `true` if a file's hashes are
    /// known-good (e.g. CIRCL hashlookup / NSRL). When set, it suppresses soft
    /// (heuristic/pattern/ML/LLM) verdicts on known-good files to cut false
    /// positives - but never overrides an exact malware-hash match.
    #[allow(clippy::type_complexity)]
    reputation: Option<Box<dyn Fn(&aether_common::FileHashes) -> bool + Send + Sync>>,
}

impl Scanner {
    /// Build a scanner from configuration, loading all enabled engines.
    pub fn new(config: Config) -> Result<Scanner> {
        // The three heavy engines (hash DB ~6s, compiled YARA ~6s, ClamAV
        // patterns ~8s) load independently - run them concurrently so startup is
        // the slowest single engine, not their sum (~20s -> ~8s). The hash DB and
        // pattern engine run on worker threads; YARA loads on the scope's own
        // thread (so `yara_x::Rules` needn't be `Send`).
        #[cfg(feature = "yara")]
        let mut yara_slot: Option<Result<YaraEngine>> = None;
        let (hashdb, ndb) = std::thread::scope(|sc| {
            let cfg = &config;
            let h = sc.spawn(move || -> Result<HashDb> {
                let db = if cfg.engines.hash {
                    HashDb::load(&cfg.engines.hash_db)?
                } else {
                    HashDb::empty()
                };
                tracing::info!(signatures = db.len(), "hash engine ready");
                Ok(db)
            });
            let n = sc.spawn(move || {
                if cfg.engines.ndb {
                    match aether_signatures::ndb::NdbEngine::from_file(&cfg.engines.ndb_db) {
                        Ok(e) => {
                            if !e.is_empty() {
                                tracing::info!(signatures = e.len(), "ClamAV pattern engine ready");
                            }
                            e
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "ClamAV .ndb load failed; pattern engine disabled");
                            aether_signatures::ndb::NdbEngine::empty()
                        }
                    }
                } else {
                    aether_signatures::ndb::NdbEngine::empty()
                }
            });
            // Compile/load YARA on this thread, concurrently with the workers.
            #[cfg(feature = "yara")]
            {
                yara_slot = Some(if cfg.engines.yara {
                    let cache = cfg.engines.yara_rules.join(".compiled.yarac");
                    YaraEngine::from_dir_cached(&cfg.engines.yara_rules, cache)
                } else {
                    YaraEngine::from_source("")
                });
            }
            (h.join().unwrap(), n.join().unwrap())
        });
        let hashdb = hashdb?;
        #[cfg(feature = "yara")]
        let yara = yara_slot.unwrap()?;

        // The ML model is best-effort: a missing/invalid model disables the
        // engine with a warning rather than refusing to scan.
        let ml = if config.engines.ml {
            match MlEngine::load(&config.engines.ml_model) {
                Ok(engine) => Some(engine),
                Err(e) => {
                    tracing::warn!(error = %e, "static-ML model unavailable; ML engine disabled");
                    None
                }
            }
        } else {
            None
        };

        let plugins = if config.engines.plugins {
            PluginRegistry::load_dir(&config.engines.plugins_dir).unwrap_or_default()
        } else {
            PluginRegistry::default()
        };
        if !plugins.is_empty() {
            tracing::info!(count = plugins.len(), "detector plugins loaded");
        }

        let intel = if config.engines.intel {
            match aether_intel::IntelStore::load_or_new(&config.engines.intel_store) {
                Ok(store) if !store.is_empty() => {
                    tracing::info!(iocs = store.len(), "threat-intel IOC matching ready");
                    Some(store)
                }
                _ => None,
            }
        } else {
            None
        };

        // TLSH fuzzy-variant DB (opt-in): absent file -> empty engine (no-op).
        let tlsh = if config.engines.tlsh {
            match std::fs::read_to_string(&config.engines.tlsh_db) {
                Ok(t) => {
                    let db = aether_signatures::fuzzy::TlshDb::from_text(&t);
                    if !db.is_empty() {
                        tracing::info!(variants = db.len(), "TLSH fuzzy-variant engine ready");
                    }
                    db
                }
                Err(_) => aether_signatures::fuzzy::TlshDb::new(),
            }
        } else {
            aether_signatures::fuzzy::TlshDb::new()
        };

        let llm = aether_llm::LlmClassifier::new(aether_llm::LlmConfig {
            enabled: config.engines.llm,
            runner: config.engines.llm_runner.clone(),
            model: config.engines.llm_model.clone(),
            server_url: config.engines.llm_server_url.clone(),
            ..Default::default()
        });
        if llm.is_available() {
            tracing::info!("on-device LLM classifier engine ready");
        }

        Ok(Scanner {
            config,
            hashdb,
            #[cfg(feature = "yara")]
            yara,
            ndb,
            tlsh,
            ml,
            plugins,
            intel,
            llm,
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            reputation: None,
        })
    }

    /// Attach a reputation allowlist (e.g. an online known-good lookup). Files
    /// it marks known-good have their soft verdicts suppressed (FP reduction);
    /// exact malware-hash matches are never overridden.
    #[allow(clippy::type_complexity)]
    pub fn with_reputation(
        mut self,
        f: Box<dyn Fn(&aether_common::FileHashes) -> bool + Send + Sync>,
    ) -> Self {
        self.reputation = Some(f);
        self
    }

    /// Whether the static-ML engine successfully loaded a model.
    pub fn ml_loaded(&self) -> bool {
        self.ml.is_some()
    }

    /// Whether the on-device LLM engine (Aegis-50M) is loaded and runnable.
    pub fn llm_loaded(&self) -> bool {
        self.llm.is_available()
    }

    /// Number of hash signatures currently loaded.
    pub fn signature_count(&self) -> usize {
        self.hashdb.len()
    }

    /// Number of compiled YARA-X rules (0 when built without the `yara` feature).
    pub fn yara_rule_count(&self) -> usize {
        #[cfg(feature = "yara")]
        {
            self.yara.rule_count()
        }
        #[cfg(not(feature = "yara"))]
        {
            0
        }
    }

    /// Scan a single in-memory buffer associated with `path` (used for the
    /// hot path, tests, and the future memory/stream scanner).
    pub fn scan_bytes(&self, path: &Path, data: &[u8]) -> ScanReport {
        if !self.config.scan.cache {
            return self.scan_bytes_depth(path, data, 0);
        }
        let key = aether_signatures::hash_bytes(data).sha256;
        if let Some((hashes, verdicts)) = self.cache.lock().unwrap().get(&key) {
            return ScanReport {
                path: path.to_path_buf(),
                hashes: hashes.clone(),
                verdicts: verdicts.clone(),
                elapsed: std::time::Duration::ZERO,
            };
        }
        let report = self.scan_bytes_depth(path, data, 0);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= 200_000 {
            cache.clear(); // simple bound; avoids unbounded growth on huge sweeps
        }
        cache.insert(key, (report.hashes.clone(), report.verdicts.clone()));
        report
    }

    fn scan_bytes_depth(&self, path: &Path, data: &[u8], depth: u32) -> ScanReport {
        let start = Instant::now();
        let hashes = aether_signatures::hash_bytes(data);
        let mut verdicts: Vec<Verdict> = Vec::new();

        // An empty file is never a threat - but its well-known hash erroneously
        // appears in some signature feeds, so short-circuit it to avoid a FP.
        if data.is_empty() {
            return ScanReport {
                path: path.to_path_buf(),
                hashes,
                verdicts,
                elapsed: start.elapsed(),
            };
        }

        // --- Engine 1: exact hash match (highest confidence, short-circuits) ---
        // Matches on SHA-256, MD5 or SHA-1 so ClamAV's MD5 DB and legacy IOCs hit.
        if self.config.engines.hash {
            if let Some(name) = self.hashdb.lookup_any(&hashes) {
                verdicts.push(
                    Verdict::malicious(EngineKind::Hash, name, 1.0)
                        .with_detail("exact hash signature match"),
                );
                return ScanReport {
                    path: path.to_path_buf(),
                    hashes,
                    verdicts,
                    elapsed: start.elapsed(),
                };
            }
        }

        // --- Engine 2: YARA-X pattern rules ---
        #[cfg(feature = "yara")]
        if self.config.engines.yara {
            match self.yara.scan(data) {
                Ok(hits) => {
                    for rule in hits {
                        verdicts.push(
                            Verdict::malicious(EngineKind::Yara, rule, 0.9)
                                .with_detail("YARA-X rule match"),
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e, path = %path.display(), "yara scan failed"),
            }
        }

        // File format - needed by the pattern engine (target typing) and the
        // heuristic/ML engines below.
        let format = FileFormat::detect(data);

        // --- Engine 2b: ClamAV-style hex pattern signatures (.ndb) ---
        // Respect the signature TargetType: a Windows-PE signature must not be
        // matched against a Linux ELF, etc. - this alone removes the bulk of
        // cross-format false positives.
        if self.config.engines.ndb {
            let target = match format {
                FileFormat::Pe => aether_signatures::ndb::TARGET_PE,
                FileFormat::Elf => aether_signatures::ndb::TARGET_ELF,
                FileFormat::MachO => aether_signatures::ndb::TARGET_MACHO,
                FileFormat::Script => aether_signatures::ndb::TARGET_ASCII,
                _ => aether_signatures::ndb::TARGET_ANY,
            };
            if let Some(name) = self.ndb.scan(data, target) {
                verdicts.push(
                    Verdict::malicious(EngineKind::Yara, format!("ClamAV.{name}"), 0.95)
                        .with_detail("ClamAV pattern signature match"),
                );
            }
        }

        // --- Engine 2c: TLSH fuzzy-hash variant match (catches polymorphic /
        // repacked relatives of known malware that exact hashes miss). The DB is
        // opt-in (empty by default); the distance threshold is conservative. ---
        if !self.tlsh.is_empty() {
            if let Some((name, dist)) = self.tlsh.nearest(data, 35) {
                verdicts.push(
                    Verdict::malicious(EngineKind::Hash, format!("Variant.{name}"), 0.9)
                        .with_detail(format!("TLSH variant match (distance {dist})")),
                );
            }
        }

        // --- Engines 3 & 4: format-aware static heuristics + static ML ---
        let threshold = self.config.scan.heuristic_threshold;
        let run_heur = self.config.engines.heuristics;

        match format {
            FileFormat::Pe => {
                // PE is the one format both heuristics and the ML model consume,
                // so parse once and feed both engines.
                match PeInfo::parse(data) {
                    Ok(pe) => {
                        if run_heur {
                            if let Some(v) = heuristics::analyze_pe(&pe, threshold) {
                                verdicts.push(v);
                            }
                        }
                        if let Some(ml) = &self.ml {
                            if let Some(v) = ml.classify_pe(&pe) {
                                verdicts.push(v);
                            }
                        }
                        // UPX: decompress with the system `upx` (if present) and
                        // scan the original bytes underneath the packer.
                        if pe.is_upx() && depth < self.config.scan.max_archive_depth {
                            if let Some(unpacked) = aether_unpack::external::upx_unpack(data) {
                                let sub = self.scan_bytes_depth(
                                    &path.join("[upx]"),
                                    &unpacked,
                                    depth + 1,
                                );
                                for mut v in sub.verdicts {
                                    v.signature = format!("upx->{}", v.signature);
                                    verdicts.push(v);
                                }
                            }
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "PE parse failed; skipping PE engines"),
                }
            }
            FileFormat::Elf if run_heur => {
                if let Ok(elf) = ElfInfo::parse(data) {
                    if let Some(v) = heuristics::analyze_elf(&elf, threshold) {
                        verdicts.push(v);
                    }
                }
            }
            FileFormat::MachO if run_heur => {
                if let Ok(m) = MachoInfo::parse(data) {
                    if let Some(v) = heuristics::analyze_macho(&m, threshold) {
                        verdicts.push(v);
                    }
                }
            }
            FileFormat::Pdf if run_heur => {
                if let Some(v) = heuristics::analyze_pdf(&PdfIndicators::scan(data), threshold) {
                    verdicts.push(v);
                }
            }
            // ZIP may be OOXML (.docm/.xlsm); OLE compound files (legacy .doc/
            // .xls) start with the D0CF11E0 magic and sniff as Unknown.
            FileFormat::Zip | FileFormat::Unknown
                if run_heur
                    && (format == FileFormat::Zip
                        || data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0])) =>
            {
                let office = OfficeIndicators::scan(data);
                if office.has_macros {
                    if let Some(v) = heuristics::analyze_office(&office, threshold) {
                        verdicts.push(v);
                    }
                }
            }
            FileFormat::Script if run_heur => {
                if let Some(v) =
                    heuristics::analyze_script(&ScriptIndicators::scan(data), threshold)
                {
                    verdicts.push(v);
                }
            }
            _ => {}
        }

        // --- Engine 5: third-party detector plugins ---
        if self.config.engines.plugins && !self.plugins.is_empty() {
            verdicts.extend(self.plugins.scan_all(data));
        }

        // --- Engine 7: threat-intel IOC matching (URLs / domains / IPs) ---
        if let Some(intel) = &self.intel {
            verdicts.extend(ioc_match(intel, data));
        }

        // --- Engine 8: dynamic sandbox / emulation (anti-evasion + shellcode) ---
        // Run on executables and on raw/unknown buffers (where shellcode hides),
        // bounded in size to keep the disassembly sweep cheap.
        if self.config.engines.sandbox
            && data.len() <= 4 * 1024 * 1024
            && matches!(format, FileFormat::Pe | FileFormat::Unknown)
        {
            let bitness = match format {
                FileFormat::Pe => match PeInfo::parse(data).map(|p| p.arch) {
                    Ok(aether_parsers::pe::Arch::X86) => aether_sandbox::Bitness::Bits32,
                    _ => aether_sandbox::Bitness::Bits64,
                },
                _ => aether_sandbox::Bitness::Bits64,
            };
            verdicts.extend(
                aether_sandbox::Sandbox::new()
                    .analyze(data, bitness)
                    .verdicts,
            );
        }

        // --- Engine 9: on-device LLM classifier (scripts / command-like text) ---
        // The novel layer: a compact fine-tuned model reads the artifact text and
        // emits a verdict. Inert unless a GGUF model is configured + present.
        if self.llm.is_available()
            && matches!(format, FileFormat::Script | FileFormat::Unknown)
            && data.len() <= 64 * 1024
        {
            if let Ok(text) = std::str::from_utf8(data) {
                // Only classify genuinely command/script-like content - never
                // arbitrary prose/notes/config - to keep the false-positive rate
                // low (the classifier is trained on command lines, not text).
                if looks_like_command(text) {
                    if let Some(v) = self.llm.classify(text) {
                        verdicts.push(v);
                    }
                }
            }
        }

        // --- Engine 6: container extraction (scan inside archives) ---
        if depth < self.config.scan.max_archive_depth {
            if let Some(members) =
                aether_unpack::try_extract(data, aether_unpack::Limits::default())
            {
                for m in members {
                    let member_path = path.join(&m.name);
                    let sub = self.scan_bytes_depth(&member_path, &m.data, depth + 1);
                    // Bubble member verdicts up, namespaced by the archive entry.
                    for mut v in sub.verdicts {
                        v.signature = format!("{}->{}", m.name, v.signature);
                        verdicts.push(v);
                    }
                }
            }
        }

        // Reputation allowlist (top level only): if a file is known-good and we
        // have no exact malware-hash match, suppress the soft verdicts that
        // produced the flag - the dominant source of false positives.
        if depth == 0 && !verdicts.is_empty() {
            if let Some(rep) = &self.reputation {
                let hard_malware = verdicts.iter().any(|v| {
                    v.engine == EngineKind::Hash && v.level == aether_common::ThreatLevel::Malicious
                });
                if !hard_malware && rep(&hashes) {
                    verdicts.clear();
                }
            }
        }

        ScanReport {
            path: path.to_path_buf(),
            hashes,
            verdicts,
            elapsed: start.elapsed(),
        }
    }

    /// Scan one file from disk, honoring the configured size limit.
    pub fn scan_file(&self, path: &Path) -> Result<ScanReport> {
        let meta = std::fs::metadata(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let limit = self.config.scan.max_file_size;
        if limit > 0 && meta.len() > limit {
            tracing::debug!(path = %path.display(), size = meta.len(), "skipping: over size limit");
            return Ok(ScanReport {
                path: path.to_path_buf(),
                hashes: aether_common::FileHashes {
                    size: meta.len(),
                    ..Default::default()
                },
                verdicts: vec![],
                elapsed: std::time::Duration::ZERO,
            });
        }

        // For large samples, memory-map to avoid copying the whole file into a
        // heap buffer (keeps RSS flat when scanning multi-hundred-MB files).
        // Small files and empty files take the simple read path (mmap of zero
        // length is invalid on some platforms).
        const MMAP_THRESHOLD: u64 = 2 * 1024 * 1024;
        if meta.len() >= MMAP_THRESHOLD {
            let file = std::fs::File::open(path).map_err(|source| Error::Io {
                path: path.to_path_buf(),
                source,
            })?;
            // SAFETY: the mapping is read-only and lives only for this call; we
            // never mutate it and drop it before returning the (owned) report.
            match unsafe { memmap2::Mmap::map(&file) } {
                Ok(mmap) => return Ok(self.scan_bytes(path, &mmap)),
                Err(e) => tracing::debug!(error = %e, "mmap failed; falling back to read"),
            }
        }

        let data = std::fs::read(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(self.scan_bytes(path, &data))
    }

    /// Scan a path: a single file, or a directory (parallel, optionally recursive).
    ///
    /// Returns every report plus an aggregate [`ScanSummary`]. Per-file errors
    /// are logged and counted, never abort the whole run.
    pub fn scan_path(&self, root: &Path) -> Result<(Vec<ScanReport>, ScanSummary)> {
        let start = Instant::now();
        let targets = self.collect_targets(root)?;
        tracing::info!(files = targets.len(), "starting scan");

        let reports: Vec<std::result::Result<ScanReport, ()>> = targets
            .par_iter()
            .map(|p| {
                self.scan_file(p).map_err(|e| {
                    tracing::warn!(error = %e, path = %p.display(), "scan error");
                })
            })
            .collect();

        let mut summary = ScanSummary::default();
        let mut ok = Vec::with_capacity(reports.len());
        for r in reports {
            match r {
                Ok(report) => {
                    summary.record(&report);
                    ok.push(report);
                }
                Err(()) => summary.errors += 1,
            }
        }
        summary.elapsed = start.elapsed();
        Ok((ok, summary))
    }

    /// Enumerate files under `root` according to the recursion setting.
    fn collect_targets(&self, root: &Path) -> Result<Vec<PathBuf>> {
        if root.is_file() {
            return Ok(vec![root.to_path_buf()]);
        }
        if !root.exists() {
            return Err(Error::Io {
                path: root.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "path not found"),
            });
        }

        let max_depth = if self.config.scan.recursive {
            usize::MAX
        } else {
            1
        };
        let targets = WalkDir::new(root)
            .max_depth(max_depth)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .collect();
        Ok(targets)
    }
}

/// Heuristic: does this text look like a command line / script (vs. prose,
/// notes, config, CSV)? Used to gate the LLM classifier so it never judges
/// arbitrary text - keeping its false-positive rate low. Permissive for real
/// commands/scripts, rejecting plain prose.
fn looks_like_command(text: &str) -> bool {
    let head: String = text.chars().take(8192).collect();
    let head = head.as_str();
    if head.trim_start().starts_with("#!") {
        return true; // shebang
    }
    let lower = head.to_ascii_lowercase();
    const TOKENS: &[&str] = &[
        "powershell",
        "cmd /c",
        "cmd.exe",
        "/bin/",
        "/usr/bin",
        "bash ",
        "sh -c",
        "-enc",
        "-encodedcommand",
        "iex",
        "invoke-",
        "downloadstring",
        "downloadfile",
        "webclient",
        "frombase64string",
        "new-object",
        "add-type",
        "start-process",
        "certutil",
        "bitsadmin",
        "rundll32",
        "regsvr32",
        "mshta",
        "wscript",
        "cscript",
        "wmic ",
        "schtasks",
        "reg add",
        "reg delete",
        "net user",
        "net localgroup",
        "vssadmin",
        "cipher /",
        "icacls",
        "takeown",
        "netsh ",
        "curl ",
        "wget ",
        "nc -",
        "ncat ",
        "/dev/tcp/",
        "base64 ",
        "eval(",
        "exec(",
        "system(",
        "shell_exec",
        "passthru(",
        "popen(",
        "os.system",
        "subprocess",
        "import socket",
        "createobject",
        "wscript.shell",
        "xmlhttp",
        "urldownloadtofile",
        "chmod +x",
        "$(",
        "${",
        ">&",
        "2>&1",
        "&&",
        "||",
        "|iex",
        "; ",
    ];
    if TOKENS.iter().any(|t| lower.contains(t)) {
        return true;
    }
    // Backtick command substitution or a pipe into another command.
    head.contains('`') || head.contains("| ")
}

/// Extract embedded URLs / domains / IPv4 indicators from `data` and match them
/// against the threat-intel store. Activates the non-hash IOCs (URLs/IPs/domains)
/// for file-content detection - e.g. a dropper carrying a known C2 URL.
fn ioc_match(intel: &aether_intel::IntelStore, data: &[u8]) -> Vec<Verdict> {
    use std::collections::HashSet;
    let cap = data.len().min(4 * 1024 * 1024); // bound cost on huge files
    let text = String::from_utf8_lossy(&data[..cap]);
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for url in find_urls(&text) {
        if let Some(t) = intel.lookup_url(&url) {
            if seen.insert(format!("u:{url}")) {
                out.push(intel_verdict("intel.url", t, &url));
            }
        }
        if let Some(host) = url_host(&url) {
            if let Some(t) = intel.lookup_domain(host) {
                if seen.insert(format!("d:{host}")) {
                    out.push(intel_verdict("intel.domain", t, host));
                }
            }
        }
    }
    for ip in find_ipv4(&text) {
        if let Some(t) = intel.lookup_ip(&ip) {
            if seen.insert(format!("i:{ip}")) {
                out.push(intel_verdict("intel.ip", t, &ip));
            }
        }
    }
    out
}

fn intel_verdict(signature: &str, threat: &str, value: &str) -> Verdict {
    Verdict {
        engine: EngineKind::Intel,
        level: aether_common::ThreatLevel::Malicious,
        signature: signature.to_string(),
        score: 0.95,
        mitre: vec!["T1071".to_string()],
        detail: Some(format!("known-malicious indicator {value} ({threat})")),
    }
}

/// Find `http(s)://…` URLs in text (terminated by whitespace/quotes/brackets).
fn find_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut i = 0;
    while let Some(pos) = text[i..].find("http") {
        let start = i + pos;
        let rest = &text[start..];
        if rest.starts_with("http://") || rest.starts_with("https://") {
            let end = rest
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '`' | ',' | '\\'
                        )
                })
                .unwrap_or(rest.len());
            if end > 10 {
                urls.push(rest[..end].to_string());
            }
            i = start + end.max(1);
        } else {
            i = start + 4;
        }
        if urls.len() > 2000 {
            break;
        }
    }
    urls
}

/// Host portion of a URL.
fn url_host(url: &str) -> Option<&str> {
    let s = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host = s.split(['/', ':', '?', '#']).next()?;
    (!host.is_empty()).then_some(host)
}

/// Find IPv4 literals in text.
fn find_ipv4(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
        {
            out.push(tok.to_string());
        }
        if out.len() > 5000 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_config() -> Config {
        // Disable on-disk engine assets so tests are hermetic; heuristics on.
        let mut cfg = Config::default();
        cfg.engines.hash = false;
        cfg.engines.yara = false;
        cfg.engines.heuristics = true;
        cfg
    }

    #[test]
    fn full_pipeline_never_panics_on_hostile_input() {
        // Hermetic engine (heuristics + archive recursion + ioc paths on,
        // on-disk DBs off). The whole scan path must survive any input.
        let scanner = Scanner::new(test_config()).unwrap();
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let magics: &[&[u8]] = &[b"MZ", b"\x7fELF", b"%PDF", b"PK\x03\x04", &[0x1f, 0x8b]];
        for i in 0..1500u64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 4096) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|j| (seed.wrapping_mul(j as u64 + 1) & 0xff) as u8)
                .collect();
            if len > 8 {
                let m = magics[(i as usize) % magics.len()];
                let n = m.len().min(buf.len());
                buf[..n].copy_from_slice(&m[..n]);
            }
            let _ = scanner.scan_bytes(Path::new("fuzz"), &buf);
        }
    }

    #[test]
    fn clean_buffer_yields_clean_report() {
        let scanner = Scanner::new(test_config()).unwrap();
        let report = scanner.scan_bytes(Path::new("hello.txt"), b"just some text");
        assert!(!report.is_threat());
        assert_eq!(report.hashes.size, 14);
    }

    #[test]
    fn hash_engine_detects_known_sample() {
        let mut cfg = test_config();
        cfg.engines.hash = true;
        // Point at a temp DB containing the hash of our payload.
        let payload = b"malware-sample-bytes";
        let h = aether_signatures::hash_bytes(payload);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{} Test.Malware", h.sha256).unwrap();
        cfg.engines.hash_db = f.path().to_path_buf();

        let scanner = Scanner::new(cfg).unwrap();
        let report = scanner.scan_bytes(Path::new("x.bin"), payload);
        assert_eq!(report.disposition(), aether_common::ThreatLevel::Malicious);
        assert_eq!(report.verdicts[0].signature, "Test.Malware");
    }

    #[test]
    fn detects_malware_inside_zip() {
        use std::io::Cursor;
        let payload = b"zip-member-malware-bytes";
        let h = aether_signatures::hash_bytes(payload);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{} Zip.Member.Malware", h.sha256).unwrap();

        let mut cfg = test_config();
        cfg.engines.hash = true;
        cfg.engines.hash_db = f.path().to_path_buf();

        // Build a zip containing the malicious member.
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            w.start_file("evil.bin", zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(payload).unwrap();
            w.finish().unwrap();
        }
        let zip_bytes = buf.into_inner();

        let scanner = Scanner::new(cfg).unwrap();
        let report = scanner.scan_bytes(Path::new("archive.zip"), &zip_bytes);
        assert_eq!(report.disposition(), aether_common::ThreatLevel::Malicious);
        // The member verdict is namespaced by the archive entry name.
        assert!(report
            .verdicts
            .iter()
            .any(|v| v.signature == "evil.bin->Zip.Member.Malware"));
    }

    #[test]
    fn detects_known_malicious_url_and_ip_in_content() {
        use aether_intel::{Feed, IntelStore, Ioc, IocKind};
        let mut store = IntelStore::new();
        let feed = Feed::new(
            1,
            vec![
                Ioc {
                    kind: IocKind::Url,
                    value: "http://evil.example/c2".into(),
                    threat: "C2.Test".into(),
                },
                Ioc {
                    kind: IocKind::Ipv4,
                    value: "45.9.1.2".into(),
                    threat: "Bot.Test".into(),
                },
            ],
        );
        store.apply(&feed, None).unwrap();
        let f = tempfile::NamedTempFile::new().unwrap();
        store.save(f.path()).unwrap();

        let mut cfg = test_config();
        cfg.engines.intel = true;
        cfg.engines.intel_store = f.path().to_path_buf();
        let scanner = Scanner::new(cfg).unwrap();

        let content = b"dropper config: beacon http://evil.example/c2 then fallback 45.9.1.2:8443";
        let report = scanner.scan_bytes(Path::new("sample.bin"), content);
        assert_eq!(report.disposition(), aether_common::ThreatLevel::Malicious);
        assert!(report.verdicts.iter().any(|v| v.signature == "intel.url"));
        assert!(report.verdicts.iter().any(|v| v.signature == "intel.ip"));
    }

    #[test]
    fn archive_recursion_is_depth_limited() {
        let mut cfg = test_config();
        cfg.scan.max_archive_depth = 0; // unpacking disabled
        let scanner = Scanner::new(cfg).unwrap();
        // A zip with max_archive_depth=0 is just scanned as opaque bytes.
        let report = scanner.scan_bytes(Path::new("a.zip"), b"PK\x03\x04 not really unpacked");
        assert!(!report.is_threat());
    }

    #[test]
    fn directory_scan_counts_files() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), b"clean").unwrap();
        }
        let scanner = Scanner::new(test_config()).unwrap();
        let (reports, summary) = scanner.scan_path(dir.path()).unwrap();
        assert_eq!(reports.len(), 3);
        assert_eq!(summary.scanned, 3);
        assert_eq!(summary.clean, 3);
    }
}
