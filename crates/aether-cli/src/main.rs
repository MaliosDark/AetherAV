//! `aether` - the AetherAV command-line interface.
//!
//! Phase 1 surface:
//!   aether scan <path> [--recursive] [--json]   scan a file or directory
//!   aether config init [--output aether.toml]   write a default config file
//!   aether info                                 show engine/build status

use aether_common::logging::{self, LogFormat};
use aether_common::ThreatLevel;
use aether_config::Config;
use aether_core::Scanner;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

/// Top-level CLI definition.
#[derive(Debug, Parser)]
#[command(
    name = "aether",
    version,
    about = "AetherAV - a modern, modular open-source antivirus engine.",
    propagate_version = true
)]
struct Cli {
    /// Path to a TOML config file (defaults are used when omitted).
    #[arg(long, short = 'c', global = true, env = "AETHER_CONFIG")]
    config: Option<PathBuf>,

    /// Override log verbosity (`error`,`warn`,`info`,`debug`,`trace`).
    #[arg(long, global = true, env = "AETHER_LOG")]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a file or directory for threats.
    Scan(ScanArgs),
    /// Analyze a behavioral event trace (JSON) for malicious activity.
    Behavior(BehaviorArgs),
    /// Statically emulate a code buffer (shellcode) for anti-evasion / shellcode tells.
    Emulate(EmulateArgs),
    /// Online-learn a per-host behavioral baseline from an event trace.
    Learn(BaselineArgs),
    /// Score an event trace for anomalies against a learned baseline.
    Anomaly(BaselineArgs),
    /// Manage the encrypted quarantine vault.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Manage threat-intel feeds and updates.
    #[command(subcommand)]
    Intel(IntelCmd),
    /// Auto-update: pull the latest Ed25519-signed feed, verify + apply it (--watch to stay current forever).
    Update(UpdateArgs),
    /// Update the on-device AI model (Aegis): pull the signed model manifest, verify, and atomically swap it in.
    ModelUpdate(ModelUpdateArgs),
    /// Run the daemon: expose the engine over an HTTP/JSON API.
    Serve(ServeArgs),
    /// Real-time monitor: stream live process events into the behavioral engines.
    Monitor(MonitorArgs),
    /// Real-time on-access protection: scan files as they are created/modified in a directory.
    Watch(WatchArgs),
    /// Kernel-level on-access protection (Linux fanotify): block malicious opens/execs before they run (needs root).
    Protect(ProtectArgs),
    /// Scan live process memory for injected / fileless code (W^X regions, unbacked executable maps).
    Memscan(MemscanArgs),
    /// Process Sentinel: detect NEW/unknown running apps (by hash, name-agnostic) + hidden (rootkit) processes.
    Sentinel(SentinelArgs),
    /// Ransomware shield: snapshot a folder, plant canaries, and roll back on attack.
    Ransomguard(RansomguardArgs),
    /// Self-protection integrity check: verify (or --write) a manifest of critical files.
    Selfcheck(SelfcheckArgs),
    /// Inspect live TCP connections and flag malware-associated ports.
    Netscan,
    /// Watch outbound DNS queries and flag lookups of known-bad domains (needs `--features pcap` + root).
    Dnswatch,
    /// Threat firewall: block malicious IPs/ports via the OS native firewall (nftables/netsh/pf). Render or --apply.
    Firewall(FirewallArgs),
    /// Web/phishing protection: sinkhole malicious domains in the OS hosts file. Render or --apply.
    Webprotect(WebprotectArgs),
    /// Stealer shield: plant wallet/credential decoys and block processes that read them or enumerate secrets.
    Stealerguard(StealerguardArgs),
    /// Clipboard guard: detect crypto-address hijackers ("clippers") and restore the original address.
    Clipguard(ClipguardArgs),
    /// Scan a file for exploit-staging indicators (NOP sleds, heap spray, stack pivots, egg-hunters).
    Exploitscan(ExploitscanArgs),
    /// VirusTotal-contributor scan: one file, detection name on stdout, exit 1=infected / 0=clean.
    VtScan(VtScanArgs),
    /// Print a file's TLSH fuzzy hash (use to build a variant database: `<hash> <threat>`).
    Tlsh(TlshArgs),
    /// Print a PE file's import hash (imphash) for malware-family clustering.
    Imphash(TlshArgs),
    /// Check a file for timestomping (faked timestamps; MITRE T1070.006).
    Timestomp(TlshArgs),
    /// Evaluate detection quality (TP/FP/FN/TN, precision/recall/FPR) on labeled dirs.
    Eval(EvalArgs),
    /// Cloud reputation: check a file/hash against CIRCL hashlookup (40B+ known files, free, no key).
    Reputation(ReputationArgs),
    /// Vulnerability intel: look up a CVE via CIRCL CVE-Search (free, no key).
    Cve(CveArgs),
    /// [Publisher, offline] Ed25519-sign an intel feed with the private key.
    Feedsign(FeedsignArgs),
    /// Verify an intel feed against the compiled-in trusted public key (what clients do).
    Feedverify(FeedverifyArgs),
    /// Opt-in: submit a detected threat's hashes/IOCs (anonymous) to improve the shared DB.
    Submit(SubmitArgs),
    /// [Publisher, offline] Ed25519-sign a release artifact (e.g. SHA256SUMS) -> <file>.sig.
    Signfile(SignfileArgs),
    /// Verify a release artifact's detached signature against the trusted public key.
    Verifyfile(VerifyfileArgs),
    /// Configuration helpers.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Show engine status and build information.
    Info,
}

#[derive(Debug, Subcommand)]
enum QuarantineCmd {
    /// List quarantined items (incident timeline).
    List {
        #[arg(long, default_value = "quarantine")]
        vault: PathBuf,
    },
    /// Restore a quarantined item by id to a destination path.
    Restore {
        id: String,
        dest: PathBuf,
        #[arg(long, default_value = "quarantine")]
        vault: PathBuf,
    },
    /// Export indicators of compromise (CSV) for the vault.
    Iocs {
        #[arg(long, default_value = "quarantine")]
        vault: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum IntelCmd {
    /// Import an external feed file (ThreatFox CSV / SHA-256 list / MISP JSON) into the store.
    Import {
        file: PathBuf,
        /// Source format.
        #[arg(long, default_value = "threatfox", value_parser = ["threatfox", "sha256", "misp", "urlhaus", "feodo", "malwarebazaar", "iplist", "domainlist"])]
        format: String,
        #[arg(long, default_value = "assets/models/intel.json")]
        store: PathBuf,
        /// Threat label for formats without one (sha256/misp).
        #[arg(long, default_value = "Imported.IOC")]
        threat: String,
        /// Feed version (monotonic).
        #[arg(long, default_value_t = 1)]
        feed_version: u64,
    },
    /// Apply a feed (delta update) to the intel store, optionally verifying its MAC.
    Apply {
        feed: PathBuf,
        #[arg(long, default_value = "assets/models/intel.json")]
        store: PathBuf,
        /// Hex shared key to verify the feed signature (rejects on mismatch).
        #[arg(long)]
        key: Option<String>,
    },
    /// Export the store's SHA-256 indicators to hash-DB format (for hot reload).
    ExportHashdb {
        #[arg(long, default_value = "assets/models/intel.json")]
        store: PathBuf,
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
    /// Export the store as an (unsigned) feed JSON, ready for `feedsign` + publish.
    ExportFeed {
        #[arg(long, default_value = "assets/models/intel.json")]
        store: PathBuf,
        #[arg(long, short = 'o')]
        output: PathBuf,
        /// Feed version (must increase each publish). Defaults to the current unix time.
        #[arg(long = "feed-version")]
        feed_version: Option<u64>,
    },
}

#[derive(Debug, Args)]
struct BehaviorArgs {
    /// Path to a JSON event trace (array of behavioral events).
    trace: PathBuf,
    /// Emit machine-readable JSON instead of a human report.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct EmulateArgs {
    /// Path to a raw code buffer (e.g. extracted shellcode).
    file: PathBuf,
    /// Code bitness.
    #[arg(long, default_value = "64", value_parser = ["32", "64"])]
    arch: String,
}

#[derive(Debug, Args)]
struct BaselineArgs {
    /// JSON event trace to learn from / score.
    trace: PathBuf,
    /// Path to the persisted baseline model (created on first learn).
    #[arg(long, short = 'm', default_value = "assets/models/baseline.json")]
    model: PathBuf,
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// File or directory to scan.
    path: PathBuf,
    /// Recurse into subdirectories.
    #[arg(long, short = 'r')]
    recursive: bool,
    /// Emit machine-readable JSON instead of a human report.
    #[arg(long)]
    json: bool,
    /// Only print threats (suppress clean files).
    #[arg(long, short = 'q')]
    quiet: bool,
    /// Quarantine malicious files into this encrypted vault directory.
    #[arg(long)]
    quarantine: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct WatchArgs {
    /// Directory to watch recursively for new/modified files.
    path: PathBuf,
    /// Quarantine malicious files on detection into this encrypted vault.
    #[arg(long)]
    quarantine: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ProtectArgs {
    /// Path(s) whose filesystem(s) to protect - every open/exec on them is checked.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Max bytes read from each file for the verdict.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    max_read: usize,
    /// Quarantine blocked files into this encrypted vault.
    #[arg(long)]
    quarantine: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct MemscanArgs {
    /// Scan a single PID (default: every accessible process).
    #[arg(long)]
    pid: Option<i32>,
    /// Also flag harvested wallet keys / seed phrases / cloud creds in memory (stealer scraping).
    #[arg(long)]
    secrets: bool,
}

#[derive(Debug, Args)]
struct SentinelArgs {
    /// Learn the current set of running executables as the trusted baseline.
    #[arg(long)]
    learn: bool,
    /// Live kernel exec-trace (cn_proc): scan every process as the kernel reports
    /// it being born. Resists userland hiding. Needs root/CAP_NET_ADMIN.
    #[arg(long)]
    watch: bool,
    /// Baseline file (path -> executable SHA-256).
    #[arg(long, default_value = "assets/models/proc_baseline.json")]
    baseline: PathBuf,
}

#[derive(Debug, Args)]
struct RansomguardArgs {
    /// Directory to protect (snapshot + canaries + rollback).
    dir: PathBuf,
    /// Vault directory for the snapshot (default: <dir>/.aether-vault).
    #[arg(long)]
    vault: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SelfcheckArgs {
    /// Write/refresh the integrity manifest instead of verifying against it.
    #[arg(long)]
    write: bool,
    /// Manifest path.
    #[arg(long, default_value = "assets/models/manifest.json")]
    manifest: PathBuf,
}

#[derive(Debug, Args)]
struct UpdateArgs {
    /// Signed-feed URL (overrides config `update.url`).
    #[arg(long)]
    url: Option<String>,
    /// Keep running and re-check forever (for a daemon / systemd service).
    #[arg(long)]
    watch: bool,
    /// Check interval in seconds when --watch (overrides config interval_hours).
    #[arg(long)]
    interval: Option<u64>,
}

#[derive(Debug, Args)]
struct ModelUpdateArgs {
    /// Model manifest URL (overrides config `update.model_url`).
    #[arg(long)]
    url: Option<String>,
    /// Destination model path.
    #[arg(long, default_value = "assets/models/aegis-50m.gguf")]
    model: PathBuf,
    /// Keep running and re-check forever.
    #[arg(long)]
    watch: bool,
    /// Check interval in seconds when --watch.
    #[arg(long)]
    interval: Option<u64>,
}

#[derive(Debug, Args)]
struct FirewallArgs {
    /// Target firewall: linux (nftables), windows (netsh), macos (pf). Default: this OS.
    #[arg(long)]
    platform: Option<String>,
    /// Install the rules into the live OS firewall (needs admin/root). Default: print only.
    #[arg(long)]
    apply: bool,
    /// Cap how many malicious IPs to include (intel can be large).
    #[arg(long, default_value_t = 2000)]
    limit: usize,
}

#[derive(Debug, Args)]
struct WebprotectArgs {
    /// Write the blocklist into the OS hosts file (needs admin/root). Default: print only.
    #[arg(long)]
    apply: bool,
    /// Remove the AetherAV-managed block from the hosts file.
    #[arg(long)]
    clear: bool,
    /// Cap how many malicious domains to include.
    #[arg(long, default_value_t = 5000)]
    limit: usize,
}

#[derive(Debug, Args)]
struct StealerguardArgs {
    /// Directory to protect (where decoys are planted and reads are watched).
    dir: std::path::PathBuf,
    /// Plant fresh decoy wallet/credential honeytokens in <dir>.
    #[arg(long)]
    arm: bool,
    /// Watch for processes reading decoys or enumerating secrets (Linux, needs root).
    #[arg(long)]
    watch: bool,
    /// On detection, kill the offending process (block the source).
    #[arg(long)]
    kill: bool,
}

#[derive(Debug, Args)]
struct ExploitscanArgs {
    /// File to scan for exploit-staging payloads.
    file: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct TlshArgs {
    /// File to compute a TLSH fuzzy hash for.
    file: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct VtScanArgs {
    /// File to scan.
    file: std::path::PathBuf,
    /// Emit a JSON result (engine + signature version) instead of plain text.
    #[arg(long)]
    json: bool,
    /// Print engine + signature-database version and exit (no scan).
    #[arg(long = "engine-version")]
    show_version: bool,
}

#[derive(Debug, Args)]
struct ClipguardArgs {
    /// Continuously watch the clipboard (default: one-shot check of current contents).
    #[arg(long)]
    watch: bool,
    /// On a detected swap, restore the original address to the clipboard.
    #[arg(long)]
    restore: bool,
}

#[derive(Debug, Args)]
struct ReputationArgs {
    /// A file path, or an MD5 / SHA-1 / SHA-256 hex digest.
    target: String,
}

#[derive(Debug, Args)]
struct CveArgs {
    /// CVE identifier, e.g. CVE-2021-44228.
    id: String,
}

#[derive(Debug, Args)]
struct FeedsignArgs {
    /// Unsigned feed JSON.
    input: PathBuf,
    /// Output path for the signed feed JSON.
    output: PathBuf,
    /// Hex Ed25519 private seed file (KEEP OFFLINE).
    #[arg(long, default_value = "assets/keys/feed_private.key")]
    key: PathBuf,
}

#[derive(Debug, Args)]
struct FeedverifyArgs {
    /// Feed JSON to verify against the compiled-in trusted public key.
    feed: PathBuf,
}

#[derive(Debug, Args)]
struct SignfileArgs {
    /// File to sign (e.g. SHA256SUMS).
    file: PathBuf,
    /// Hex Ed25519 private seed file (KEEP OFFLINE).
    #[arg(long, default_value = "assets/keys/feed_private.key")]
    key: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyfileArgs {
    /// File whose detached signature (`<file>.sig`) to verify.
    file: PathBuf,
}

#[derive(Debug, Args)]
struct SubmitArgs {
    /// File whose hashes/IOCs to submit (anonymous).
    path: PathBuf,
    /// Submission endpoint (HTTPS). If omitted, prints the payload (dry-run).
    #[arg(long)]
    url: Option<String>,
    /// Also include the file's bytes (only do this for confirmed malware - files
    /// may contain personal data). Off by default.
    #[arg(long)]
    include_sample: bool,
}

#[derive(Debug, Args)]
struct EvalArgs {
    /// Directory of known-benign files (false positives are flagged here).
    #[arg(long)]
    clean: PathBuf,
    /// Directory of known-malicious files (false negatives are missed here).
    #[arg(long)]
    malware: PathBuf,
    /// Also run `clamscan` on the same dirs for a head-to-head (needs ClamAV).
    #[arg(long)]
    clamav: bool,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8088")]
    addr: String,
}

#[derive(Debug, Args)]
struct MonitorArgs {
    /// Number of poll cycles to run (0 = run until interrupted).
    #[arg(long, default_value_t = 0)]
    ticks: u64,
    /// Milliseconds between polls.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    /// Optional baseline model to also flag anomalies against.
    #[arg(long, short = 'm')]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    /// Write a default configuration file.
    Init {
        /// Where to write it.
        #[arg(long, short = 'o', default_value = "aether.toml")]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Resolve config first so logging can honor configured level/format.
    let mut config = match Config::load_or_default(cli.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(level) = &cli.log_level {
        config.logging.level = level.clone();
    }

    let fmt = if config.logging.json {
        LogFormat::Json
    } else {
        LogFormat::Pretty
    };
    logging::init(&config.logging.level, fmt);

    let result = match cli.command {
        Command::Scan(args) => run_scan(config, args),
        Command::Behavior(args) => run_behavior(args),
        Command::Emulate(args) => run_emulate(args),
        Command::Learn(args) => run_learn(args),
        Command::Anomaly(args) => run_anomaly(args),
        Command::Quarantine(cmd) => run_quarantine(cmd),
        Command::Intel(cmd) => run_intel(cmd),
        Command::Update(args) => run_update(config, args),
        Command::ModelUpdate(args) => run_model_update(config, args),
        Command::Serve(args) => run_serve(config, args),
        Command::Monitor(args) => run_monitor(args),
        Command::Watch(args) => run_watch(config, args),
        Command::Protect(args) => run_protect(config, args),
        Command::Memscan(args) => run_memscan(config, args),
        Command::Sentinel(args) => run_sentinel(config, args),
        Command::Ransomguard(args) => run_ransomguard(args),
        Command::Selfcheck(args) => run_selfcheck(config, args),
        Command::Netscan => run_netscan(config),
        Command::Dnswatch => run_dnswatch(config),
        Command::Firewall(args) => run_firewall(config, args),
        Command::Webprotect(args) => run_webprotect(config, args),
        Command::Stealerguard(args) => run_stealerguard(config, args),
        Command::Clipguard(args) => run_clipguard(config, args),
        Command::Exploitscan(args) => run_exploitscan(args),
        Command::VtScan(args) => run_vt_scan(config, args),
        Command::Tlsh(args) => run_tlsh(args),
        Command::Imphash(args) => run_imphash(args),
        Command::Timestomp(args) => run_timestomp(args),
        Command::Eval(args) => run_eval(config, args),
        Command::Reputation(args) => run_reputation(args),
        Command::Cve(args) => run_cve(args),
        Command::Feedsign(args) => run_feedsign(args),
        Command::Feedverify(args) => run_feedverify(args),
        Command::Signfile(args) => run_signfile(args),
        Command::Verifyfile(args) => run_verifyfile(args),
        Command::Submit(args) => run_submit(args),
        Command::Config(ConfigCmd::Init { output }) => run_config_init(&config, output),
        Command::Info => run_info(config),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Exit codes follow the ClamAV convention so AetherAV is a drop-in in scripts:
///   0 = no threats, 1 = threats found, 2 = error.
fn run_scan(mut config: Config, args: ScanArgs) -> Result<ExitCode> {
    config.scan.recursive = args.recursive || config.scan.recursive;
    if args.json {
        config.logging.json = true;
    }

    let use_rep = config.engines.reputation;
    let mut scanner = Scanner::new(config).context("failed to initialize scanner")?;
    if use_rep {
        scanner = scanner.with_reputation(hashlookup_reputation());
    }
    let (reports, summary) = scanner
        .scan_path(&args.path)
        .with_context(|| format!("scanning {}", args.path.display()))?;

    if args.json {
        // One JSON object per threat line; summary last. Stable for piping.
        for r in reports.iter().filter(|r| r.is_threat()) {
            println!("{}", to_json(r));
        }
    } else {
        for r in &reports {
            if r.is_threat() {
                let worst = r
                    .verdicts
                    .iter()
                    .max_by(|a, b| a.level.cmp(&b.level))
                    .unwrap();
                println!(
                    "{:<11} {}  [{}] {}",
                    r.disposition().to_string(),
                    r.path.display(),
                    worst.signature,
                    worst.detail.as_deref().unwrap_or("")
                );
            } else if !args.quiet {
                println!("{:<11} {}", "CLEAN", r.path.display());
            }
        }
        println!(
            "\n-- scanned {} | clean {} | suspicious {} | malicious {} | errors {} | {} ms",
            summary.scanned,
            summary.clean,
            summary.suspicious,
            summary.malicious,
            summary.errors,
            summary.elapsed.as_millis()
        );
    }

    // Optional remediation: secure malicious files into the encrypted vault.
    if let Some(vault_dir) = &args.quarantine {
        let mut vault = aether_quarantine::Vault::open(vault_dir)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for r in reports.iter().filter(|r| {
            r.disposition() == aether_common::ThreatLevel::Malicious && r.path.is_file()
        }) {
            let threat = r
                .verdicts
                .iter()
                .max_by(|a, b| a.level.cmp(&b.level))
                .map(|v| v.signature.clone())
                .unwrap_or_else(|| "Unknown".into());
            match vault.quarantine_file(&r.path, &threat) {
                Ok(e) => println!("QUARANTINED {}  (id {})", r.path.display(), &e.id[..16]),
                Err(e) => tracing::warn!(error = %e, path = %r.path.display(), "quarantine failed"),
            }
        }
    }

    Ok(if summary.malicious + summary.suspicious > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Analyze a behavioral event trace. Exit codes match `scan`.
fn run_behavior(args: BehaviorArgs) -> Result<ExitCode> {
    use aether_behavior::BehaviorEngine;

    let json = std::fs::read_to_string(&args.trace)
        .with_context(|| format!("reading trace {}", args.trace.display()))?;
    let report = BehaviorEngine::new()
        .analyze_json(&json)
        .map_err(|e| anyhow::anyhow!(e))?;

    if args.json {
        for v in &report.verdicts {
            println!(
                r#"{{"signature":"{}","level":"{}","score":{:.3},"mitre":[{}],"detail":"{}"}}"#,
                v.signature,
                v.level,
                v.score,
                v.mitre
                    .iter()
                    .map(|m| format!("\"{m}\""))
                    .collect::<Vec<_>>()
                    .join(","),
                v.detail.as_deref().unwrap_or("").replace('"', "\\\"")
            );
        }
    } else {
        println!(
            "behavior graph: {} entities, {} relationships",
            report.nodes, report.edges
        );
        if report.verdicts.is_empty() {
            println!("CLEAN  no malicious behavior detected");
        } else {
            for v in &report.verdicts {
                println!(
                    "{:<11} [{}] {}  ({})",
                    v.level.to_string(),
                    v.signature,
                    v.detail.as_deref().unwrap_or(""),
                    v.mitre.join(", ")
                );
            }
            println!(
                "\nMITRE ATT&CK techniques: {}",
                report.techniques().join(", ")
            );
        }
    }

    Ok(if report.disposition() >= ThreatLevel::Suspicious {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Statically emulate a code buffer. Exit codes match `scan`.
fn run_emulate(args: EmulateArgs) -> Result<ExitCode> {
    use aether_sandbox::{Bitness, Sandbox};

    let code =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let bitness = if args.arch == "32" {
        Bitness::Bits32
    } else {
        Bitness::Bits64
    };

    let report = Sandbox::new().analyze(&code, bitness);
    println!(
        "emulated {} bytes, {} instructions ({}-bit)",
        code.len(),
        report.instructions,
        bitness.value()
    );
    if report.verdicts.is_empty() {
        println!("CLEAN  no anti-evasion or shellcode techniques detected");
    } else {
        for v in &report.verdicts {
            println!(
                "{:<11} [{}] {}  ({})",
                v.level.to_string(),
                v.signature,
                v.detail.as_deref().unwrap_or(""),
                v.mitre.join(", ")
            );
        }
        println!(
            "\nMITRE ATT&CK techniques: {}",
            report.techniques().join(", ")
        );
    }

    Ok(if report.disposition() >= ThreatLevel::Suspicious {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Online-learn (or update) a host baseline from a benign trace, then persist.
fn run_learn(args: BaselineArgs) -> Result<ExitCode> {
    use aether_anomaly::{AnomalyEngine, Baseline};

    let json = std::fs::read_to_string(&args.trace)
        .with_context(|| format!("reading trace {}", args.trace.display()))?;
    let events = aether_behavior::Event::from_json(&json).map_err(|e| anyhow::anyhow!(e))?;

    // Load existing baseline so learning is incremental across invocations.
    let baseline =
        Baseline::load_or_new(&args.model).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut engine = AnomalyEngine::new(baseline);
    engine.learn(&events);
    engine
        .baseline()
        .save(&args.model)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let b = engine.baseline();
    println!(
        "baseline updated -> {} ({} known programs, {} lineages, {} net dests, {} spawns total){}",
        args.model.display(),
        b.process_freq.len(),
        b.spawn_pairs.len(),
        b.net_dests.len(),
        b.total_spawns,
        if b.is_trained() {
            ""
        } else {
            " - not yet trained (need ≥15 spawns)"
        }
    );
    Ok(ExitCode::SUCCESS)
}

/// Score a trace for anomalies against a learned baseline.
fn run_anomaly(args: BaselineArgs) -> Result<ExitCode> {
    use aether_anomaly::{AnomalyEngine, Baseline};

    let json = std::fs::read_to_string(&args.trace)
        .with_context(|| format!("reading trace {}", args.trace.display()))?;
    let events = aether_behavior::Event::from_json(&json).map_err(|e| anyhow::anyhow!(e))?;

    let baseline =
        Baseline::load_or_new(&args.model).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if !baseline.is_trained() {
        println!(
            "baseline {} is not trained yet - run `aether learn` on benign traces first",
            args.model.display()
        );
        return Ok(ExitCode::from(2));
    }
    let engine = AnomalyEngine::new(baseline);
    let anomalies = engine.score(&events);

    if anomalies.is_empty() {
        println!("CLEAN  no anomalies relative to the learned baseline");
    } else {
        for v in &anomalies {
            println!(
                "{:<11} [{}] {}",
                v.level.to_string(),
                v.signature,
                v.detail.as_deref().unwrap_or("")
            );
        }
    }
    Ok(if anomalies.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn run_quarantine(cmd: QuarantineCmd) -> Result<ExitCode> {
    use aether_quarantine::Vault;
    match cmd {
        QuarantineCmd::List { vault } => {
            let v = Vault::open(&vault).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let items = v.timeline();
            if items.is_empty() {
                println!("vault {} is empty", vault.display());
            } else {
                for e in items {
                    println!(
                        "{}  {:<22} {}  (from {})",
                        &e.id[..16],
                        e.threat,
                        e.quarantined_at,
                        e.original_path
                    );
                }
            }
        }
        QuarantineCmd::Restore { id, dest, vault } => {
            let v = Vault::open(&vault).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            v.restore(&id, &dest)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!("restored {id} -> {}", dest.display());
        }
        QuarantineCmd::Iocs { vault } => {
            let v = Vault::open(&vault).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            print!("{}", v.export_iocs());
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One auto-update cycle: fetch the signed feed, verify it (Ed25519 trust +
/// anti-rollback), apply it, and rebuild the hash DB. Returns (added, version).
fn update_once(
    url: &str,
    store_path: &std::path::Path,
    hash_db: &std::path::Path,
) -> Result<(usize, u64)> {
    use aether_intel::{Feed, IntelStore};
    let (code, body) = http_get(url)?;
    if code != 200 {
        return Err(anyhow::anyhow!("feed fetch HTTP {code}"));
    }
    let feed = Feed::from_json(&body).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut store =
        IntelStore::load_or_new(store_path).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    // apply_signed enforces the Ed25519 trust anchor + anti-rollback. Integrity
    // holds even over plain HTTP, because a forged feed can't be signed.
    let added = store
        .apply_signed(&feed)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if added > 0 {
        store
            .save(store_path)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        // Merge the store's sha256 IOCs into the on-disk hash DB and dedup.
        let base = std::fs::read_to_string(hash_db).unwrap_or_default();
        let mut lines: std::collections::BTreeSet<String> =
            base.lines().map(|s| s.to_string()).collect();
        for l in store.export_hashdb().lines() {
            lines.insert(l.to_string());
        }
        let _ = std::fs::write(hash_db, lines.into_iter().collect::<Vec<_>>().join("\n"));
    }
    Ok((added, store.version))
}

/// Auto-update from the signed feed. With --watch, loops forever so detection
/// never falls behind.
fn run_update(config: Config, args: UpdateArgs) -> Result<ExitCode> {
    let url = args
        .url
        .filter(|u| !u.is_empty())
        .or_else(|| (!config.update.url.is_empty()).then(|| config.update.url.clone()));
    let Some(url) = url else {
        eprintln!("no update URL — set `update.url` in the config or pass --url");
        return Ok(ExitCode::FAILURE);
    };
    if !url.starts_with("https://") {
        eprintln!("note: feed integrity is guaranteed by the signature even over HTTP, but HTTPS is recommended for privacy");
    }
    let interval = std::time::Duration::from_secs(
        args.interval
            .unwrap_or(config.update.interval_hours.max(1) * 3600),
    );
    let store_path = config.engines.intel_store.clone();
    let hash_db = config.engines.hash_db.clone();

    loop {
        match update_once(&url, &store_path, &hash_db) {
            Ok((0, ver)) => println!("up to date (feed v{ver})"),
            Ok((added, ver)) => println!("updated: +{added} indicators, now at feed v{ver}"),
            Err(e) => eprintln!("update failed: {e}"),
        }
        if !args.watch {
            break;
        }
        std::thread::sleep(interval);
    }
    Ok(ExitCode::SUCCESS)
}

/// GET raw bytes (for binary artifacts like the GGUF model).
fn http_get_bytes(url: &str) -> Result<(u16, Vec<u8>)> {
    use std::io::Read;
    match ureq::get(url)
        .timeout(std::time::Duration::from_secs(120))
        .call()
    {
        Ok(r) => {
            let code = r.status();
            let mut buf = Vec::new();
            r.into_reader()
                .take(512 * 1024 * 1024)
                .read_to_end(&mut buf)
                .ok();
            Ok((code, buf))
        }
        Err(ureq::Error::Status(code, _)) => Ok((code, Vec::new())),
        Err(e) => Err(anyhow::anyhow!(e.to_string())),
    }
}

/// One AI-model update cycle. The manifest is Ed25519-signed over
/// "version|sha256"; we verify it, enforce anti-rollback, download the model,
/// check its hash, and atomically swap it in. Returns (updated, version).
fn model_update_once(manifest_url: &str, model: &std::path::Path) -> Result<(bool, u64)> {
    let (code, body) = http_get(manifest_url)?;
    if code != 200 {
        return Err(anyhow::anyhow!("manifest HTTP {code}"));
    }
    let m: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("bad manifest: {e}"))?;
    let version = m
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("manifest missing version"))?;
    let sha256 = m
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("manifest missing sha256"))?;
    let model_url = m
        .get("model_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("manifest missing model_url"))?;
    let sig = m
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("manifest missing sig"))?;

    // Verify the signature over "version|sha256" against the trusted key.
    let signed = format!("{version}|{sha256}");
    if !aether_intel::verify_detached(aether_intel::TRUSTED_FEED_PUBKEY, signed.as_bytes(), sig) {
        return Err(anyhow::anyhow!("untrusted model manifest - rejected"));
    }

    // Anti-rollback: don't accept an older model than the one we have.
    let version_path = model.with_extension("version");
    let current: u64 = std::fs::read_to_string(&version_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if version <= current {
        return Ok((false, current));
    }

    // Download + verify the model bytes against the signed hash.
    let (code2, bytes) = http_get_bytes(model_url)?;
    if code2 != 200 || bytes.is_empty() {
        return Err(anyhow::anyhow!("model download HTTP {code2}"));
    }
    if aether_signatures::hash_bytes(&bytes).sha256 != sha256 {
        return Err(anyhow::anyhow!("model hash mismatch - rejected"));
    }

    // Atomic swap: write a temp file in the same dir, then rename over the model.
    let tmp = model.with_extension("gguf.tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, model)?;
    std::fs::write(&version_path, version.to_string())?;
    Ok((true, version))
}

/// Update the on-device AI model from the signed manifest (--watch to stay current).
fn run_model_update(config: Config, args: ModelUpdateArgs) -> Result<ExitCode> {
    let url = args
        .url
        .filter(|u| !u.is_empty())
        .or_else(|| (!config.update.model_url.is_empty()).then(|| config.update.model_url.clone()));
    let Some(url) = url else {
        eprintln!("no model manifest URL - set `update.model_url` in the config or pass --url");
        return Ok(ExitCode::FAILURE);
    };
    let interval = std::time::Duration::from_secs(
        args.interval
            .unwrap_or(config.update.interval_hours.max(1) * 3600),
    );
    loop {
        match model_update_once(&url, &args.model) {
            Ok((true, v)) => println!("AI model updated to v{v} (verified + swapped)"),
            Ok((false, v)) => println!("model up to date (v{v})"),
            Err(e) => eprintln!("model update failed: {e}"),
        }
        if !args.watch {
            break;
        }
        std::thread::sleep(interval);
    }
    Ok(ExitCode::SUCCESS)
}

fn run_intel(cmd: IntelCmd) -> Result<ExitCode> {
    use aether_intel::{Feed, IntelStore};
    match cmd {
        IntelCmd::Import {
            file,
            format,
            store,
            threat,
            feed_version,
        } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let feed = match format.as_str() {
                "threatfox" => Feed::from_threatfox_csv(&text, feed_version),
                "sha256" => Feed::from_sha256_list(&text, feed_version, &threat),
                "misp" => Feed::from_misp_json(&text, feed_version, &threat),
                "urlhaus" => Feed::from_urlhaus_csv(&text, feed_version),
                "feodo" => Feed::from_feodo_csv(&text, feed_version),
                "malwarebazaar" => Feed::from_malwarebazaar_csv(&text, feed_version),
                "iplist" => Feed::from_ipv4_list(&text, feed_version, &threat),
                "domainlist" => Feed::from_domain_list(&text, feed_version, &threat),
                other => return Err(anyhow::anyhow!(
                    "unknown format '{other}' (threatfox|sha256|misp|urlhaus|feodo|malwarebazaar|iplist|domainlist)"
                )),
            }
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let mut s =
                IntelStore::load_or_new(&store).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let added = s
                .apply(&feed, None)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            s.save(&store).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!(
                "imported {added} indicators ({format}) -> store v{}, {} IOCs total",
                s.version,
                s.len()
            );
        }
        IntelCmd::Apply { feed, store, key } => {
            let feed = Feed::load(&feed).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let mut s =
                IntelStore::load_or_new(&store).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let key_bytes = match &key {
                Some(hexkey) => Some(hex::decode(hexkey).context("--key must be hex")?),
                None => None,
            };
            let added = s
                .apply(&feed, key_bytes.as_deref())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            s.save(&store).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!(
                "applied feed v{} ({added} indicators) -> store now v{}, {} IOCs",
                feed.version,
                s.version,
                s.len()
            );
        }
        IntelCmd::ExportHashdb { store, output } => {
            let s = IntelStore::load_or_new(&store).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            std::fs::write(&output, s.export_hashdb())
                .with_context(|| format!("writing {}", output.display()))?;
            println!(
                "exported {} hash signatures -> {}",
                s.len(),
                output.display()
            );
        }
        IntelCmd::ExportFeed {
            store,
            output,
            feed_version,
        } => {
            let s = IntelStore::load_or_new(&store).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let ver = feed_version.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });
            let feed = s.to_feed(ver);
            let json = feed.to_json().map_err(|e| anyhow::anyhow!(e.to_string()))?;
            std::fs::write(&output, json)
                .with_context(|| format!("writing {}", output.display()))?;
            println!(
                "exported feed v{ver} with {} IOCs -> {} (now sign it with `aether feedsign`)",
                feed.iocs.len(),
                output.display()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Real-time monitor loop: poll live process events and run the engines.
fn run_monitor(args: MonitorArgs) -> Result<ExitCode> {
    use aether_anomaly::{AnomalyEngine, Baseline};
    use aether_realtime::{Collector, EventSource, ProcMonitor};
    use std::collections::HashSet;
    use std::time::Duration;

    let mut monitor = ProcMonitor::new();
    monitor.prime(); // ignore the existing process table; report only new spawns
    let mut collector = Collector::new(10_000);

    let anomaly = match &args.baseline {
        Some(p) => {
            let b = Baseline::load_or_new(p).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            Some(AnomalyEngine::new(b))
        }
        None => None,
    };

    println!(
        "real-time monitor started ({} source) - interval {}ms{}",
        monitor.name(),
        args.interval_ms,
        if args.ticks == 0 {
            ", until interrupted"
        } else {
            ""
        }
    );

    let mut printed: HashSet<String> = HashSet::new();
    let mut tick = 0u64;
    loop {
        std::thread::sleep(Duration::from_millis(args.interval_ms));
        let events = monitor.poll();
        let new_count = events.len();
        collector.ingest(events);

        let mut verdicts = collector.analyze();
        if let Some(eng) = &anomaly {
            verdicts.extend(eng.score(collector.window()));
        }
        for v in &verdicts {
            let key = format!("{}|{}", v.signature, v.detail.as_deref().unwrap_or(""));
            if printed.insert(key) {
                println!(
                    "{:<11} [{}] {}",
                    v.level.to_string(),
                    v.signature,
                    v.detail.as_deref().unwrap_or("")
                );
            }
        }
        if new_count > 0 {
            println!("· tick {tick}: {new_count} new process event(s)");
        }

        tick += 1;
        if args.ticks != 0 && tick >= args.ticks {
            break;
        }
    }
    println!("monitor stopped after {tick} ticks");
    Ok(ExitCode::SUCCESS)
}

/// Watch outbound DNS queries and flag lookups of known-bad domains.
fn run_dnswatch(_config: Config) -> Result<ExitCode> {
    #[cfg(feature = "pcap")]
    {
        use aether_intel::IntelStore;
        use aether_realtime::{dns, netmon};
        let store = IntelStore::load_or_new(&_config.engines.intel_store)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let domains = store.count_kind(aether_intel::IocKind::Domain);
        println!("DNS query monitor active - {domains} domain IOCs - Ctrl-C to stop");
        dns::watch_dns_queries(|qname| {
            for cand in netmon::domain_candidates(&qname) {
                if let Some(threat) = store.lookup_domain(&cand) {
                    println!("MALICIOUS  DNS query {qname}  [intel domain {cand}] {threat}");
                    return;
                }
            }
            tracing::debug!(query = %qname, "dns");
        })
        .map_err(|e| anyhow::anyhow!(e))?;
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(feature = "pcap"))]
    {
        println!(
            "DNS query monitoring requires a privileged capture build:\n  \
             cargo build -p aether-cli --features pcap   (needs libpcap)\n  \
             sudo ./target/debug/aether dnswatch         (needs CAP_NET_RAW / root)"
        );
        Ok(ExitCode::from(2))
    }
}

/// True if an IPv4/IPv6 string is a routable (non-private, non-loopback) address.
fn is_external(ip: &str) -> bool {
    !(ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip == "0.0.0.0"
        || ip.starts_with("::1")
        || ip.starts_with("fe80")
        || ip.starts_with("::")
        || (ip.starts_with("172.")
            && ip
                .split('.')
                .nth(1)
                .and_then(|o| o.parse::<u8>().ok())
                .is_some_and(|o| (16..=31).contains(&o))))
}

/// Build and render (or apply) a threat firewall driven by our intel + the
/// malicious-port table, in the chosen OS's native firewall syntax.
fn run_firewall(config: Config, args: FirewallArgs) -> Result<ExitCode> {
    use aether_firewall::{Platform, RuleSet};
    use aether_intel::{IntelStore, IocKind};
    use aether_realtime::netmon;

    let platform = match &args.platform {
        Some(p) => Platform::parse(p)
            .ok_or_else(|| anyhow::anyhow!("unknown platform '{p}' (use linux|windows|macos)"))?,
        None => Platform::current(),
    };

    let mut rs = RuleSet::new();
    // Malicious / C2 / RAT ports (high-signal, curated).
    for (port, name, _sev) in netmon::MALICIOUS_PORTS {
        rs.block_port(*port, *name);
    }
    // Known-bad IPs from the (signed) threat-intel store.
    let mut intel_ips = 0usize;
    if let Ok(store) = IntelStore::load_or_new(&config.engines.intel_store) {
        for ioc in store.iocs() {
            if ioc.kind == IocKind::Ipv4 {
                if rs.bad_ips.len() >= args.limit {
                    break;
                }
                rs.block_ip(ioc.value.clone());
                intel_ips += 1;
            }
        }
    }
    rs.note = format!(
        "{} malicious IPs + {} ports (intel-driven)",
        rs.bad_ips.len(),
        rs.bad_ports.len()
    );

    if args.apply {
        match rs.install(platform) {
            Ok(msg) => {
                println!(
                    "[firewall] applied to {} firewall: {msg}",
                    platform.as_str()
                );
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("[firewall] could not apply ({e}). Run with admin/root, or render without --apply.");
                Ok(ExitCode::FAILURE)
            }
        }
    } else {
        eprintln!(
            "[firewall] {} platform | {} IPs ({intel_ips} from intel) + {} ports | install with --apply (needs admin)",
            platform.as_str(),
            rs.bad_ips.len(),
            rs.bad_ports.len()
        );
        print!("{}", rs.render(platform));
        Ok(ExitCode::SUCCESS)
    }
}

/// Build and render (or apply) a hosts-file blocklist of malicious / phishing
/// domains from the threat-intel store - local, private, no cloud.
fn run_webprotect(config: Config, args: WebprotectArgs) -> Result<ExitCode> {
    use aether_firewall::web;
    use aether_intel::{IntelStore, IocKind};

    if args.clear {
        return match web::clear() {
            Ok(()) => {
                println!(
                    "[webprotect] removed the AetherAV block from {:?}",
                    web::hosts_path()
                );
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("[webprotect] could not edit hosts ({e}). Run with admin/root.");
                Ok(ExitCode::FAILURE)
            }
        };
    }

    let store = IntelStore::load_or_new(&config.engines.intel_store)
        .map_err(|e| anyhow::anyhow!("load intel: {e}"))?;
    let domains: Vec<String> = store
        .iocs()
        .filter(|i| i.kind == IocKind::Domain)
        .take(args.limit)
        .map(|i| i.value.clone())
        .collect();
    let refs: Vec<&str> = domains.iter().map(String::as_str).collect();

    if args.apply {
        match web::apply(&refs) {
            Ok(n) => {
                println!(
                    "[webprotect] sinkholed {n} host entries in {:?}",
                    web::hosts_path()
                );
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("[webprotect] could not edit hosts ({e}). Run with admin/root.");
                Ok(ExitCode::FAILURE)
            }
        }
    } else {
        eprintln!(
            "[webprotect] {} malicious domains | install with --apply (needs admin), remove with --clear",
            domains.len()
        );
        print!("{}", web::render_block(&refs));
        Ok(ExitCode::SUCCESS)
    }
}

/// Read the OS clipboard via whatever tool is available. Returns None if none.
fn read_clipboard() -> Option<String> {
    use std::process::Command;
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbpaste", &[])]
    } else if cfg!(target_os = "windows") {
        &[("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])]
    } else {
        &[
            ("wl-paste", &["-n"]),
            ("xclip", &["-o", "-selection", "clipboard"]),
            ("xsel", &["-b"]),
        ]
    };
    for (cmd, a) in attempts {
        if let Ok(o) = Command::new(cmd).args(*a).output() {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout);
                return Some(s.trim_end_matches(['\n', '\r']).to_string());
            }
        }
    }
    None
}

/// Write text to the OS clipboard. Returns true on success.
fn write_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if cfg!(target_os = "windows") {
        &[("clip", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-i", "-selection", "clipboard"]),
            ("xsel", &["-bi"]),
        ]
    };
    for (cmd, a) in attempts {
        if let Ok(mut c) = Command::new(cmd).args(*a).stdin(Stdio::piped()).spawn() {
            if let Some(mut si) = c.stdin.take() {
                let _ = si.write_all(text.as_bytes());
            }
            if c.wait().map(|st| st.success()).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// VirusTotal-contributor scan contract: scan ONE file and report a detection.
///   stdout (plain): the detection name, or empty when clean.
///   exit code:      1 = infected, 0 = clean, 2 = error.
/// Detection fires only on a Malicious disposition (conservative - false
/// positives on VirusTotal damage reputation).
fn run_vt_scan(config: Config, args: VtScanArgs) -> Result<ExitCode> {
    use serde_json::json;
    let engine_version = env!("CARGO_PKG_VERSION");

    let scanner = match Scanner::new(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    let sigs = scanner.signature_count();

    if args.show_version {
        if args.json {
            println!(
                "{}",
                json!({"engine": "AetherAV", "version": engine_version, "signatures": sigs})
            );
        } else {
            println!("AetherAV {engine_version} (signatures: {sigs})");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let report = match scanner.scan_file(&args.file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error scanning {}: {e}", args.file.display());
            return Ok(ExitCode::from(2));
        }
    };
    let detected = report.disposition() == aether_common::ThreatLevel::Malicious;
    let name = report
        .verdicts
        .iter()
        .max_by_key(|v| v.level)
        .map(|v| v.signature.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "AetherAV.Malware.Generic".to_string());

    if args.json {
        println!(
            "{}",
            json!({
                "engine": "AetherAV",
                "version": engine_version,
                "signatures": sigs,
                "detected": detected,
                "result": if detected { name.as_str() } else { "" },
            })
        );
    } else if detected {
        println!("{name}");
    }
    Ok(if detected {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Check a file's timestamps (and PE compile time) for timestomping.
fn run_timestomp(args: TlshArgs) -> Result<ExitCode> {
    use aether_realtime::timestomp;
    let meta =
        std::fs::metadata(&args.file).with_context(|| format!("stat {}", args.file.display()))?;
    let times = timestomp::from_metadata(&meta);
    let pe_ts = std::fs::read(&args.file)
        .ok()
        .and_then(|d| aether_parsers::pe::PeInfo::parse(&d).ok())
        .map(|p| p.pe_timestamp)
        .filter(|&t| t != 0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let r = timestomp::evaluate(&times, pe_ts, now);
    if r.indicators.is_empty() {
        println!(
            "[timestomp] {} - no timestomping indicators",
            args.file.display()
        );
        Ok(ExitCode::SUCCESS)
    } else {
        let tag = if r.suspicious { "SUSPICIOUS" } else { "note" };
        println!("[timestomp] {} - {}:", args.file.display(), tag);
        for i in &r.indicators {
            println!("   - {}", i.describe());
        }
        Ok(if r.suspicious {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        })
    }
}

/// Print a PE file's import hash (imphash) for family clustering.
fn run_imphash(args: TlshArgs) -> Result<ExitCode> {
    let data =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    match aether_parsers::pe::PeInfo::parse(&data) {
        Ok(pe) => match pe.imphash {
            Some(h) => {
                println!("{h}  {}", args.file.display());
                Ok(ExitCode::SUCCESS)
            }
            None => {
                eprintln!("[imphash] {} has no imports", args.file.display());
                Ok(ExitCode::FAILURE)
            }
        },
        Err(_) => {
            eprintln!("[imphash] {} is not a PE file", args.file.display());
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Print a file's TLSH fuzzy hash (for building a variant DB line `<hash> <threat>`).
fn run_tlsh(args: TlshArgs) -> Result<ExitCode> {
    let data =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    match aether_signatures::fuzzy::tlsh(&data) {
        Some(h) => {
            println!("{h}  {}", args.file.display());
            Ok(ExitCode::SUCCESS)
        }
        None => {
            eprintln!(
                "[tlsh] {} is too small/uniform for a TLSH digest",
                args.file.display()
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Scan a file for static exploit-staging indicators.
fn run_exploitscan(args: ExploitscanArgs) -> Result<ExitCode> {
    let data =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    let hits = aether_sandbox::exploit::scan_exploit(&data);
    if hits.is_empty() {
        println!(
            "[exploitscan] {} - no exploit-staging indicators",
            args.file.display()
        );
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "[exploitscan] {} - {} indicator(s):",
            args.file.display(),
            hits.len()
        );
        for h in &hits {
            println!("   - {}", h.describe());
        }
        Ok(ExitCode::FAILURE)
    }
}

/// Crypto clipboard-hijacker ("clipper") guard: watch the clipboard and flag (or
/// restore) when a copied wallet address is swapped for another.
fn run_clipguard(_config: Config, args: ClipguardArgs) -> Result<ExitCode> {
    use aether_realtime::clipguard::{classify_address, ClipGuard};

    if !args.watch {
        match read_clipboard() {
            Some(c) => match classify_address(&c) {
                Some(k) => println!("[clipguard] clipboard holds a {} address", k.as_str()),
                None => println!("[clipguard] clipboard does not contain a crypto address"),
            },
            None => eprintln!(
                "[clipguard] no clipboard tool found (Linux: wl-clipboard or xclip; macOS: pbpaste; Windows: PowerShell)."
            ),
        }
        return Ok(ExitCode::SUCCESS);
    }

    if read_clipboard().is_none() {
        eprintln!(
            "[clipguard] no clipboard tool available; install wl-clipboard or xclip (Linux)."
        );
        return Ok(ExitCode::FAILURE);
    }

    let mut guard = ClipGuard::new();
    eprintln!("[clipguard] watching clipboard for crypto-address hijacking (Ctrl-C to stop)...");
    let mut last = String::new();
    loop {
        if let Some(c) = read_clipboard() {
            if c != last {
                last = c.clone();
                if let Some(a) = guard.observe(&c) {
                    eprintln!("[clipguard] ALERT: {}", a.note);
                    eprintln!("            was: {}\n            now: {}", a.from, a.to);
                    if args.restore && write_clipboard(&a.from) {
                        eprintln!(
                            "[clipguard] restored the original {} address",
                            a.kind.as_str()
                        );
                        last = a.from.clone();
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

/// Infostealer / wallet-stealer shield: plant decoy honeytokens, and (on Linux,
/// via fanotify) detect + block any process that reads them or enumerates
/// credential / wallet files.
fn run_stealerguard(_config: Config, args: StealerguardArgs) -> Result<ExitCode> {
    use aether_realtime::stealerguard::{kill_pid, Decoys, StealerDetector};

    if args.arm {
        match Decoys::plant(&args.dir) {
            Ok(d) => {
                println!(
                    "[stealerguard] planted {} decoy honeytokens in {}:",
                    d.files.len(),
                    args.dir.display()
                );
                for f in &d.files {
                    println!("   {}", f.display());
                }
            }
            Err(e) => {
                eprintln!("[stealerguard] could not plant decoys: {e}");
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    if !args.watch {
        if !args.arm {
            eprintln!("[stealerguard] nothing to do - pass --arm to plant decoys and/or --watch to monitor.");
        }
        return Ok(ExitCode::SUCCESS);
    }

    #[cfg(target_os = "linux")]
    {
        use aether_realtime::onaccess::OnAccessGuard;
        let decoys = Decoys::existing(&args.dir);
        let mut det = StealerDetector::new();
        let guard = match OnAccessGuard::new(std::slice::from_ref(&args.dir)) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[stealerguard] cannot start watch ({e}). Needs root / CAP_SYS_ADMIN.");
                return Ok(ExitCode::FAILURE);
            }
        };
        eprintln!(
            "[stealerguard] watching {} for wallet/credential theft (Ctrl-C to stop)...",
            args.dir.display()
        );
        let kill = args.kill;
        let res = guard.run_detailed(0, |pid, path, _bytes| {
            let is_decoy = decoys.is_decoy(path);
            if let Some(d) = det.observe(pid, path, is_decoy) {
                eprintln!(
                    "[stealerguard] ALERT pid {} [{}]: {}",
                    d.pid, d.severity, d.reason
                );
                if kill && kill_pid(d.pid) {
                    eprintln!("[stealerguard] killed source pid {}", d.pid);
                }
                // Block the read at the source for high-confidence decoy hits.
                return !d.decoy;
            }
            true
        });
        if let Err(e) = res {
            eprintln!("[stealerguard] watch ended: {e}");
            return Ok(ExitCode::FAILURE);
        }
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = StealerDetector::new();
        eprintln!("[stealerguard] live blocking (fanotify) is Linux-only for now; decoys are planted and classification works on all platforms.");
        Ok(ExitCode::SUCCESS)
    }
}

/// List live TCP connections, flagging both malware-associated ports and
/// connections to known-malicious remote IPs from the threat-intel store.
fn run_netscan(config: Config) -> Result<ExitCode> {
    use aether_intel::IntelStore;
    use aether_realtime::netmon;

    let conns = netmon::connections();
    let intel = IntelStore::load_or_new(&config.engines.intel_store).ok();
    let intel_ips = intel
        .as_ref()
        .map(|s| s.count_kind(aether_intel::IocKind::Ipv4))
        .unwrap_or(0);

    // Pre-resolve external established remotes concurrently (bounded, ~3s cap).
    let hosts = if intel.is_some() {
        let mut ips: Vec<String> = conns
            .iter()
            .filter(|c| c.state == "ESTABLISHED" && is_external(&c.remote_addr))
            .map(|c| c.remote_addr.clone())
            .collect();
        ips.sort();
        ips.dedup();
        netmon::resolve_hosts(&ips, 60, std::time::Duration::from_secs(3))
    } else {
        std::collections::HashMap::new()
    };

    let mut hits = 0usize;
    println!(
        "live TCP endpoints: {} | malicious-port DB: {} | intel IPs: {}",
        conns.len(),
        netmon::MALICIOUS_PORTS.len(),
        intel_ips
    );
    for c in &conns {
        // Port-based flag.
        if let Some((port, name, sev)) = c.flagged() {
            hits += 1;
            println!(
                "{:<7} {}:{} -> {}:{}  [port {}] {}  ({})",
                sev.as_str().to_uppercase(),
                c.local_addr,
                c.local_port,
                c.remote_addr,
                c.remote_port,
                port,
                name,
                c.state
            );
        }
        // Intel IP-based flag (known-bad remote on any port).
        if let Some(threat) = intel.as_ref().and_then(|s| s.lookup_ip(&c.remote_addr)) {
            hits += 1;
            println!(
                "HIGH    {}:{} -> {}:{}  [intel IP] {}  ({})",
                c.local_addr, c.local_port, c.remote_addr, c.remote_port, threat, c.state
            );
        }
        // Domain IOC: match the (pre-resolved) hostname and parent domains
        // against the intel store.
        if let (Some(store), Some(host)) = (intel.as_ref(), hosts.get(&c.remote_addr)) {
            for cand in netmon::domain_candidates(host) {
                if let Some(threat) = store.lookup_domain(&cand) {
                    hits += 1;
                    println!(
                        "HIGH    {}:{} -> {} ({})  [intel domain] {}",
                        c.local_addr, c.local_port, c.remote_addr, host, threat
                    );
                    break;
                }
            }
        }
    }
    if hits == 0 {
        println!("CLEAN  no connections on malicious ports / known-bad IPs / domains");
    }
    Ok(if hits == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Real-time on-access protection: scan files as they appear/change.
fn run_watch(config: Config, args: WatchArgs) -> Result<ExitCode> {
    use aether_realtime::FileWatcher;
    use std::time::Duration;

    let scanner = Scanner::new(config).context("failed to initialize scanner")?;
    let watcher = FileWatcher::watch(&args.path).map_err(|e| anyhow::anyhow!(e))?;
    let mut vault = match &args.quarantine {
        Some(dir) => {
            Some(aether_quarantine::Vault::open(dir).map_err(|e| anyhow::anyhow!(e.to_string()))?)
        }
        None => None,
    };

    println!(
        "real-time protection active on {} - Ctrl-C to stop",
        args.path.display()
    );
    let mut recent: std::collections::HashMap<String, std::time::Instant> =
        std::collections::HashMap::new();
    loop {
        let Some(path) = watcher.next_changed(Duration::from_secs(3600)) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }
        // Debounce duplicate events for the same path within 1s.
        let key = path.to_string_lossy().into_owned();
        if recent
            .get(&key)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            continue;
        }
        recent.insert(key, std::time::Instant::now());

        if let Ok(report) = scanner.scan_file(&path) {
            if report.is_threat() {
                let worst = report
                    .verdicts
                    .iter()
                    .max_by(|a, b| a.level.cmp(&b.level))
                    .unwrap();
                println!(
                    "{:<11} {}  [{}] {}",
                    report.disposition().to_string(),
                    path.display(),
                    worst.signature,
                    worst.detail.as_deref().unwrap_or("")
                );
                if let Some(v) = &mut vault {
                    if report.disposition() == ThreatLevel::Malicious {
                        match v.quarantine_file(&path, &worst.signature) {
                            Ok(e) => println!("            -> quarantined (id {})", &e.id[..16]),
                            Err(e) => tracing::warn!(error = %e, "quarantine failed"),
                        }
                    }
                }
            }
        }
    }
}

/// Kernel-level on-access protection via fanotify (Linux) - blocks malicious
/// opens/execs before they run.
#[cfg(target_os = "linux")]
fn run_protect(mut config: Config, args: ProtectArgs) -> Result<ExitCode> {
    use aether_realtime::onaccess::OnAccessGuard;

    // On-access must be low-latency: use only the fast engines (hash + YARA +
    // heuristics + ML), never the LLM or full sandbox, per open.
    config.engines.llm = false;
    config.engines.sandbox = false;
    let scanner = Scanner::new(config).context("failed to initialize scanner")?;
    let mut vault = match &args.quarantine {
        Some(dir) => {
            Some(aether_quarantine::Vault::open(dir).map_err(|e| anyhow::anyhow!(e.to_string()))?)
        }
        None => None,
    };

    // Self-protect: become non-dumpable + OOM-resistant before going live.
    match aether_realtime::selfprotect::harden() {
        Ok(_) => tracing::info!("self-protection enabled (non-dumpable, OOM-protected)"),
        Err(e) => tracing::warn!(error = %e, "self-protection unavailable"),
    }
    let guard = OnAccessGuard::new(&args.paths).map_err(|e| anyhow::anyhow!(e))?;
    println!(
        "kernel on-access protection ACTIVE on {:?} - every open/exec is checked. Ctrl-C to stop.",
        args.paths
    );
    let mut blocked = 0u64;
    guard
        .run(args.max_read, |path, bytes| {
            let report = scanner.scan_bytes(path, bytes);
            if report.disposition() == ThreatLevel::Malicious {
                let worst = report
                    .verdicts
                    .iter()
                    .max_by(|a, b| a.level.cmp(&b.level))
                    .unwrap();
                blocked += 1;
                println!(
                    "BLOCKED  {}  [{}] {}",
                    path.display(),
                    worst.signature,
                    worst.detail.as_deref().unwrap_or("")
                );
                if let Some(v) = &mut vault {
                    match v.quarantine_file(path, &worst.signature) {
                        Ok(e) => println!("            -> quarantined (id {})", &e.id[..16]),
                        Err(e) => tracing::warn!(error = %e, "quarantine failed"),
                    }
                }
                return false; // DENY the open/exec
            }
            true // allow
        })
        .map_err(|e| anyhow::anyhow!(e))?;
    let _ = blocked;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(target_os = "linux"))]
fn run_protect(_config: Config, _args: ProtectArgs) -> Result<ExitCode> {
    eprintln!("on-access protection (fanotify) is only available on Linux");
    Ok(ExitCode::FAILURE)
}

/// Scan live process memory for injected / fileless code.
fn run_memscan(config: Config, args: MemscanArgs) -> Result<ExitCode> {
    use aether_realtime::memscan;

    let scanner = Scanner::new(config).context("failed to initialize scanner")?;
    let want_secrets = args.secrets;
    // Content-scan flagged regions with the fast engines (hash + YARA + heuristics),
    // and optionally for harvested secrets (wallet keys / seed phrases / cloud creds).
    let scan = |bytes: &[u8]| -> Vec<String> {
        let mut out = Vec::new();
        if want_secrets {
            out.extend(aether_realtime::secrets::secret_labels(bytes));
        }
        if bytes.len() >= 64 {
            let r = scanner.scan_bytes(std::path::Path::new("<process-memory>"), bytes);
            out.extend(
                r.verdicts
                    .iter()
                    .filter(|v| v.level >= ThreatLevel::Suspicious)
                    .map(|v| v.signature.clone()),
            );
        }
        out
    };

    let findings = match args.pid {
        Some(p) => memscan::scan_pid(p, scan),
        None => memscan::scan_all(scan),
    };

    let mut high = 0u64;
    for f in &findings {
        let hits = if f.matches.is_empty() {
            String::new()
        } else {
            format!("  [content: {}]", f.matches.join(", "))
        };
        println!(
            "{:<7} pid {:<7} {:<18} {} {}  {}{}",
            f.severity.to_uppercase(),
            f.pid,
            f.process,
            f.region,
            f.perms,
            f.detail,
            hits
        );
        if f.severity == "high" {
            high += 1;
        }
    }
    println!(
        "\n-- memory scan: {} suspicious region(s), {} high severity",
        findings.len(),
        high
    );
    Ok(if high > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Process Sentinel: novelty (new/unknown apps, identified by hash not name) +
/// cross-view rootkit detection (hidden processes) + stealth tells.
fn run_sentinel(config: Config, args: SentinelArgs) -> Result<ExitCode> {
    use aether_realtime::sentinel;
    use std::collections::HashMap;

    // Phase 2: live kernel-sourced exec tracing (cn_proc) - scan each process
    // the instant the kernel reports its birth.
    #[cfg(target_os = "linux")]
    if args.watch {
        let scanner = Scanner::new(config).context("engine init")?;
        println!("live kernel exec-trace (cn_proc) active - Ctrl-C to stop (needs root)");
        let res = aether_realtime::exectrace::watch_execs(|ev| {
            let exe = std::fs::read_link(format!("/proc/{}/exe", ev.pid)).ok();
            let name = sentinel::proc_name(ev.pid);
            match exe.as_ref().and_then(|p| scanner.scan_file(p).ok()) {
                Some(r) if r.is_threat() => {
                    let w = r
                        .verdicts
                        .iter()
                        .max_by(|a, b| a.level.cmp(&b.level))
                        .unwrap();
                    println!(
                        "⚠ exec pid {:<7} {:<20} {}  -> {} [{}]",
                        ev.pid,
                        name,
                        exe.as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        r.disposition(),
                        w.signature
                    );
                }
                _ => println!(
                    "  exec pid {:<7} {:<20} {}",
                    ev.pid,
                    name,
                    exe.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ),
            }
        });
        if let Err(e) = res {
            eprintln!("exec-trace unavailable: {e}");
            return Ok(ExitCode::FAILURE);
        }
        return Ok(ExitCode::SUCCESS);
    }

    let snap = sentinel::snapshot();
    // Hash each unique, readable executable once (dedupe by path).
    let mut exe_hash: HashMap<String, String> = HashMap::new();
    for p in &snap {
        if let Some(exe) = &p.exe {
            if p.exe_deleted {
                continue;
            }
            let key = exe.display().to_string();
            if let std::collections::hash_map::Entry::Vacant(slot) = exe_hash.entry(key) {
                if let Ok(data) = std::fs::read(exe) {
                    slot.insert(aether_signatures::hash_bytes(&data).sha256);
                }
            }
        }
    }

    if args.learn {
        let json = serde_json::to_string_pretty(&exe_hash).unwrap_or_default();
        std::fs::write(&args.baseline, json)
            .with_context(|| format!("writing {}", args.baseline.display()))?;
        println!(
            "baseline learned: {} executables -> {}",
            exe_hash.len(),
            args.baseline.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let baseline: HashMap<String, String> = std::fs::read_to_string(&args.baseline)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    if baseline.is_empty() {
        eprintln!(
            "no baseline at {} - run `aether sentinel --learn` on a known-clean system first",
            args.baseline.display()
        );
        return Ok(ExitCode::FAILURE);
    }

    // 1) Novelty: executables whose path is unknown, or whose content changed.
    let mut new_exes: Vec<(i32, String, String, Option<String>)> = Vec::new(); // pid,name,path,hash
    for p in &snap {
        let Some(exe) = &p.exe else { continue };
        let path = exe.display().to_string();
        let hash = exe_hash.get(&path).cloned();
        let is_new = match (baseline.get(&path), &hash) {
            (None, _) => true,                    // path never seen
            (Some(known), Some(h)) => known != h, // content changed at a known path
            (Some(_), None) => false,             // known path, couldn't re-hash -> trust
        };
        if is_new {
            new_exes.push((p.pid, p.name.clone(), path, hash));
        }
    }

    // 2) Cross-view: processes hidden from the directory listing (rootkit).
    let hidden = sentinel::hidden_pids();

    // 3) Stealth tells.
    let stealth: Vec<&sentinel::Proc> = snap
        .iter()
        .filter(|p| p.exe_deleted || p.from_temp)
        .collect();

    // Report + scan the new executables with the engine.
    let mut threats = 0u64;
    if !new_exes.is_empty() {
        println!("-- NEW / unknown executables running ({}):", new_exes.len());
        let scanner = Scanner::new(config).context("engine init")?;
        let mut scanned = std::collections::HashSet::new();
        for (pid, name, path, _h) in &new_exes {
            print!("  pid {pid:<7} {name:<20} {path}");
            if scanned.insert(path.clone()) {
                if let Ok(r) = scanner.scan_file(std::path::Path::new(path)) {
                    if r.is_threat() {
                        let w = r
                            .verdicts
                            .iter()
                            .max_by(|a, b| a.level.cmp(&b.level))
                            .unwrap();
                        print!("  ⚠ {} [{}]", r.disposition(), w.signature);
                        threats += 1;
                    } else {
                        print!("  (engine: clean)");
                    }
                }
            }
            println!();
        }
    }
    if !hidden.is_empty() {
        println!(
            "-- ⚠ HIDDEN processes (visible to kill(2) but not /proc - rootkit indicator): {:?}",
            hidden
        );
    }
    if !stealth.is_empty() {
        println!("-- stealth indicators:");
        for p in &stealth {
            let why = if p.exe_deleted {
                "executable DELETED while running"
            } else {
                "running from a temp/volatile dir"
            };
            println!(
                "  pid {:<7} {:<20} {}  - {why}",
                p.pid,
                p.name,
                p.exe
                    .as_ref()
                    .map(|e| e.display().to_string())
                    .unwrap_or_default()
            );
        }
    }
    println!(
        "\n-- sentinel: {} new · {} hidden · {} stealth · {} malicious",
        new_exes.len(),
        hidden.len(),
        stealth.len(),
        threats
    );
    Ok(if threats > 0 || !hidden.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Ransomware shield: snapshot + canaries + automatic rollback on attack.
fn run_ransomguard(args: RansomguardArgs) -> Result<ExitCode> {
    use aether_realtime::ransomguard::RansomGuard;
    let vault = args.vault.unwrap_or_else(|| args.dir.join(".aether-vault"));
    let guard = RansomGuard::arm(&args.dir, &vault).map_err(|e| anyhow::anyhow!(e))?;
    println!(
        "ransomware shield ACTIVE on {} - snapshot taken, canaries planted. Ctrl-C to stop.",
        args.dir.display()
    );
    let incident = guard
        .run(|p| tracing::debug!(path = %p.display(), "changed"))
        .map_err(|e| anyhow::anyhow!(e))?;
    println!("\n⚠ RANSOMWARE DETECTED - {}", incident.reason);
    println!(
        "   {} files affected · {} restored from snapshot (rollback complete)",
        incident.modified, incident.restored
    );
    Ok(ExitCode::FAILURE)
}

/// Self-protection: build/verify a SHA-256 manifest of critical files so
/// tampering with the engine, signature DBs or model is detected.
fn run_selfcheck(config: Config, args: SelfcheckArgs) -> Result<ExitCode> {
    let mut targets: Vec<PathBuf> = vec![
        config.engines.hash_db.clone(),
        config.engines.ndb_db.clone(),
        config.engines.ml_model.clone(),
        config.engines.llm_model.clone(),
    ];
    if let Ok(exe) = std::env::current_exe() {
        targets.push(exe);
    }
    let mut current = serde_json::Map::new();
    for p in &targets {
        if let Ok(data) = std::fs::read(p) {
            current.insert(
                p.display().to_string(),
                serde_json::Value::String(aether_signatures::hash_bytes(&data).sha256),
            );
        }
    }

    if args.write {
        std::fs::write(
            &args.manifest,
            serde_json::to_string_pretty(&current).unwrap_or_default(),
        )
        .with_context(|| format!("writing {}", args.manifest.display()))?;
        println!("integrity manifest written: {} files", current.len());
        return Ok(ExitCode::SUCCESS);
    }

    let saved: serde_json::Map<String, serde_json::Value> = std::fs::read_to_string(&args.manifest)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    if saved.is_empty() {
        eprintln!(
            "no manifest at {} - run with --write first",
            args.manifest.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    let mut tampered = 0;
    for (path, hash) in &saved {
        match current.get(path) {
            Some(h) if h == hash => println!("OK        {path}"),
            Some(_) => {
                println!("TAMPERED  {path}");
                tampered += 1;
            }
            None => {
                println!("MISSING   {path}");
                tampered += 1;
            }
        }
    }
    if tampered > 0 {
        eprintln!("\n⚠ self-check FAILED: {tampered} file(s) tampered/missing");
        Ok(ExitCode::FAILURE)
    } else {
        println!("\n✓ self-check passed: all critical files intact");
        Ok(ExitCode::SUCCESS)
    }
}

/// GET a URL, returning (status, body) and folding 4xx/5xx into Ok so callers
/// can branch on the status (a 404 from a lookup API is a normal answer).
fn http_get(url: &str) -> Result<(u16, String)> {
    use std::time::Duration;
    match ureq::get(url)
        .set("Accept", "application/json")
        .timeout(Duration::from_secs(20))
        .call()
    {
        Ok(r) => {
            let code = r.status();
            Ok((code, r.into_string().unwrap_or_default()))
        }
        Err(ureq::Error::Status(code, r)) => Ok((code, r.into_string().unwrap_or_default())),
        Err(e) => Err(anyhow::anyhow!(e.to_string())),
    }
}

/// Build a reputation allowlist hook backed by CIRCL hashlookup (no key). It
/// caches results in-memory; a 200 means the file is known-good (NSRL).
fn hashlookup_reputation() -> Box<dyn Fn(&aether_common::FileHashes) -> bool + Send + Sync> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    Box::new(move |h: &aether_common::FileHashes| {
        if h.sha256.is_empty() {
            return false;
        }
        if let Some(v) = cache.lock().unwrap().get(&h.sha256) {
            return *v;
        }
        let url = format!("https://hashlookup.circl.lu/lookup/sha256/{}", h.sha256);
        let known = matches!(http_get(&url), Ok((200, _)));
        cache.lock().unwrap().insert(h.sha256.clone(), known);
        known
    })
}

/// Cloud reputation via CIRCL hashlookup (free, no API key, 40B+ known files).
/// A hit means the file is *known* (overwhelmingly clean software / NSRL) -
/// invaluable for suppressing false positives; a miss means "unknown".
fn run_reputation(args: ReputationArgs) -> Result<ExitCode> {
    let t = args.target.trim();
    let is_hash = matches!(t.len(), 32 | 40 | 64) && t.bytes().all(|b| b.is_ascii_hexdigit());
    let (algo, hash) = if is_hash {
        let algo = match t.len() {
            32 => "md5",
            40 => "sha1",
            _ => "sha256",
        };
        (algo, t.to_ascii_lowercase())
    } else {
        let data = std::fs::read(t).with_context(|| format!("reading {t}"))?;
        ("sha256", aether_signatures::hash_bytes(&data).sha256)
    };

    let url = format!("https://hashlookup.circl.lu/lookup/{algo}/{hash}");
    println!("CIRCL hashlookup · {algo}:{hash}");
    let (code, body) = http_get(&url)?;
    match code {
        200 => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let name = v.get("FileName").and_then(|x| x.as_str()).unwrap_or("");
            let source = v
                .get("source")
                .or_else(|| v.get("DB"))
                .and_then(|x| x.as_str())
                .unwrap_or("NSRL / known software");
            println!("  ✓ KNOWN-GOOD - in the known-files database (low risk).");
            if !name.is_empty() {
                println!("    file:   {name}");
            }
            println!("    source: {source}");
            Ok(ExitCode::SUCCESS)
        }
        404 => {
            println!("  ? UNKNOWN - not in the 40B+ known-good database.");
            println!("    (unknown ≠ malicious, but combine with the local engine's verdict.)");
            Ok(ExitCode::SUCCESS)
        }
        other => {
            println!("  lookup returned HTTP {other}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Vulnerability intel via CIRCL CVE-Search (free, no API key).
fn run_cve(args: CveArgs) -> Result<ExitCode> {
    let id = args.id.trim().to_uppercase();
    let url = format!("https://cve.circl.lu/api/cve/{id}");
    let (code, body) = http_get(&url)?;
    if code != 200 || body.trim().is_empty() || body.trim() == "null" {
        println!("{id}: not found (HTTP {code})");
        return Ok(ExitCode::FAILURE);
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    // CVE 5.x record: descriptions + metrics live under containers.cna.
    let cna = v.pointer("/containers/cna");
    let desc = cna
        .and_then(|c| c.pointer("/descriptions/0/value"))
        .and_then(|x| x.as_str())
        .or_else(|| v.get("summary").and_then(|x| x.as_str()))
        .unwrap_or("(no description)");
    let published = v
        .pointer("/cveMetadata/datePublished")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let cvss = cna
        .and_then(|c| c.pointer("/metrics/0/cvssV3_1/baseScore"))
        .or_else(|| cna.and_then(|c| c.pointer("/metrics/0/cvssV3_0/baseScore")))
        .map(|x| x.to_string())
        .unwrap_or_else(|| "n/a".into());
    println!("{id}   published {published}   CVSS {cvss}");
    println!("{desc}");
    Ok(ExitCode::SUCCESS)
}

/// [Offline publisher] Ed25519-sign an intel feed with the private seed.
fn run_feedsign(args: FeedsignArgs) -> Result<ExitCode> {
    let key_hex = std::fs::read_to_string(&args.key)
        .with_context(|| format!("reading key {}", args.key.display()))?;
    let seed = <[u8; 32]>::try_from(
        hex::decode(key_hex.trim())
            .map_err(|e| anyhow::anyhow!("bad key hex: {e}"))?
            .as_slice(),
    )
    .map_err(|_| anyhow::anyhow!("private key must be 32 bytes (64 hex chars)"))?;

    let text = std::fs::read_to_string(&args.input)?;
    let mut feed =
        aether_intel::Feed::from_json(&text).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    feed.sign_ed25519(&seed);
    let out = feed.to_json().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    std::fs::write(&args.output, out)?;
    println!("✓ signed feed written: {}", args.output.display());
    Ok(ExitCode::SUCCESS)
}

/// Verify a feed against the compiled-in trusted public key - exactly the check
/// a client performs before applying an update.
fn run_feedverify(args: FeedverifyArgs) -> Result<ExitCode> {
    let text = std::fs::read_to_string(&args.feed)?;
    let feed = aether_intel::Feed::from_json(&text).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if feed.verify_trusted() {
        println!("✓ TRUSTED - signature valid; update would be applied.");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("✗ REJECTED - missing/invalid signature; a client would NOT apply this update.");
        Ok(ExitCode::FAILURE)
    }
}

/// [Offline publisher] Sign a release artifact with Ed25519 -> `<file>.sig`.
fn run_signfile(args: SignfileArgs) -> Result<ExitCode> {
    let key_hex = std::fs::read_to_string(&args.key)
        .with_context(|| format!("reading key {}", args.key.display()))?;
    let seed = <[u8; 32]>::try_from(
        hex::decode(key_hex.trim())
            .map_err(|e| anyhow::anyhow!("bad key hex: {e}"))?
            .as_slice(),
    )
    .map_err(|_| anyhow::anyhow!("private key must be 32 bytes (64 hex chars)"))?;
    let data = std::fs::read(&args.file)?;
    let sig = aether_intel::sign_detached(&seed, &data);
    let sig_path = format!("{}.sig", args.file.display());
    std::fs::write(&sig_path, sig)?;
    println!("✓ signature written: {sig_path}");
    Ok(ExitCode::SUCCESS)
}

/// Verify a release artifact against the compiled-in trusted public key - what a
/// user runs to confirm a download wasn't tampered with.
fn run_verifyfile(args: VerifyfileArgs) -> Result<ExitCode> {
    let data = std::fs::read(&args.file)?;
    let sig = std::fs::read_to_string(format!("{}.sig", args.file.display()))
        .with_context(|| "missing <file>.sig")?;
    if aether_intel::verify_detached(aether_intel::TRUSTED_FEED_PUBKEY, &data, sig.trim()) {
        println!("✓ TRUSTED - signature valid (official AetherAV release).");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("✗ REJECTED - signature invalid/missing; do NOT trust this file.");
        Ok(ExitCode::FAILURE)
    }
}

/// Opt-in, anonymous threat submission. Sends only hashes/IOCs by default (no
/// path, user, hostname or file content) - the file's bytes are included only
/// with `--include-sample`. The submitter only SENDS; nothing executable is
/// ever accepted back (the sole inbound channel is the signed feed).
fn run_submit(args: SubmitArgs) -> Result<ExitCode> {
    let data =
        std::fs::read(&args.path).with_context(|| format!("reading {}", args.path.display()))?;
    let h = aether_signatures::hash_bytes(&data);
    let mut payload = serde_json::json!({
        "schema": 1,
        "client": "aetherav",
        "sha256": h.sha256,
        "sha1": h.sha1,
        "md5": h.md5,
        "size": h.size,
    });
    if args.include_sample {
        if data.len() > 8 * 1024 * 1024 {
            eprintln!("sample too large to submit (>8MB); sending hashes only");
        } else {
            payload["sample_hex"] = serde_json::Value::String(hex::encode(&data));
        }
    }

    match &args.url {
        None => {
            println!("dry-run (no --url) - would submit ANONYMOUSLY (no path/user/host):");
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(url) => {
            if !url.starts_with("https://") {
                eprintln!("refusing to submit over a non-HTTPS endpoint");
                return Ok(ExitCode::FAILURE);
            }
            let body = serde_json::to_string(&payload).unwrap_or_default();
            match ureq::post(url)
                .timeout(std::time::Duration::from_secs(20))
                .set("Content-Type", "application/json")
                .send_string(&body)
            {
                Ok(_) => {
                    println!("✓ submitted anonymously");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("submission failed: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

/// Evaluate detection quality on labeled directories and print metrics.
fn run_eval(config: Config, args: EvalArgs) -> Result<ExitCode> {
    let scanner = Scanner::new(config).context("failed to initialize scanner")?;

    let (clean, _) = scanner
        .scan_path(&args.clean)
        .with_context(|| format!("scanning clean set {}", args.clean.display()))?;
    let (malware, _) = scanner
        .scan_path(&args.malware)
        .with_context(|| format!("scanning malware set {}", args.malware.display()))?;

    let fp = clean.iter().filter(|r| r.is_threat()).count();
    let tn = clean.len() - fp;
    let tp = malware.iter().filter(|r| r.is_threat()).count();
    let fn_ = malware.len() - tp;

    let pct = |n: usize, d: usize| {
        if d == 0 {
            0.0
        } else {
            100.0 * n as f64 / d as f64
        }
    };
    let precision = pct(tp, tp + fp);
    let recall = pct(tp, tp + fn_); // detection rate
    let fpr = pct(fp, fp + tn);
    let accuracy = pct(tp + tn, tp + tn + fp + fn_);

    println!("AetherAV detection evaluation");
    println!("  clean samples:   {}", clean.len());
    println!("  malware samples: {}", malware.len());
    println!("  +---------------+----------+----------+");
    println!("  |               | flagged  | clean    |");
    println!("  | malware (P)   | TP {tp:<5} | FN {fn_:<5} |");
    println!("  | benign  (N)   | FP {fp:<5} | TN {tn:<5} |");
    println!("  +---------------+----------+----------+");
    println!("  detection rate (recall): {recall:.2}%");
    println!("  false-positive rate:     {fpr:.2}%");
    println!("  precision:               {precision:.2}%");
    println!("  accuracy:                {accuracy:.2}%");

    if args.clamav {
        match (
            clamscan_detections(&args.malware),
            clamscan_detections(&args.clean),
        ) {
            (Some(mdet), Some(cfp)) => {
                println!("\nClamAV (clamscan) head-to-head");
                println!(
                    "  detection rate: {:.2}%  ({mdet}/{} malware)",
                    pct(mdet, malware.len()),
                    malware.len()
                );
                println!("  false positives: {cfp} on the clean set");
            }
            _ => println!("\n(clamscan not available - install ClamAV for a head-to-head)"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Count files ClamAV flags in `dir` (`<file>: <sig> FOUND`). None if unavailable.
fn clamscan_detections(dir: &std::path::Path) -> Option<usize> {
    let out = std::process::Command::new("clamscan")
        .args(["-r", "--no-summary", "-i"])
        .arg(dir)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Some(
        text.lines()
            .filter(|l| l.trim_end().ends_with("FOUND"))
            .count(),
    )
}

/// Run the HTTP/JSON daemon until interrupted.
fn run_serve(config: Config, args: ServeArgs) -> Result<ExitCode> {
    use aether_daemon::Daemon;

    let scanner = Scanner::new(config).context("failed to initialize scanner")?;
    println!("AetherAV daemon listening on http://{}", args.addr);
    println!("  GET  /health   GET /version   POST /scan   POST /behavior");
    Daemon::new(scanner)
        .serve(&args.addr)
        .with_context(|| format!("serving on {}", args.addr))?;
    Ok(ExitCode::SUCCESS)
}

fn run_config_init(config: &Config, output: PathBuf) -> Result<ExitCode> {
    let toml = config.to_toml().context("rendering config")?;
    std::fs::write(&output, toml).with_context(|| format!("writing {}", output.display()))?;
    println!("wrote default configuration to {}", output.display());
    Ok(ExitCode::SUCCESS)
}

fn run_info(config: Config) -> Result<ExitCode> {
    let scanner = Scanner::new(config).context("failed to initialize scanner")?;
    println!("AetherAV {}", env!("CARGO_PKG_VERSION"));
    println!("  hash engine:  {} signatures", scanner.signature_count());
    println!(
        "  yara engine:  {}",
        if cfg!(feature = "yara") {
            "enabled"
        } else {
            "disabled (build without --features yara)"
        }
    );
    println!(
        "  static-ML:    {}",
        if scanner.ml_loaded() {
            "model loaded"
        } else {
            "unavailable"
        }
    );
    println!("  parsers:      PE, ELF, Mach-O, PDF, Office(OLE/OOXML), scripts");
    Ok(ExitCode::SUCCESS)
}

/// Minimal hand-rolled JSON for a report (avoids pulling serde_json into the
/// CLI just for output; the structured types already derive Serialize for the
/// daemon/API path).
fn to_json(r: &aether_common::ScanReport) -> String {
    let verdicts: Vec<String> = r
        .verdicts
        .iter()
        .map(|v| {
            format!(
                r#"{{"engine":"{:?}","level":"{}","signature":"{}","score":{:.3}}}"#,
                v.engine,
                v.level,
                v.signature.replace('"', "\\\""),
                v.score
            )
        })
        .collect();
    format!(
        r#"{{"path":"{}","sha256":"{}","disposition":"{}","verdicts":[{}]}}"#,
        r.path.display(),
        r.hashes.sha256,
        r.disposition(),
        verdicts.join(",")
    )
}

// Keep the unused import warning-free in builds without threats path exercised.
#[allow(dead_code)]
fn _assert_threatlevel_display(t: ThreatLevel) -> String {
    t.to_string()
}
