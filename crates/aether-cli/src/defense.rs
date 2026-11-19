use aether_common::{EngineKind, ScanReport, ThreatLevel};
use aether_config::Config;
use aether_core::Scanner;
use anyhow::{ensure, Context, Result};
use clap::Args;
use serde_json::json;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Args)]
pub struct PackArgs {
    /// Reviewed SHA-256 list in strictly sorted order. Optional names are discarded.
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Refuse publication below this count of distinct hashes (for example, 23000000).
    #[arg(long, default_value_t = 1)]
    min_entries: u64,
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

pub fn pack_signatures(args: PackArgs) -> Result<ExitCode> {
    let input = BufReader::new(File::open(&args.input).context("opening reviewed hash list")?);
    let mut staging = tempfile::NamedTempFile::new_in(output_parent(&args.output))?;
    let count =
        aether_signatures::packed::write_index(input, BufWriter::new(staging.as_file_mut()))?;
    ensure!(
        count >= args.min_entries,
        "catalog contains {count} unique signatures; {} required",
        args.min_entries
    );
    staging.as_file().sync_all()?;
    staging.persist_noclobber(&args.output)?;
    println!("{}", json!({"sha256_entries":count,"index":args.output}));
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Args)]
pub struct LearnAttackArgs {
    /// File submitted for investigation. Scans its bytes without executing it.
    file: PathBuf,
    /// Analyst-approved family label.
    #[arg(long)]
    family: String,
    /// Write the approved record to a new, explicitly selected file.
    #[arg(long, requires = "output")]
    apply: bool,
    #[arg(long)]
    output: Option<PathBuf>,
}

pub(crate) fn eligible_candidate(report: &ScanReport) -> bool {
    let independent: HashSet<_> = report
        .verdicts
        .iter()
        .filter(|v| v.level == ThreatLevel::Malicious)
        .map(|v| v.engine)
        .filter(|engine| {
            matches!(
                engine,
                EngineKind::Yara
                    | EngineKind::Heuristic
                    | EngineKind::Ml
                    | EngineKind::Sandbox
                    | EngineKind::Intel
            )
        })
        .collect();
    report.hashes.sha256.len() == 64
        && report.hashes.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        && !report.verdicts.iter().any(|v| v.engine == EngineKind::Hash)
        && independent.len() >= 2
}

pub(crate) fn record_candidate(directory: &Path, host: &str, report: &ScanReport) -> Result<()> {
    ensure!(
        eligible_candidate(report),
        "candidate lacks corroborating evidence"
    );
    let destination = directory.join(format!(
        "{}.json",
        report.hashes.sha256.to_ascii_lowercase()
    ));
    let mut staging = tempfile::NamedTempFile::new_in(directory)?;
    let engines: HashSet<_> = report
        .verdicts
        .iter()
        .filter(|v| v.level == ThreatLevel::Malicious)
        .map(|v| v.engine)
        .collect();
    serde_json::to_writer(
        &mut staging,
        &json!({"schema":"aether.signature_candidate.v1", "host":host,
               "sha256":report.hashes.sha256, "status":"review_required", "engines":engines}),
    )?;
    writeln!(staging)?;
    staging.as_file().sync_all()?;
    match staging.persist_noclobber(destination) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn learn_attack(mut config: Config, args: LearnAttackArgs) -> Result<ExitCode> {
    ensure!(
        !args.family.is_empty()
            && args.family.len() <= 96
            && args
                .family
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "invalid analyst-approved family label"
    );
    config.engines.llm = false;
    config.engines.plugins = false;
    config.engines.reputation = false;
    let report = Scanner::new(config)?.scan_file(&args.file)?;
    let candidate = eligible_candidate(&report);
    println!(
        "{}",
        json!({
            "sha256":report.hashes.sha256, "family":args.family, "eligible_for_review":candidate,
            "verdicts":report.verdicts, "approval_requested":args.apply
        })
    );
    if args.apply {
        ensure!(
            candidate,
            "requires two independent malicious verdicts and an uncataloged SHA-256 digest"
        );
        let destination = args.output.context("missing approval output")?;
        let mut staging = tempfile::NamedTempFile::new_in(output_parent(&destination))?;
        writeln!(staging, "{} {}", report.hashes.sha256, args.family)?;
        staging.as_file().sync_all()?;
        staging.persist_noclobber(destination)?;
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Args)]
pub struct HostAuditArgs {
    /// Effective configuration exported with sshd -T on the host.
    #[arg(long)]
    sshd: PathBuf,
    /// Numbered or verbose ufw status exported on the host.
    #[arg(long)]
    ufw: Option<PathBuf>,
    /// Group names exported with id -nG for the administrative account.
    #[arg(long)]
    admin_groups: Option<PathBuf>,
    /// Account sudo privileges exported with LC_ALL=C sudo -l -U <account>.
    #[arg(long)]
    sudo_listing: Option<PathBuf>,
    /// JSON report produced by cargo audit for the antivirus checkout.
    #[arg(long)]
    cargo_audit: Option<PathBuf>,
    /// Export of pending operating-system package updates.
    #[arg(long)]
    pending_packages: Option<PathBuf>,
}

fn bounded_text(path: &Path) -> Result<String> {
    let mut body = String::new();
    File::open(path)?
        .take(1_048_577)
        .read_to_string(&mut body)?;
    ensure!(body.len() <= 1_048_576, "audit input exceeds 1 MiB");
    Ok(body)
}

pub fn host_audit(args: HostAuditArgs) -> Result<ExitCode> {
    let ssh = bounded_text(&args.sshd)?;
    let effective: std::collections::HashMap<_, _> = ssh
        .lines()
        .filter_map(|line| line.split_once(' '))
        .collect();
    ensure!(
        effective.contains_key("permitrootlogin")
            && effective.contains_key("passwordauthentication"),
        "expected effective OpenSSH settings from sshd -T"
    );
    let mut count = 0;
    let mut finding = |id: &str, review: &str| {
        count += 1;
        println!(
            "{}",
            json!({"check_id":id,"recommendation":review,"remediation":"manual_review"})
        );
    };
    if effective.get("permitrootlogin") != Some(&"no") {
        finding("audit.ssh.root_login", "Verify a separate administrative login and console recovery, then set PermitRootLogin no and validate with sshd -t.");
    }
    if effective.get("passwordauthentication") != Some(&"no")
        || effective.get("kbdinteractiveauthentication") == Some(&"yes")
    {
        finding("audit.ssh.password_or_interactive", "Validate key-based access and review password and keyboard-interactive authentication, including any required second factor.");
    }
    if effective
        .get("maxauthtries")
        .is_some_and(|n| n.parse::<u32>().is_ok_and(|v| v > 4))
    {
        finding("audit.ssh.max_auth_tries", "Review MaxAuthTries and rate limits against the expected administrator login workflow.");
    }
    if effective.get("permitemptypasswords") == Some(&"yes") {
        finding("audit.ssh.empty_passwords", "Set PermitEmptyPasswords no in the managed SSH configuration, validate with sshd -t and verify access in a separate session.");
    }
    if effective
        .get("gatewayports")
        .is_some_and(|&value| value != "no")
        && effective.get("allowtcpforwarding") != Some(&"no")
        && effective.get("disableforwarding") != Some(&"yes")
    {
        finding("audit.ssh.gateway_ports", "Check whether SSH forwarding must bind outside loopback and review AllowTcpForwarding, GatewayPorts and PermitListen.");
    }
    if let Some(path) = args.ufw {
        let ufw = bounded_text(&path)?;
        if ufw.lines().any(|l| l.trim() == "Status: inactive") {
            finding("audit.firewall.ufw_inactive", "Verify the effective nftables or provider firewall policy and allow authorized SSH sources before enabling a host firewall.");
        } else if !ufw.lines().any(|l| l.trim() == "Status: active") {
            finding(
                "audit.firewall.ufw_unknown",
                "Obtain effective UFW or nftables status before assessing host filtering.",
            );
        }
        if ufw.lines().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            line.starts_with("default:") && line.contains("allow (incoming)")
        }) {
            finding("audit.firewall.allow_incoming_default", "Review the default incoming rule against the approved service inventory and confirm console recovery before changing it.");
        }
        let ports: Vec<_> = ssh
            .lines()
            .filter_map(|line| line.strip_prefix("port "))
            .collect();
        if ufw.lines().any(|line| {
            let line = line.trim();
            let line = if line.starts_with('[') {
                line.split_once(']')
                    .map_or("", |(_, rule)| rule.trim_start())
            } else {
                line
            };
            let Some((target, source)) = line.split_once("ALLOW") else {
                return false;
            };
            let target = target.split_whitespace().next().unwrap_or("");
            let port = target.strip_suffix("/tcp").unwrap_or(target);
            let mut source = source.split_whitespace();
            let address = match source.next() {
                Some("IN") => source.next(),
                Some("OUT") => None,
                address => address,
            };
            (target == "OpenSSH" || ports.contains(&port) || (ports.is_empty() && port == "22"))
                && address.is_some_and(|source| matches!(source, "Anywhere" | "0.0.0.0/0" | "::/0"))
        }) {
            finding("audit.firewall.public_ssh_rule", "Review the open SSH rule and authorized management sources. Verify an alternate access path before changing the firewall.");
        }
    }
    if let Some(path) = args.cargo_audit {
        let data: serde_json::Value = serde_json::from_str(&bounded_text(&path)?)?;
        let advisories = data["vulnerabilities"]["list"]
            .as_array()
            .context("expected cargo audit JSON vulnerability list")?;
        for item in advisories {
            if let Some(id) = item["advisory"]["id"].as_str() {
                finding(id, "Review the advisory and the fixed package version, then rebuild and validate the antivirus in staging.");
            }
        }
    }
    if let Some(path) = args.pending_packages {
        let updates = bounded_text(&path)?;
        if updates
            .lines()
            .any(|line| line.contains("[upgradable from:"))
        {
            finding("audit.system.updates_available", "Review OS package updates and applicable security advisories, then schedule maintenance and verify services after applying.");
        }
    }
    if let Some(path) = args.admin_groups {
        let groups = bounded_text(&path)?;
        if groups
            .split_whitespace()
            .any(|group| matches!(group, "docker" | "lxd" | "disk"))
        {
            finding("audit.account.privileged_group", "Review privileged group membership, sudo scope and a tested recovery login before reducing access.");
        }
    }
    if let Some(path) = args.sudo_listing {
        let listing = bounded_text(&path)?;
        if listing.lines().any(|line| {
            let Some((run_as, commands)) = line.trim_start().split_once(')') else {
                return false;
            };
            matches!(
                run_as.trim_end(),
                "(ALL" | "(ALL : ALL" | "(root" | "(root : root"
            ) && commands.trim() == "NOPASSWD: ALL"
        }) {
            finding("audit.account.passwordless_sudo_all", "Review the account's unrestricted passwordless sudo grant. Validate a least-privilege replacement with visudo -c and test recovery before removing access.");
        }
    }
    Ok(ExitCode::from(u8::from(count > 0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_common::{FileHashes, Verdict};

    #[test]
    fn review_requires_independent_non_model_evidence() {
        let mut report = ScanReport {
            path: PathBuf::from("fixture"),
            hashes: FileHashes {
                sha256: "a".repeat(64),
                ..Default::default()
            },
            verdicts: vec![
                Verdict::malicious(EngineKind::Yara, "fixture.one", 1.0),
                Verdict::malicious(EngineKind::Yara, "fixture.two", 1.0),
                Verdict::malicious(EngineKind::Llm, "fixture.model", 1.0),
            ],
            elapsed: std::time::Duration::ZERO,
        };
        assert!(!eligible_candidate(&report));
        report.verdicts.push(Verdict::malicious(
            EngineKind::Sandbox,
            "fixture.disagreed",
            1.0,
        ));
        assert!(eligible_candidate(&report));
        let review_dir = tempfile::tempdir().unwrap();
        record_candidate(review_dir.path(), "first-host", &report).unwrap();
        record_candidate(review_dir.path(), "second-host", &report).unwrap();
        let entries: Vec<_> = std::fs::read_dir(review_dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let entry = entries.into_iter().next().unwrap().unwrap();
        let document: serde_json::Value =
            serde_json::from_reader(File::open(entry.path()).unwrap()).unwrap();
        assert_eq!(document["sha256"], report.hashes.sha256);
        assert_eq!(document["host"], "first-host");
        assert_eq!(document["status"], "review_required");
        assert!(document.get("path").is_none());
        report
            .verdicts
            .push(Verdict::malicious(EngineKind::Hash, "fixture.known", 1.0));
        assert!(!eligible_candidate(&report));
    }
}
