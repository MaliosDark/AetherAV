use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use aether_common::ScanReport;
use aether_config::Config;
use aether_core::Scanner;
use anyhow::{ensure, Context, Result};

use crate::EvalArgs;

const MIN_RECALL: f64 = 0.9899;
const MAX_FPR: f64 = 0.0029;

pub(super) fn run(mut config: Config, args: EvalArgs) -> Result<ExitCode> {
    // Always include files in nested corpus directories.
    config.scan.recursive = true;
    let scanner = Scanner::new(config).context("failed to initialize scanner")?;

    let (clean, clean_summary) = scanner
        .scan_path(&args.clean)
        .context("scanning clean set")?;
    let (malware, malware_summary) = scanner
        .scan_path(&args.malware)
        .context("scanning malware set")?;
    ensure!(
        clean_summary.errors == 0 && malware_summary.errors == 0,
        "evaluation incomplete: {} clean and {} malware traversal or scan errors",
        clean_summary.errors,
        malware_summary.errors
    );
    let benign = unique_verdicts(&clean, "clean")?;
    let malicious = unique_verdicts(&malware, "malware")?;
    ensure!(
        !benign.keys().any(|hash| malicious.contains_key(hash)),
        "evaluation has identical content with both clean and malware labels"
    );

    let fp = positives(&benign);
    let tn = benign.len() - fp;
    let tp = positives(&malicious);
    let fn_ = malicious.len() - tp;
    let (recall_low, recall_high) = wilson(tp, malicious.len());
    let (fpr_low, fpr_high) = wilson(fp, benign.len());
    let passed = recall_low >= MIN_RECALL && fpr_high <= MAX_FPR;

    println!("AetherAV detection evaluation");
    println!("  clean samples:   {}", benign.len());
    println!("  malware samples: {}", malicious.len());
    println!(
        "  SHA-256 duplicates excluded: {} clean, {} malware",
        clean.len() - benign.len(),
        malware.len() - malicious.len()
    );
    println!("  +---------------+----------+----------+");
    println!("  |               | flagged  | clean    |");
    println!("  | malware (P)   | TP {tp:<5} | FN {fn_:<5} |");
    println!("  | benign  (N)   | FP {fp:<5} | TN {tn:<5} |");
    println!("  +---------------+----------+----------+");
    println!(
        "  detection rate (recall): {:.2}% (95% CI {:.2}% to {:.2}%)",
        pct(tp, malicious.len()),
        recall_low * 100.0,
        recall_high * 100.0
    );
    println!(
        "  false-positive rate:     {:.2}% (95% CI {:.2}% to {:.2}%)",
        pct(fp, benign.len()),
        fpr_low * 100.0,
        fpr_high * 100.0
    );
    if tp + fp == 0 {
        println!("  precision:               undefined (zero detections)");
    } else {
        println!("  precision:               {:.2}%", pct(tp, tp + fp));
    }
    println!(
        "  accuracy:                {:.2}%",
        pct(tp + tn, benign.len() + malicious.len())
    );

    if args.clamav {
        if benign.len() == clean.len() && malicious.len() == malware.len() {
            match (
                clamscan_detections(&args.malware),
                clamscan_detections(&args.clean),
            ) {
                (Some(mdet), Some(cfp)) if mdet <= malicious.len() && cfp <= benign.len() => {
                    println!("\nClamAV (clamscan) head-to-head");
                    println!(
                        "  detection rate: {:.2}%  ({mdet}/{} malware)",
                        pct(mdet, malicious.len()),
                        malicious.len()
                    );
                    println!("  false positives: {cfp} on the clean set");
                }
                _ => println!("\nClamAV comparison unavailable or incomplete"),
            }
        } else {
            println!("\nClamAV comparison requires a corpus without duplicate files");
        }
    }
    if args.release_gate {
        println!(
            "  release gate (95% recall lower bound >= 98.99%; FPR upper bound <= 0.29%): {}",
            if passed { "PASS" } else { "FAIL" }
        );
        if !passed {
            return Ok(ExitCode::from(3));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn unique_verdicts<'a>(reports: &'a [ScanReport], label: &str) -> Result<HashMap<&'a str, bool>> {
    ensure!(
        !reports.is_empty(),
        "{label} corpus contains no scanned files"
    );
    let mut unique = HashMap::new();
    for report in reports {
        let hash = report.hashes.sha256.as_str();
        ensure!(
            !hash.is_empty(),
            "{label} corpus includes an unscanned file (check scan size limit): {}",
            report.path.display()
        );
        let flagged = report.is_threat();
        if let Some(previous) = unique.insert(hash, flagged) {
            ensure!(
                previous == flagged,
                "{label} corpus has inconsistent decisions for SHA-256 {hash}"
            );
        }
    }
    Ok(unique)
}

fn positives(class: &HashMap<&str, bool>) -> usize {
    class.values().filter(|&&flagged| flagged).count()
}

fn pct(n: usize, d: usize) -> f64 {
    100.0 * n as f64 / d as f64
}

fn wilson(observed: usize, total: usize) -> (f64, f64) {
    let n = total as f64;
    let p = observed as f64 / n;
    let z: f64 = 1.959_963_984_54;
    let denominator = 1.0 + z.powi(2) / n;
    let center = p + z.powi(2) / (2.0 * n);
    let margin = z * ((p * (1.0 - p) + z.powi(2) / (4.0 * n)) / n).sqrt();
    (
        ((center - margin) / denominator).max(0.0),
        ((center + margin) / denominator).min(1.0),
    )
}

fn clamscan_detections(dir: &Path) -> Option<usize> {
    let out = aether_common::quiet_command("clamscan")
        .args(["-r", "--no-summary", "-i", "--"])
        .arg(dir)
        .output()
        .ok()?;
    if !matches!(out.status.code(), Some(0 | 1)) {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|line| line.trim_end().ends_with(" FOUND"))
            .count(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_requires_enough_samples_even_for_perfect_results() {
        assert!(wilson(1, 1).0 < MIN_RECALL);
        assert!(wilson(0, 500).1 > MAX_FPR);
        assert!(wilson(5_000, 5_000).0 > MIN_RECALL);
        assert!(wilson(0, 5_000).1 < MAX_FPR);
    }

    #[test]
    fn skipped_files_cannot_count_as_clean() {
        let report = ScanReport {
            path: "oversized".into(),
            hashes: Default::default(),
            verdicts: vec![],
            elapsed: Default::default(),
        };
        assert!(unique_verdicts(&[report], "clean").is_err());
    }
}
