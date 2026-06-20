//! Best-effort extraction/unpacking via external system tools.
//!
//! Some formats have no mature pure-Rust reader (RAR) or need their original
//! tool to reverse a transform (UPX). When the relevant binary is installed we
//! shell out to it in a temp directory; when it isn't, these functions return
//! empty/`None` so the scan degrades gracefully (the container is still scanned
//! as opaque bytes). All paths are temp-scoped and size-bounded.

use crate::{ExtractedFile, Limits};
use std::path::Path;
use std::process::{Command, Stdio};

fn run(cmd: &mut Command) -> bool {
    matches!(
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(s) if s.success()
    )
}

/// Collect files from a directory tree into `ExtractedFile`s within limits.
fn collect_dir(dir: &Path, limits: Limits) -> Vec<ExtractedFile> {
    let mut out = Vec::new();
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if out.len() >= limits.max_entries {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = entry.metadata().ok();
        if meta.map(|m| m.len()).unwrap_or(0) > limits.max_entry_bytes {
            continue;
        }
        if let Ok(data) = std::fs::read(entry.path()) {
            total += data.len() as u64;
            if total > limits.max_total_bytes {
                break;
            }
            let name = entry
                .path()
                .strip_prefix(dir)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .into_owned();
            out.push(ExtractedFile { name, data });
        }
    }
    out
}

/// Extract a RAR archive using a system `7z`/`7za`/`unrar` if available.
pub fn rar_extract(data: &[u8], limits: Limits) -> Vec<ExtractedFile> {
    let Ok(tmp) = tempfile::tempdir() else {
        return Vec::new();
    };
    let rar = tmp.path().join("a.rar");
    let out = tmp.path().join("out");
    if std::fs::write(&rar, data).is_err() || std::fs::create_dir_all(&out).is_err() {
        return Vec::new();
    }
    let odir = out.display().to_string();
    // 7z handles RAR and writes to -o<dir>; unrar uses a trailing dest path.
    let ok = run(Command::new("7z")
        .args(["x", "-y", "-bso0", "-bsp0", &format!("-o{odir}")])
        .arg(&rar))
        || run(Command::new("7za")
            .args(["x", "-y", &format!("-o{odir}")])
            .arg(&rar))
        || run(Command::new("unrar")
            .args(["x", "-y", "-inul"])
            .arg(&rar)
            .arg(format!("{odir}/")));
    if !ok {
        tracing::debug!("no usable RAR extractor (7z/7za/unrar) found");
        return Vec::new();
    }
    collect_dir(&out, limits)
}

/// Decompress a UPX-packed executable using the system `upx` if available.
/// Returns the original (unpacked) bytes, or `None` if upx is missing/failed.
pub fn upx_unpack(data: &[u8]) -> Option<Vec<u8>> {
    let tmp = tempfile::tempdir().ok()?;
    let inp = tmp.path().join("in.bin");
    let outp = tmp.path().join("out.bin");
    std::fs::write(&inp, data).ok()?;
    if !run(Command::new("upx").arg("-d").arg("-o").arg(&outp).arg(&inp)) {
        return None;
    }
    std::fs::read(&outp).ok()
}

/// Whether any external extractor is available (for status reporting).
pub fn extractors_available() -> Vec<&'static str> {
    ["7z", "7za", "unrar", "upx"]
        .into_iter()
        .filter(|t| run(Command::new(*t).arg("--help")) || run(Command::new(*t).arg("-V")))
        .collect()
}
