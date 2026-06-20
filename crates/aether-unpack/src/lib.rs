//! `aether-unpack` - container extraction so the engine can scan *inside*
//! archives, the way mature scanners do.
//!
//! Supports ZIP (covers .jar/.apk/.docx/.xlsx), GZIP and TAR. Nested containers
//! (e.g. `.tar.gz`) fall out naturally: GZIP yields one blob which the caller
//! re-detects as TAR and extracts again, bounded by a recursion depth limit.
//!
//! Every path is bounded to resist decompression bombs: per-entry cap, total
//! uncompressed cap, and max entry count.

pub mod external;

use aether_common::{Error, Result};
use std::io::{Cursor, Read};

/// A file pulled out of a container.
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// Extraction safety limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 2048,
            max_entry_bytes: 128 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Recognised container kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Zip,
    Gzip,
    Tar,
    SevenZ,
    /// Detected but not extracted in-process (needs an external `unrar`/`7z`).
    Rar,
}

/// Sniff the container type from magic bytes (`None` if not an archive).
pub fn detect(data: &[u8]) -> Option<Container> {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return Some(Container::Zip);
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return Some(Container::Gzip);
    }
    // 7z: "7z\xBC\xAF\x27\x1C"
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(Container::SevenZ);
    }
    // RAR: "Rar!\x1A\x07" (v4 and v5).
    if data.starts_with(b"Rar!\x1a\x07") {
        return Some(Container::Rar);
    }
    // TAR: "ustar" magic at offset 257.
    if data.len() >= 262 && &data[257..262] == b"ustar" {
        return Some(Container::Tar);
    }
    None
}

/// Extract members from `data` if it is a supported container, else `None`.
pub fn try_extract(data: &[u8], limits: Limits) -> Option<Vec<ExtractedFile>> {
    let container = detect(data)?;
    match extract(container, data, limits) {
        Ok(files) => Some(files),
        Err(e) => {
            tracing::debug!(?container, error = %e, "container extraction failed");
            None
        }
    }
}

/// Extract a known container kind.
pub fn extract(container: Container, data: &[u8], limits: Limits) -> Result<Vec<ExtractedFile>> {
    match container {
        Container::Zip => extract_zip(data, limits),
        Container::Gzip => extract_gzip(data, limits),
        Container::Tar => extract_tar(data, limits),
        Container::SevenZ => extract_7z(data, limits),
        // RAR has no mature pure-Rust reader; use a system 7z/unrar if present.
        Container::Rar => Ok(external::rar_extract(data, limits)),
    }
}

fn extract_7z(data: &[u8], limits: Limits) -> Result<Vec<ExtractedFile>> {
    let mut reader = sevenz_rust::SevenZReader::new(
        Cursor::new(data),
        data.len() as u64,
        sevenz_rust::Password::empty(),
    )
    .map_err(|e| Error::Parser(format!("7z: {e}")))?;
    let mut out = Vec::new();
    let mut total = 0u64;
    reader
        .for_each_entries(|entry, rd| {
            if entry.is_directory() || out.len() >= limits.max_entries {
                return Ok(true);
            }
            let mut buf = Vec::new();
            rd.take(limits.max_entry_bytes).read_to_end(&mut buf)?;
            total += buf.len() as u64;
            if total <= limits.max_total_bytes {
                out.push(ExtractedFile {
                    name: entry.name().to_string(),
                    data: buf,
                });
            }
            Ok(true)
        })
        .map_err(|e| Error::Parser(format!("7z read: {e}")))?;
    Ok(out)
}

fn extract_zip(data: &[u8], limits: Limits) -> Result<Vec<ExtractedFile>> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(data)).map_err(|e| Error::Parser(format!("zip: {e}")))?;
    let mut out = Vec::new();
    let mut total = 0u64;
    let count = archive.len().min(limits.max_entries);
    for i in 0..count {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Error::Parser(format!("zip entry {i}: {e}")))?;
        if !entry.is_file() || entry.size() > limits.max_entry_bytes {
            continue;
        }
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        entry
            .by_ref()
            .take(limits.max_entry_bytes)
            .read_to_end(&mut buf)
            .map_err(|e| Error::Parser(format!("zip read {name}: {e}")))?;
        total += buf.len() as u64;
        if total > limits.max_total_bytes {
            break;
        }
        out.push(ExtractedFile { name, data: buf });
    }
    Ok(out)
}

fn extract_gzip(data: &[u8], limits: Limits) -> Result<Vec<ExtractedFile>> {
    let mut buf = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(limits.max_total_bytes)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Parser(format!("gzip: {e}")))?;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![ExtractedFile {
        name: "gzip-content".to_string(),
        data: buf,
    }])
}

fn extract_tar(data: &[u8], limits: Limits) -> Result<Vec<ExtractedFile>> {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let mut out = Vec::new();
    let mut total = 0u64;
    let entries = archive
        .entries()
        .map_err(|e| Error::Parser(format!("tar: {e}")))?;
    for entry in entries {
        if out.len() >= limits.max_entries {
            break;
        }
        let mut entry = entry.map_err(|e| Error::Parser(format!("tar entry: {e}")))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "tar-entry".to_string());
        let mut buf = Vec::new();
        entry
            .by_ref()
            .take(limits.max_entry_bytes)
            .read_to_end(&mut buf)
            .map_err(|e| Error::Parser(format!("tar read {name}: {e}")))?;
        total += buf.len() as u64;
        if total > limits.max_total_bytes {
            break;
        }
        out.push(ExtractedFile { name, data: buf });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(name: &str, content: &[u8]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            w.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(content).unwrap();
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn detects_and_extracts_zip() {
        let z = make_zip("inner.txt", b"hello inside the zip");
        assert_eq!(detect(&z), Some(Container::Zip));
        let files = try_extract(&z, Limits::default()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "inner.txt");
        assert_eq!(files[0].data, b"hello inside the zip");
    }

    #[test]
    fn extracts_gzip() {
        // gzip of "payload" produced via flate2 so the test is self-contained.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"payload bytes").unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(detect(&gz), Some(Container::Gzip));
        let files = try_extract(&gz, Limits::default()).unwrap();
        assert_eq!(files[0].data, b"payload bytes");
    }

    #[test]
    fn non_archive_is_none() {
        assert!(detect(b"MZ\x90\x00 not an archive").is_none());
        assert!(try_extract(b"plain text", Limits::default()).is_none());
    }

    #[test]
    fn extraction_never_panics_on_hostile_input() {
        let mut seed = 0xDEAD_BEEF_1234_5678u64;
        let magics: &[&[u8]] = &[
            b"PK\x03\x04",
            &[0x1f, 0x8b],
            &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            b"Rar!\x1a\x07",
        ];
        for i in 0..3000u64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 6000) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|j| (seed.wrapping_add(j as u64) & 0xff) as u8)
                .collect();
            if len > 16 {
                let m = magics[(i as usize) % magics.len()];
                let n = m.len().min(buf.len());
                buf[..n].copy_from_slice(&m[..n]);
            }
            // Malformed archives must error, never crash.
            let _ = try_extract(&buf, Limits::default());
        }
    }

    #[test]
    fn entry_count_is_capped() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            for i in 0..10 {
                w.start_file(
                    format!("f{i}.txt"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
                w.write_all(b"x").unwrap();
            }
            w.finish().unwrap();
        }
        let z = buf.into_inner();
        let limits = Limits {
            max_entries: 3,
            ..Default::default()
        };
        assert_eq!(try_extract(&z, limits).unwrap().len(), 3);
    }
}
