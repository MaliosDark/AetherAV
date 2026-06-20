//! Minimal-but-useful PE (Portable Executable) parser.
//!
//! We lean on `goblin` for the structural parse and layer the antivirus-relevant
//! feature extraction on top: per-section entropy, writable+executable sections,
//! suspicious import names, and section-name anomalies. These features feed the
//! heuristic engine today and will become inputs to the static-ML model later.

use crate::section::SectionInfo;
use aether_common::{Error, Result};
use goblin::pe::PE;

/// Architecture of the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
    Arm64,
    Other(u16),
}

impl Arch {
    fn from_machine(machine: u16) -> Arch {
        // Values from winnt.h IMAGE_FILE_MACHINE_*.
        match machine {
            0x014C => Arch::X86,
            0x8664 => Arch::X64,
            0xAA64 => Arch::Arm64,
            other => Arch::Other(other),
        }
    }
}

/// Extracted, scanner-relevant view of a PE file.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub arch: Arch,
    pub is_dll: bool,
    pub entry: usize,
    pub sections: Vec<SectionInfo>,
    /// Lowercased imported symbol names (across all DLLs).
    pub imports: Vec<String>,
    pub import_dll_count: usize,
    /// True if the PE carries an Authenticode signature (certificate table
    /// present). A reputation signal - signed binaries are far less likely to be
    /// malware - not full trust-chain validation.
    pub signed: bool,
    /// The signing publisher's Common Name, if extractable from the certificate
    /// (e.g. "Microsoft Corporation"). Final trust-chain validation is delegated
    /// to the OS (WinVerifyTrust on Windows).
    pub signer: Option<String>,
    /// PE import hash (imphash) - MD5 of the normalized, ordered import list.
    /// Clusters malware that shares a toolchain / imports; `None` if no imports.
    pub imphash: Option<String>,
    /// PE header compile timestamp (COFF TimeDateStamp, unix seconds). Useful for
    /// timestomping checks (a future value, or a value far from the file's age).
    pub pe_timestamp: u32,
}

/// Compute the PE import hash (imphash): MD5 of the lowercased, ext-stripped
/// `library.function` import list, joined by `,` in import-table order. By
/// convention an ordinal import becomes `lib.ord<n>`. Matches the canonical
/// (pefile) algorithm for named imports.
pub(crate) fn imphash_entries(imports: &[(&str, &str, u16)]) -> Option<String> {
    use md5::{Digest, Md5};
    let mut parts: Vec<String> = Vec::new();
    for (dll, name, ordinal) in imports {
        let mut lib = dll.to_lowercase();
        for ext in [".dll", ".ocx", ".sys"] {
            if let Some(s) = lib.strip_suffix(ext) {
                lib = s.to_string();
                break;
            }
        }
        let func = if name.starts_with("ORDINAL ") {
            format!("ord{ordinal}")
        } else {
            name.to_lowercase()
        };
        if lib.is_empty() && func.is_empty() {
            continue;
        }
        parts.push(format!("{lib}.{func}"));
    }
    if parts.is_empty() {
        return None;
    }
    let mut h = Md5::new();
    h.update(parts.join(",").as_bytes());
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Pull Common Name (CN) strings out of a DER blob (the PKCS#7 certificate
/// table) so we can show *who* signed a PE. Lightweight scan for the CN OID
/// (2.5.4.3 = `06 03 55 04 03`), short-form lengths.
pub(crate) fn extract_cns(der: &[u8]) -> Vec<String> {
    const CN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + CN_OID.len() + 2 < der.len() {
        if &der[i..i + CN_OID.len()] == CN_OID {
            let j = i + CN_OID.len();
            let tag = der[j];
            let len = der[j + 1] as usize;
            if len < 0x80 && j + 2 + len <= der.len() {
                let val = &der[j + 2..j + 2 + len];
                let s = match tag {
                    0x0c | 0x13 | 0x16 => String::from_utf8_lossy(val).to_string(), // UTF8 / Printable / IA5
                    0x1e => {
                        // BMPString (UTF-16BE)
                        let u: Vec<u16> = val
                            .chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&u)
                    }
                    _ => String::new(),
                };
                let s = s.trim().to_string();
                if !s.is_empty() && !out.contains(&s) {
                    out.push(s);
                }
            }
            i = j + 2;
        } else {
            i += 1;
        }
    }
    out
}

impl PeInfo {
    /// Parse a PE image from its bytes.
    pub fn parse(data: &[u8]) -> Result<PeInfo> {
        let pe = PE::parse(data).map_err(|e| Error::Parser(format!("PE parse failed: {e}")))?;

        // IMAGE_SCN_MEM_WRITE / _EXECUTE characteristics flags.
        const MEM_EXECUTE: u32 = 0x2000_0000;
        const MEM_WRITE: u32 = 0x8000_0000;

        let sections = pe
            .sections
            .iter()
            .map(|s| {
                let name = s.name().unwrap_or("<invalid>").to_string();
                SectionInfo::from_range(
                    name,
                    data,
                    s.pointer_to_raw_data as usize,
                    s.size_of_raw_data as usize,
                    s.virtual_size as u64,
                    s.characteristics & MEM_WRITE != 0,
                    s.characteristics & MEM_EXECUTE != 0,
                )
            })
            .collect();

        let imports = pe.imports.iter().map(|i| i.name.to_lowercase()).collect();
        let imp_entries: Vec<(&str, &str, u16)> = pe
            .imports
            .iter()
            .map(|i| (i.dll, i.name.as_ref(), i.ordinal))
            .collect();
        let imphash = imphash_entries(&imp_entries);

        // Authenticode = a non-empty certificate table in the optional header.
        // Its virtual_address is a raw FILE offset (not an RVA).
        let cert_dir = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| oh.data_directories.get_certificate_table())
            .copied();
        let signed = cert_dir.map(|d| d.size > 0).unwrap_or(false);
        let signer = cert_dir.and_then(|d| {
            let (off, sz) = (d.virtual_address as usize, d.size as usize);
            // Skip the 8-byte WIN_CERTIFICATE header, then mine the PKCS#7 for a CN.
            if sz > 8 && off.checked_add(sz).is_some_and(|end| end <= data.len()) {
                extract_cns(&data[off + 8..off + sz]).into_iter().next()
            } else {
                None
            }
        });

        Ok(PeInfo {
            arch: Arch::from_machine(pe.header.coff_header.machine),
            is_dll: pe.is_lib,
            entry: pe.entry,
            sections,
            imports,
            import_dll_count: pe.libraries.len(),
            signed,
            signer,
            imphash,
            pe_timestamp: pe.header.coff_header.time_date_stamp,
        })
    }

    /// Highest section entropy - the single most useful packer signal.
    pub fn max_section_entropy(&self) -> f64 {
        self.sections
            .iter()
            .map(|s| s.entropy)
            .fold(0.0_f64, f64::max)
    }

    /// True if any section is simultaneously writable and executable.
    pub fn has_wx_section(&self) -> bool {
        self.sections.iter().any(SectionInfo::is_wx)
    }

    /// Heuristic UPX-packer detection via the characteristic `UPX0`/`UPX1`
    /// section names. (Real unpacking needs the UPX tool; detection is the
    /// high-value signal.)
    pub fn is_upx(&self) -> bool {
        self.sections
            .iter()
            .any(|s| s.name.to_ascii_uppercase().starts_with("UPX"))
    }

    /// Imports commonly abused for code injection / dynamic resolution.
    /// (Presence is *suspicious*, not conclusive - context matters.)
    pub fn suspicious_imports(&self) -> Vec<&str> {
        const WATCH: &[&str] = &[
            "virtualalloc",
            "virtualprotect",
            "writeprocessmemory",
            "createremotethread",
            "loadlibrarya",
            "loadlibraryw",
            "getprocaddress",
            "setwindowshookexa",
            "ntunmapviewofsection",
        ];
        self.imports
            .iter()
            .filter(|i| WATCH.contains(&i.as_str()))
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imphash_normalizes_and_hashes() {
        // Case + extension normalization must yield the same hash.
        let a = imphash_entries(&[
            ("KERNEL32.dll", "GetProcAddress", 0),
            ("USER32.DLL", "MessageBoxA", 0),
        ])
        .unwrap();
        let b = imphash_entries(&[
            ("kernel32.DLL", "getprocaddress", 0),
            ("user32", "messageboxa", 0),
        ])
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32); // MD5 hex
                                 // Ordinal import normalizes to ord<n>; empty -> None.
        assert!(imphash_entries(&[("ws2_32.dll", "ORDINAL 115", 115)]).is_some());
        assert!(imphash_entries(&[]).is_none());
    }

    #[test]
    fn extracts_common_name_from_der() {
        // CN OID (06 03 55 04 03) + PrintableString(0x13) "AetherAV CA".
        let mut der = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0b];
        der.extend_from_slice(b"AetherAV CA");
        assert_eq!(extract_cns(&der), vec!["AetherAV CA".to_string()]);
        // No CN OID -> nothing.
        assert!(extract_cns(b"no certificate here at all").is_empty());
    }

    #[test]
    fn rejects_non_pe() {
        let err = PeInfo::parse(b"not a pe at all").unwrap_err();
        assert!(matches!(err, Error::Parser(_)));
    }

    #[test]
    fn arch_mapping() {
        assert_eq!(Arch::from_machine(0x8664), Arch::X64);
        assert_eq!(Arch::from_machine(0x014C), Arch::X86);
        assert!(matches!(Arch::from_machine(0x1234), Arch::Other(0x1234)));
    }
}
