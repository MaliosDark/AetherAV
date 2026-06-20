//! `aether-parsers` - the Universal Parser Layer.
//!
//! Phase 1 ships the PE parser and the entropy primitive that the heuristic
//! engine consumes. ELF, Mach-O, PDF, OOXML, APK and script parsers slot in
//! behind the same [`FileFormat`] detection front-end in later phases.

pub mod elf;
pub mod entropy;
pub mod macho;
pub mod office;
pub mod pdf;
pub mod pe;
pub mod script;
pub mod section;

/// Coarse file-format classification from magic bytes.
///
/// Cheap to compute and used to route a sample to the right structural parser
/// before any heavy analysis runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Pe,
    Elf,
    MachO,
    Pdf,
    /// ZIP container - could be OOXML (docx/xlsx), JAR, APK, etc.
    Zip,
    Script,
    Unknown,
}

impl FileFormat {
    /// Sniff the format from the leading bytes of a file.
    pub fn detect(data: &[u8]) -> FileFormat {
        match data {
            [b'M', b'Z', ..] => FileFormat::Pe,
            [0x7F, b'E', b'L', b'F', ..] => FileFormat::Elf,
            // Mach-O: 32/64-bit and fat, both endiannesses.
            [0xFE, 0xED, 0xFA, 0xCE, ..]
            | [0xFE, 0xED, 0xFA, 0xCF, ..]
            | [0xCE, 0xFA, 0xED, 0xFE, ..]
            | [0xCF, 0xFA, 0xED, 0xFE, ..]
            | [0xCA, 0xFE, 0xBA, 0xBE, ..] => FileFormat::MachO,
            [b'%', b'P', b'D', b'F', ..] => FileFormat::Pdf,
            [b'P', b'K', 0x03, 0x04, ..] => FileFormat::Zip,
            _ if looks_like_script(data) => FileFormat::Script,
            _ => FileFormat::Unknown,
        }
    }
}

/// Heuristic: a shebang or BOM-less mostly-ASCII head suggests a script.
fn looks_like_script(data: &[u8]) -> bool {
    if data.starts_with(b"#!") {
        return true;
    }
    let head = &data[..data.len().min(256)];
    !head.is_empty()
        && head
            .iter()
            .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7E).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_formats() {
        assert_eq!(FileFormat::detect(b"MZ\x90\x00"), FileFormat::Pe);
        assert_eq!(FileFormat::detect(b"\x7FELF\x02"), FileFormat::Elf);
        assert_eq!(FileFormat::detect(b"%PDF-1.7"), FileFormat::Pdf);
        assert_eq!(FileFormat::detect(b"PK\x03\x04zip"), FileFormat::Zip);
        assert_eq!(FileFormat::detect(b"#!/bin/sh\n"), FileFormat::Script);
        assert_eq!(
            FileFormat::detect(&[0x00, 0x01, 0xFF, 0xFE]),
            FileFormat::Unknown
        );
    }

    /// Deterministic xorshift PRNG (no external dep, reproducible failures).
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Robustness fuzz: throw thousands of random and magic-prefixed buffers at
    /// every parser and assert none panics. A panic here = a crash bug on
    /// attacker-controlled input, the #1 attack surface of a scanner.
    #[test]
    fn parsers_never_panic_on_hostile_input() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let magics: &[&[u8]] = &[
            b"MZ\x90\x00",
            b"\x7fELF",
            b"%PDF-1.7",
            b"PK\x03\x04",
            &[0xCF, 0xFA, 0xED, 0xFE],
            &[0xCA, 0xFE, 0xBA, 0xBE],
            b"#!/bin/sh\n",
            &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        ];
        for i in 0..5000u64 {
            let len = (xorshift(&mut seed) % 8192) as usize;
            let mut buf: Vec<u8> = (0..len)
                .map(|_| (xorshift(&mut seed) & 0xff) as u8)
                .collect();
            // Half the time, drive deeper into a real parser via its magic.
            if len > 16 && i % 2 == 0 {
                let m = magics[(xorshift(&mut seed) as usize) % magics.len()];
                let n = m.len().min(buf.len());
                buf[..n].copy_from_slice(&m[..n]);
            }
            // None of these may panic, regardless of input.
            let _ = FileFormat::detect(&buf);
            let _ = pe::PeInfo::parse(&buf);
            let _ = elf::ElfInfo::parse(&buf);
            let _ = macho::MachoInfo::parse(&buf);
            let _ = pdf::PdfIndicators::scan(&buf);
            let _ = office::OfficeIndicators::scan(&buf);
            let _ = script::ScriptIndicators::scan(&buf);
            let _ = script::classify_lang(&buf);
            let _ = entropy::shannon(&buf);
        }
    }
}
