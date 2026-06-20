//! Minimal ClamAV-style hex **pattern** engine (`.ndb` body signatures).
//!
//! Hashes only catch a file you've seen byte-for-byte; pattern signatures catch
//! *variants* - the same code with a different hash. This adopts ClamAV's own
//! body-signature format so we can ingest its (huge, free) `.ndb` set.
//!
//! `.ndb` line:  `MalwareName:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]`
//! HexSignature: hex bytes, `??` = any byte. We support plain hex + `??`; we
//! skip signatures using `*`, `{n}`, `(a|b)`, `[..]`, `!` (a pragmatic subset
//! that still loads the bulk of basic body signatures).
//!
//! Performance: each signature's longest literal run is its *anchor*. All
//! anchors go into one Aho-Corasick automaton (single O(n) pass over the file);
//! the full pattern (honouring `??`) is only verified around each anchor hit.

use aether_common::{Error, Result};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use std::path::Path;

struct Sig {
    name: String,
    pattern: Vec<Option<u8>>, // None == `??`
    anchor_off: usize,
    /// ClamAV TargetType: 0=any, 1=PE, 6=ELF, 7=ASCII, 9=Mach-O, …
    target: u8,
}

/// ClamAV target-type codes we map files to (others collapse to 0/"any").
pub const TARGET_ANY: u8 = 0;
pub const TARGET_PE: u8 = 1;
pub const TARGET_ELF: u8 = 6;
pub const TARGET_ASCII: u8 = 7;
pub const TARGET_MACHO: u8 = 9;

/// A compiled set of ClamAV `.ndb` hex signatures.
pub struct NdbEngine {
    sigs: Vec<Sig>,
    ac: Option<AhoCorasick>,
}

/// Minimum literal-anchor length; shorter anchors cause too many false anchors.
const MIN_ANCHOR: usize = 4;

impl NdbEngine {
    pub fn empty() -> NdbEngine {
        NdbEngine {
            sigs: Vec::new(),
            ac: None,
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<NdbEngine> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(NdbEngine::empty());
        }
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(NdbEngine::from_text(&text))
    }

    pub fn from_text(text: &str) -> NdbEngine {
        let mut sigs: Vec<Sig> = Vec::new();
        let mut anchors: Vec<Vec<u8>> = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(4, ':');
            let (Some(name), Some(target_s), Some(_offset), Some(rest)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            // Skip PUA (potentially-unwanted: packers/adware) - notoriously
            // false-positive-prone and not malware.
            if name.starts_with("PUA.") {
                continue;
            }
            let target: u8 = target_s.trim().parse().unwrap_or(0);
            // `rest` is the hex signature plus optional :MinFL:MaxFL - take the hex.
            let hex = rest.split(':').next().unwrap_or("");
            // Skip the advanced-syntax signatures we don't implement.
            if hex.is_empty()
                || hex.contains('*')
                || hex.contains('{')
                || hex.contains('(')
                || hex.contains('[')
                || hex.contains('!')
            {
                continue;
            }
            let Some(pattern) = parse_hex(hex) else {
                continue;
            };
            if pattern.len() < MIN_ANCHOR {
                continue;
            }
            let (anchor_off, anchor_len) = longest_literal(&pattern);
            if anchor_len < MIN_ANCHOR {
                continue;
            }
            let anchor: Vec<u8> = pattern[anchor_off..anchor_off + anchor_len]
                .iter()
                .map(|b| b.unwrap())
                .collect();
            anchors.push(anchor);
            sigs.push(Sig {
                name: name.to_string(),
                pattern,
                anchor_off,
                target,
            });
        }

        // ContiguousNFA builds far faster than the default DFA for ~100k
        // patterns (≈9s -> <1s) while keeping fast overlapping search.
        let ac = if anchors.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .build(&anchors)
                .ok()
        };
        NdbEngine { sigs, ac }
    }

    /// Number of loaded signatures.
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    /// Scan a buffer; return the first matching signature's malware name.
    /// `file_target` is the file's ClamAV target code (see `TARGET_*`); a
    /// signature only fires if its target is `0` (any) or equals `file_target`,
    /// so Windows-PE signatures never match a Linux ELF, etc.
    pub fn scan(&self, data: &[u8], file_target: u8) -> Option<&str> {
        let ac = self.ac.as_ref()?;
        for m in ac.find_overlapping_iter(data) {
            let sig = &self.sigs[m.pattern().as_usize()];
            if sig.target != TARGET_ANY && sig.target != file_target {
                continue; // wrong file type for this signature
            }
            let astart = m.start();
            if astart < sig.anchor_off {
                continue;
            }
            let pstart = astart - sig.anchor_off;
            if pstart + sig.pattern.len() > data.len() {
                continue;
            }
            let matches = sig.pattern.iter().enumerate().all(|(i, pb)| match pb {
                Some(b) => data[pstart + i] == *b,
                None => true, // `??` wildcard
            });
            if matches {
                return Some(&sig.name);
            }
        }
        None
    }
}

/// Parse a hex string with `??` wildcards into bytes (`None` == wildcard).
fn parse_hex(hex: &str) -> Option<Vec<Option<u8>>> {
    let b = hex.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'?' && b[i + 1] == b'?' {
            out.push(None);
        } else {
            let hi = (b[i] as char).to_digit(16)?;
            let lo = (b[i + 1] as char).to_digit(16)?;
            out.push(Some(((hi << 4) | lo) as u8));
        }
        i += 2;
    }
    Some(out)
}

/// Longest run of literal (non-wildcard) bytes -> (offset, length).
fn longest_literal(p: &[Option<u8>]) -> (usize, usize) {
    let (mut best_off, mut best_len) = (0usize, 0usize);
    let (mut cur_off, mut cur_len) = (0usize, 0usize);
    for (i, b) in p.iter().enumerate() {
        if b.is_some() {
            if cur_len == 0 {
                cur_off = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_off = cur_off;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    (best_off, best_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_plain_and_wildcard_signatures() {
        // "Win.Test" = 41 42 43 44 ?? 46  -> "ABCD<any>F"
        let db = "Win.Test.Demo:0:*:4142434445??47\n";
        let eng = NdbEngine::from_text(db);
        assert_eq!(eng.len(), 1);
        assert_eq!(eng.scan(b"....ABCDE\x00G....", 0), Some("Win.Test.Demo")); // \x00 is a valid ??
        assert_eq!(eng.scan(b"xxABCDEqGyy", 0), Some("Win.Test.Demo")); // 41 42 43 44 45 71(??) 47
        assert_eq!(eng.scan(b"xxABCDEqXyy", 0), None); // last byte must be 'G' (47)
        assert_eq!(eng.scan(b"nothing here", 0), None);
    }

    #[test]
    fn skips_advanced_syntax() {
        let db = "A:0:*:4142*4344\nB:0:*:41{4}42\nC:0:*:41(42|43)44\n";
        assert_eq!(NdbEngine::from_text(db).len(), 0);
    }
}
