//! A format-agnostic view of an executable section/segment.
//!
//! PE sections, ELF sections and Mach-O sections all reduce to the same set of
//! antivirus-relevant features: a name, a slice of raw bytes (hence entropy),
//! and memory-protection flags. Sharing one type lets the heuristic and ML
//! layers treat every object format uniformly.

use crate::entropy::{self, EntropyBand};

/// One section/segment with the features detection cares about.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub band: EntropyBand,
    pub writable: bool,
    pub executable: bool,
}

impl SectionInfo {
    /// Build a section from a raw byte range within `data`, clamping to bounds.
    pub fn from_range(
        name: impl Into<String>,
        data: &[u8],
        offset: usize,
        len: usize,
        virtual_size: u64,
        writable: bool,
        executable: bool,
    ) -> SectionInfo {
        let end = offset.saturating_add(len).min(data.len());
        let raw = data.get(offset..end).unwrap_or(&[]);
        let e = entropy::shannon(raw);
        SectionInfo {
            name: name.into(),
            virtual_size,
            raw_size: len as u64,
            entropy: e,
            band: EntropyBand::classify(e),
            writable,
            executable,
        }
    }

    /// Writable + executable simultaneously - a classic unpacker / W^X signal.
    pub fn is_wx(&self) -> bool {
        self.writable && self.executable
    }
}
