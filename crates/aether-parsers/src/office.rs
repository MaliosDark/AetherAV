//! Office document macro detector.
//!
//! Two container families carry VBA macros:
//!   * **OLE / CFB** (legacy `.doc`/`.xls`) - magic `D0 CF 11 E0 A1 B1 1A E1`,
//!     macros live in a `VBA` storage / `_VBA_PROJECT`.
//!   * **OOXML / ZIP** (modern `.docm`/`.xlsm`) - a ZIP whose central directory
//!     references `vbaProject.bin`.
//!
//! We detect the *presence* of macros and a few high-signal payload strings
//! without a full OLE/ZIP parse - enough for the heuristic engine to flag and
//! for a later phase to deep-parse.

/// What the detector found in an Office document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfficeIndicators {
    pub container: OfficeContainer,
    /// A VBA project is present (macros embedded).
    pub has_macros: bool,
    /// Auto-execution macro entry points (AutoOpen / Document_Open / Workbook_Open).
    pub auto_exec: bool,
    /// Shell/exec or download payload strings visible in the raw bytes.
    pub suspicious_calls: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OfficeContainer {
    Ole,
    Ooxml,
    #[default]
    None,
}

impl OfficeIndicators {
    /// Inspect raw document bytes.
    pub fn scan(data: &[u8]) -> OfficeIndicators {
        let container = if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
            OfficeContainer::Ole
        } else if data.starts_with(b"PK\x03\x04") {
            OfficeContainer::Ooxml
        } else {
            OfficeContainer::None
        };

        // `vbaProject.bin` appears in OOXML central directory; `_VBA_PROJECT`
        // and `VBA` storage names appear in OLE compound files.
        let has_macros = contains(data, b"vbaProject.bin")
            || contains(data, b"_VBA_PROJECT")
            || contains(data, b"VBA\x00")
            || contains(data, b"Macros");

        let auto_exec = contains(data, b"AutoOpen")
            || contains(data, b"Auto_Open")
            || contains(data, b"Document_Open")
            || contains(data, b"Workbook_Open");

        let suspicious_calls = contains(data, b"Shell")
            || contains(data, b"WScript.Shell")
            || contains(data, b"powershell")
            || contains(data, b"MSXML2.XMLHTTP")
            || contains(data, b"URLDownloadToFile");

        OfficeIndicators {
            container,
            has_macros,
            auto_exec,
            suspicious_calls,
        }
    }

    /// Auto-executing macro with a shell/download call - classic maldoc.
    pub fn is_high_risk(&self) -> bool {
        self.has_macros && (self.auto_exec || self.suspicious_calls)
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ooxml_macro_doc() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"...word/vbaProject.bin...AutoOpen...Shell...");
        let ind = OfficeIndicators::scan(&data);
        assert_eq!(ind.container, OfficeContainer::Ooxml);
        assert!(ind.has_macros && ind.auto_exec && ind.suspicious_calls);
        assert!(ind.is_high_risk());
    }

    #[test]
    fn detects_ole_container() {
        let data = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert_eq!(
            OfficeIndicators::scan(&data).container,
            OfficeContainer::Ole
        );
    }
}
