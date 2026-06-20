//! Lightweight PDF indicator scanner.
//!
//! We do not fully parse the PDF object graph (a Phase-2.x task); instead we
//! surface the well-known malicious-document indicators that AV/IR triage on:
//! embedded JavaScript, auto-execution actions, launch actions and embedded
//! files. These map cleanly to MITRE techniques and feed the heuristic engine.

/// Suspicious structural markers found in a PDF.
#[derive(Debug, Clone, Default)]
pub struct PdfIndicators {
    /// `/JavaScript` or `/JS` - script embedded in the document.
    pub javascript: bool,
    /// `/OpenAction` or `/AA` - runs something when the doc opens.
    pub auto_action: bool,
    /// `/Launch` - launches an external program.
    pub launch: bool,
    /// `/EmbeddedFile` - carries another file payload.
    pub embedded_file: bool,
    /// `/RichMedia` or `/Flash` - legacy exploit vectors.
    pub rich_media: bool,
    /// Count of object streams (`/ObjStm`) - heavy use can hide content.
    pub obj_streams: usize,
}

impl PdfIndicators {
    /// Scan raw PDF bytes for indicators.
    pub fn scan(data: &[u8]) -> PdfIndicators {
        PdfIndicators {
            javascript: contains(data, b"/JavaScript") || contains(data, b"/JS"),
            auto_action: contains(data, b"/OpenAction") || contains(data, b"/AA"),
            launch: contains(data, b"/Launch"),
            embedded_file: contains(data, b"/EmbeddedFile"),
            rich_media: contains(data, b"/RichMedia") || contains(data, b"/Flash"),
            obj_streams: count(data, b"/ObjStm"),
        }
    }

    /// Highest-risk combination: a script that runs automatically on open.
    pub fn is_high_risk(&self) -> bool {
        (self.javascript && self.auto_action) || self.launch
    }

    /// Any indicator present at all.
    pub fn any(&self) -> bool {
        self.javascript || self.auto_action || self.launch || self.embedded_file || self.rich_media
    }
}

/// Naive substring search (PDF keywords are short; sample sizes modest).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_auto_executing_js() {
        let pdf = b"%PDF-1.7 ... /OpenAction << /JS (evil) >> /JavaScript ...";
        let ind = PdfIndicators::scan(pdf);
        assert!(ind.javascript && ind.auto_action);
        assert!(ind.is_high_risk());
    }

    #[test]
    fn benign_pdf_has_no_indicators() {
        let ind = PdfIndicators::scan(b"%PDF-1.4 just text and /Pages");
        assert!(!ind.any());
        assert!(!ind.is_high_risk());
    }
}
