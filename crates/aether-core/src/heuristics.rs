//! Static heuristic engine.
//!
//! Heuristics turn structural features (from `aether-parsers`) into a weighted
//! suspicion score. They are deliberately explainable: every point added is
//! recorded with a reason, so a verdict can tell the analyst *why*. This is the
//! seam where the static-ML model will later plug in - same inputs, learned
//! weights instead of hand-tuned ones.

use aether_common::{EngineKind, ThreatLevel, Verdict};
use aether_parsers::elf::ElfInfo;
use aether_parsers::entropy::EntropyBand;
use aether_parsers::macho::MachoInfo;
use aether_parsers::office::OfficeIndicators;
use aether_parsers::pdf::PdfIndicators;
use aether_parsers::pe::PeInfo;
use aether_parsers::script::ScriptIndicators;

/// Accumulates weighted evidence and explanations.
#[derive(Default)]
struct Score {
    total: f32,
    reasons: Vec<String>,
}

impl Score {
    fn add(&mut self, weight: f32, reason: impl Into<String>) {
        self.total += weight;
        self.reasons.push(reason.into());
    }

    /// Turn accumulated evidence into a verdict if it meets `threshold`.
    fn finish(
        self,
        threshold: f32,
        signature: &str,
        level: ThreatLevel,
        mitre: &[&str],
    ) -> Option<Verdict> {
        let confidence = self.total.min(1.0);
        if confidence < threshold {
            return None;
        }
        Some(Verdict {
            engine: EngineKind::Heuristic,
            level,
            signature: signature.to_string(),
            score: confidence,
            mitre: mitre.iter().map(|s| s.to_string()).collect(),
            detail: Some(self.reasons.join("; ")),
        })
    }
}

/// Run PE heuristics. Returns a verdict if the score meets `threshold`.
///
/// `threshold` comes from `ScanConfig::heuristic_threshold` (default 0.75).
pub fn analyze_pe(pe: &PeInfo, threshold: f32) -> Option<Verdict> {
    let mut score = Score::default();

    // 1) Packed/encrypted sections - the strongest single static signal.
    for s in &pe.sections {
        match s.band {
            EntropyBand::VeryHigh => score.add(
                0.45,
                format!("section {:?} entropy {:.2} (very high)", s.name, s.entropy),
            ),
            EntropyBand::High => score.add(
                0.20,
                format!("section {:?} entropy {:.2} (high)", s.name, s.entropy),
            ),
            _ => {}
        }
    }

    // 2) W^X violation: writable + executable section (self-modifying / unpacker).
    if pe.has_wx_section() {
        score.add(0.35, "writable+executable section (W^X violation)");
    }

    // 3) Injection / dynamic-resolution import combo.
    let sus = pe.suspicious_imports();
    if sus.contains(&"virtualalloc")
        && (sus.contains(&"writeprocessmemory") || sus.contains(&"createremotethread"))
    {
        score.add(
            0.40,
            format!("process-injection import combo: {}", sus.join(", ")),
        );
    } else if sus.len() >= 3 {
        score.add(
            0.15,
            format!("multiple watched imports: {}", sus.join(", ")),
        );
    }

    // 4) Section-name anomalies (common with custom packers / stripped headers).
    if pe
        .sections
        .iter()
        .any(|s| s.name.is_empty() || s.name == "<invalid>")
    {
        score.add(0.10, "anonymous / malformed section name");
    }

    // 5) Very few imports in a sizeable executable hints at packing.
    if pe.imports.len() <= 2 && !pe.is_dll && pe.max_section_entropy() > 7.0 {
        score.add(0.20, "tiny import table with high entropy (likely packed)");
    }

    // 6) UPX packer (UPX0/UPX1 sections). Packing alone isn't malware, but it
    //    is a strong obfuscation signal that compounds with the above.
    if pe.is_upx() {
        score.add(0.25, "UPX-packed executable (UPX section names)");
    }

    let mitre: &[&str] = if sus.contains(&"writeprocessmemory") {
        &["T1055"] // Process Injection
    } else {
        &[]
    };
    score.finish(
        threshold,
        "pe.static.heuristic",
        ThreatLevel::Suspicious,
        mitre,
    )
}

/// ELF static heuristics - the Linux analogue of [`analyze_pe`].
pub fn analyze_elf(elf: &ElfInfo, threshold: f32) -> Option<Verdict> {
    let mut score = Score::default();

    // High entropy is a WEAK signal counted ONCE (not per-section): large legit
    // statically-linked binaries (e.g. Go) have several high-entropy sections -
    // stacking them produced false positives on docker/cloudflared. Real packers
    // pair high entropy with a W^X segment, which is the strong signal below.
    let top = elf.sections.iter().map(|s| s.band).max_by_key(|b| match b {
        EntropyBand::VeryHigh => 2,
        EntropyBand::High => 1,
        _ => 0,
    });
    match top {
        Some(EntropyBand::VeryHigh) => score.add(
            0.30,
            format!(
                "max section entropy {:.2} (very high)",
                elf.max_section_entropy()
            ),
        ),
        Some(EntropyBand::High) => score.add(
            0.12,
            format!(
                "max section entropy {:.2} (high)",
                elf.max_section_entropy()
            ),
        ),
        _ => {}
    }

    // RWX PT_LOAD segment - the ELF W^X violation, the strong packer/dropper tell.
    if elf.has_rwx_segment {
        score.add(0.45, "RWX loadable segment (W^X violation)");
    }

    score.finish(
        threshold,
        "elf.static.heuristic",
        ThreatLevel::Suspicious,
        &[],
    )
}

/// Mach-O static heuristics.
pub fn analyze_macho(macho: &MachoInfo, threshold: f32) -> Option<Verdict> {
    let mut score = Score::default();
    for s in &macho.sections {
        if s.band == EntropyBand::VeryHigh {
            score.add(
                0.40,
                format!("section {:?} entropy {:.2} (very high)", s.name, s.entropy),
            );
        }
    }
    if macho.has_wx_section {
        score.add(0.40, "writable+executable segment (W^X violation)");
    }
    score.finish(
        threshold,
        "macho.static.heuristic",
        ThreatLevel::Suspicious,
        &[],
    )
}

/// PDF structural heuristics - maps to script-in-document techniques.
pub fn analyze_pdf(ind: &PdfIndicators, threshold: f32) -> Option<Verdict> {
    let mut score = Score::default();
    if ind.javascript {
        score.add(0.30, "embedded JavaScript (/JS)");
    }
    if ind.auto_action {
        score.add(0.25, "auto-execution action (/OpenAction or /AA)");
    }
    if ind.launch {
        score.add(0.45, "launch action (/Launch) - runs external program");
    }
    if ind.embedded_file {
        score.add(0.20, "embedded file payload (/EmbeddedFile)");
    }
    if ind.rich_media {
        score.add(0.15, "rich-media / Flash object (legacy exploit vector)");
    }

    // T1204 User Execution / T1059 Command and Scripting Interpreter.
    let mitre: &[&str] = if ind.javascript || ind.launch {
        &["T1204", "T1059"]
    } else {
        &[]
    };
    score.finish(
        threshold,
        "pdf.static.heuristic",
        ThreatLevel::Suspicious,
        mitre,
    )
}

/// Office macro heuristics - maldoc detection.
pub fn analyze_office(ind: &OfficeIndicators, threshold: f32) -> Option<Verdict> {
    let mut score = Score::default();
    if ind.has_macros {
        score.add(0.35, "VBA macros present");
    }
    if ind.auto_exec {
        score.add(0.35, "auto-executing macro (AutoOpen/Document_Open)");
    }
    if ind.suspicious_calls {
        score.add(0.35, "shell/download call in macro body");
    }
    // T1566 Phishing / T1059.005 Visual Basic.
    let mitre: &[&str] = if ind.has_macros {
        &["T1566", "T1059.005"]
    } else {
        &[]
    };
    score.finish(
        threshold,
        "office.macro.heuristic",
        ThreatLevel::Suspicious,
        mitre,
    )
}

/// Script obfuscation heuristics - fileless / LOLBin detection.
pub fn analyze_script(ind: &ScriptIndicators, threshold: f32) -> Option<Verdict> {
    let mut score = Score::default();
    if ind.dynamic_exec {
        score.add(0.30, "dynamic code execution (IEX/eval)");
    }
    if ind.encoded_cmd {
        score.add(0.30, "encoded command / hidden window");
    }
    if ind.network && ind.dynamic_exec {
        score.add(0.30, "network download + execute (dropper cradle)");
    } else if ind.network {
        score.add(0.15, "network download");
    }
    if ind.base64_decode {
        score.add(0.15, "base64 payload decoding");
    }
    if ind.char_codes {
        score.add(0.15, "char-code string reconstruction (obfuscation)");
    }
    if ind.entropy > 5.5 && ind.signal_count() >= 2 {
        score.add(0.10, format!("elevated script entropy {:.2}", ind.entropy));
    }
    // T1059 Command and Scripting Interpreter; T1027 Obfuscated Files.
    let mitre: &[&str] = if ind.signal_count() >= 2 {
        &["T1059", "T1027"]
    } else {
        &["T1059"]
    };
    score.finish(
        threshold,
        "script.obfuscation.heuristic",
        ThreatLevel::Suspicious,
        mitre,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_parsers::pdf::PdfIndicators;
    use aether_parsers::script::ScriptIndicators;

    #[test]
    fn pdf_launch_action_flags() {
        let ind = PdfIndicators {
            launch: true,
            ..Default::default()
        };
        let v = analyze_pdf(&ind, 0.4).expect("launch should flag");
        assert!(v.mitre.contains(&"T1059".to_string()));
    }

    #[test]
    fn script_dropper_cradle_flags() {
        let ind = ScriptIndicators {
            dynamic_exec: true,
            network: true,
            encoded_cmd: true,
            ..Default::default()
        };
        let v = analyze_script(&ind, 0.5);
        assert!(v.is_some());
    }

    #[test]
    fn quiet_script_does_not_flag() {
        let ind = ScriptIndicators::default();
        assert!(analyze_script(&ind, 0.5).is_none());
    }
}
