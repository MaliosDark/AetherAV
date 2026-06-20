//! `aether-sandbox` - the Dynamic Sandbox & Emulation layer.
//!
//! Two backends behind one interface:
//!
//! * **Static emulation (default, pure Rust):** a linear `iced-x86` disassembly
//!   sweep feeds the [`antievasion`] and [`shellcode`] analyzers. It needs no
//!   native dependencies and catches anti-sandbox/anti-debug tells and
//!   position-independent shellcode patterns at instruction level.
//! * **Full CPU emulation (`unicorn` feature):** the Unicorn Engine actually
//!   executes the code, hooks memory/API access, and emits high-level
//!   behavioral [`aether_behavior::Event`]s for the Phase-5 engine.
//!
//! The analyzers emit MITRE-tagged verdicts; the optional emulator emits the
//! behavioral event stream.

pub mod antievasion;
pub mod disasm;
pub mod exploit;
pub mod shellcode;

#[cfg(feature = "unicorn")]
pub mod emulator;

pub use disasm::Bitness;

use aether_common::{EngineKind, ThreatLevel, Verdict};

/// One sandbox observation, before being lowered to a [`Verdict`].
#[derive(Debug, Clone)]
pub struct Finding {
    pub signature: &'static str,
    pub level: ThreatLevel,
    pub score: f32,
    pub mitre: Vec<&'static str>,
    pub detail: String,
}

impl Finding {
    pub fn new(
        signature: &'static str,
        level: ThreatLevel,
        score: f32,
        mitre: &[&'static str],
        detail: String,
    ) -> Finding {
        Finding {
            signature,
            level,
            score,
            mitre: mitre.to_vec(),
            detail,
        }
    }

    fn into_verdict(self) -> Verdict {
        Verdict {
            engine: EngineKind::Sandbox,
            level: self.level,
            signature: self.signature.to_string(),
            score: self.score,
            mitre: self.mitre.iter().map(|s| s.to_string()).collect(),
            detail: Some(self.detail),
        }
    }
}

/// Result of analyzing a code buffer.
#[derive(Debug, Clone)]
pub struct EmulationReport {
    pub verdicts: Vec<Verdict>,
    /// Number of instructions decoded in the linear sweep.
    pub instructions: usize,
    pub bitness: Bitness,
}

impl EmulationReport {
    /// Worst severity observed.
    pub fn disposition(&self) -> ThreatLevel {
        self.verdicts
            .iter()
            .map(|v| v.level)
            .max()
            .unwrap_or(ThreatLevel::Clean)
    }

    /// Distinct MITRE ATT&CK techniques, sorted and de-duplicated.
    pub fn techniques(&self) -> Vec<String> {
        let mut t: Vec<String> = self
            .verdicts
            .iter()
            .flat_map(|v| v.mitre.iter().cloned())
            .collect();
        t.sort();
        t.dedup();
        t
    }
}

/// The sandbox engine.
#[derive(Default)]
pub struct Sandbox;

impl Sandbox {
    pub fn new() -> Sandbox {
        Sandbox
    }

    /// Statically emulate / analyze a raw code buffer (shellcode or a code
    /// section) of the given bitness.
    pub fn analyze(&self, code: &[u8], bitness: Bitness) -> EmulationReport {
        let insns = disasm::decode(bitness, code, 0x1000);
        let mut findings = antievasion::analyze(&insns);
        findings.extend(shellcode::analyze(&insns, bitness));
        tracing::debug!(
            instructions = insns.len(),
            findings = findings.len(),
            "static emulation complete"
        );
        EmulationReport {
            verdicts: findings.into_iter().map(Finding::into_verdict).collect(),
            instructions: insns.len(),
            bitness,
        }
    }

    /// Dynamically emulate `code` on a real CPU (Unicorn Engine). Requires the
    /// `unicorn` feature. Returns the execution trace (instructions executed,
    /// final IP, whether control flow left the buffer).
    #[cfg(feature = "unicorn")]
    pub fn emulate_dynamic(
        &self,
        code: &[u8],
        bitness: Bitness,
        max_insns: usize,
    ) -> Result<emulator::EmulationTrace, String> {
        emulator::emulate(code, bitness, max_insns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_shellcode_is_malicious() {
        // gs:[0x60] PEB read + GetPC (call $+0) + ret. Two tells -> composite.
        // 65 48 8B 04 25 60 00 00 00   mov rax, gs:[0x60]
        // E8 00 00 00 00               call $+5 (GetPC)
        // 58                            pop rax
        // C3                            ret
        let code = [
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
            0x58, 0xC3,
        ];
        let report = Sandbox::new().analyze(&code, Bitness::Bits64);
        assert_eq!(report.disposition(), ThreatLevel::Malicious);
        assert!(report
            .verdicts
            .iter()
            .any(|v| v.signature == "sandbox.shellcode.composite"));
        assert!(report
            .verdicts
            .iter()
            .all(|v| v.engine == EngineKind::Sandbox));
    }

    #[test]
    fn benign_code_is_clean() {
        let report = Sandbox::new().analyze(&[0x48, 0x31, 0xC0, 0xC3], Bitness::Bits64);
        assert_eq!(report.disposition(), ThreatLevel::Clean);
        assert!(report.verdicts.is_empty());
    }
}
