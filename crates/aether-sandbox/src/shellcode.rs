//! Position-independent shellcode technique detection.
//!
//! Shellcode resolves its own imports and locates itself at runtime, leaving
//! recognizable instruction patterns: PEB access to find loaded modules, a
//! rotate-add hashing loop to resolve API names, and a GetPC trick to learn its
//! own address. None of these appear in normal compiled code, so each is a
//! strong indicator; together they are conclusive.

use crate::disasm::Bitness;
use crate::Finding;
use aether_common::ThreatLevel;
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

/// Scan decoded instructions for shellcode tells.
pub fn analyze(insns: &[Instruction], bitness: Bitness) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut indicators = 0u32;

    // --- PEB access (T1106 / self-resolution) ---
    // x86: fs:[0x30]   x64: gs:[0x60]
    let (seg, disp) = match bitness {
        Bitness::Bits32 => (Register::FS, 0x30u64),
        Bitness::Bits64 => (Register::GS, 0x60u64),
    };
    if insns
        .iter()
        .any(|i| i.memory_segment() == seg && i.memory_displacement64() == disp)
    {
        indicators += 1;
        findings.push(Finding::new(
            "sandbox.shellcode.peb_walk",
            ThreatLevel::Suspicious,
            0.7,
            &["T1106", "T1027"],
            format!(
                "PEB access via {:?}:[{:#x}] - runtime module/API resolution",
                seg, disp
            ),
        ));
    }

    // --- API-hashing loop: rotate (esp. ROR 13) + a backward branch ---
    let ror13 = insns.iter().any(|i| {
        matches!(i.mnemonic(), Mnemonic::Ror | Mnemonic::Rol)
            && i.op_kind(1) == OpKind::Immediate8
            && i.immediate8() == 0x0D
    });
    let has_backward_branch = insns
        .iter()
        .any(|i| i.is_jcc_short_or_near() && i.near_branch_target() <= i.ip());
    if ror13 && has_backward_branch {
        indicators += 1;
        findings.push(Finding::new(
            "sandbox.shellcode.api_hashing",
            ThreatLevel::Malicious,
            0.85,
            &["T1027"],
            "ROR-13 hashing loop - API name resolution by hash (Metasploit-style)".into(),
        ));
    }

    // --- GetPC: a near call to the immediately-following instruction ---
    // (`call $+5; pop reg`) or `fnstenv`-based GetPC.
    let getpc = insns
        .iter()
        .any(|i| i.is_call_near() && i.near_branch_target() == i.next_ip())
        || insns.iter().any(|i| i.mnemonic() == Mnemonic::Fnstenv);
    if getpc {
        indicators += 1;
        findings.push(Finding::new(
            "sandbox.shellcode.getpc",
            ThreatLevel::Suspicious,
            0.6,
            &["T1027"],
            "GetPC stub (call/pop or fnstenv) - position-independent code".into(),
        ));
    }

    // Multiple independent shellcode tells together are conclusive.
    if indicators >= 2 {
        findings.push(Finding::new(
            "sandbox.shellcode.composite",
            ThreatLevel::Malicious,
            0.95,
            &["T1027", "T1620"],
            format!("{indicators} independent shellcode techniques present"),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::decode;

    #[test]
    fn detects_x64_peb_walk() {
        // mov rax, gs:[0x60]  =>  65 48 8B 04 25 60 00 00 00
        let insns = decode(
            Bitness::Bits64,
            &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
            0x1000,
        );
        let f = analyze(&insns, Bitness::Bits64);
        assert!(f
            .iter()
            .any(|f| f.signature == "sandbox.shellcode.peb_walk"));
    }

    #[test]
    fn detects_x86_peb_walk() {
        // mov eax, fs:[0x30]  =>  64 A1 30 00 00 00
        let insns = decode(
            Bitness::Bits32,
            &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
            0x1000,
        );
        let f = analyze(&insns, Bitness::Bits32);
        assert!(f
            .iter()
            .any(|f| f.signature == "sandbox.shellcode.peb_walk"));
    }

    #[test]
    fn clean_code_quiet() {
        let insns = decode(Bitness::Bits64, &[0x48, 0x31, 0xC0, 0xC3], 0x1000);
        assert!(analyze(&insns, Bitness::Bits64).is_empty());
    }
}
