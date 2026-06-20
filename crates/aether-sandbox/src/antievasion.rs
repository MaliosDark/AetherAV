//! Anti-analysis / anti-evasion technique detection.
//!
//! Malware that fingerprints sandboxes or debuggers before detonating is a 2026
//! staple. These tells are visible at the instruction level without executing
//! anything, so the static disassembly backend catches them cheaply. Each maps
//! to a MITRE Defense-Evasion technique.

use crate::Finding;
use aether_common::ThreatLevel;
use iced_x86::{Instruction, Mnemonic, OpKind};

/// VMware backdoor magic 'VMXh' used with the `in`/`out` IO port 0x5658.
const VMWARE_MAGIC: u64 = 0x564D_5868;

/// Scan decoded instructions for anti-evasion techniques.
pub fn analyze(insns: &[Instruction]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // --- Timing-based evasion: rdtsc / rdtscp deltas (T1497.003) ---
    let rdtsc = insns
        .iter()
        .filter(|i| matches!(i.mnemonic(), Mnemonic::Rdtsc | Mnemonic::Rdtscp))
        .count();
    if rdtsc >= 2 {
        findings.push(Finding::new(
            "sandbox.evasion.timing",
            ThreatLevel::Suspicious,
            0.6,
            &["T1497.003"],
            format!("{rdtsc} rdtsc/rdtscp reads - timing-based sandbox/debugger evasion"),
        ));
    }

    // --- Descriptor-table VM checks: Red Pill / No Pill (T1497.001) ---
    let dt = insns
        .iter()
        .filter(|i| {
            matches!(
                i.mnemonic(),
                Mnemonic::Sidt | Mnemonic::Sgdt | Mnemonic::Sldt | Mnemonic::Smsw
            )
        })
        .count();
    if dt > 0 {
        findings.push(Finding::new(
            "sandbox.evasion.descriptor_table",
            ThreatLevel::Suspicious,
            0.65,
            &["T1497.001"],
            "descriptor-table read (sidt/sgdt/sldt) - classic VM-detection (Red Pill)".into(),
        ));
    }

    // --- VMware backdoor IO port (T1497.001) ---
    let has_magic = insns.iter().any(|i| has_immediate(i, VMWARE_MAGIC));
    let has_io = insns.iter().any(|i| {
        matches!(
            i.mnemonic(),
            Mnemonic::In | Mnemonic::Out | Mnemonic::Insb | Mnemonic::Outsb
        )
    });
    if has_magic && has_io {
        findings.push(Finding::new(
            "sandbox.evasion.vmware_backdoor",
            ThreatLevel::Malicious,
            0.85,
            &["T1497.001"],
            "VMware backdoor probe ('VMXh' + IO port) - virtualization detection".into(),
        ));
    }

    // --- Anti-debug interrupts: int3 scanning, int 2dh (T1622) ---
    let int3 = insns
        .iter()
        .filter(|i| i.mnemonic() == Mnemonic::Int3)
        .count();
    let int2d = insns
        .iter()
        .any(|i| i.mnemonic() == Mnemonic::Int && immediate8_eq(i, 0x2D));
    if int2d || int3 >= 3 {
        findings.push(Finding::new(
            "sandbox.evasion.anti_debug",
            ThreatLevel::Suspicious,
            0.6,
            &["T1622"],
            format!("anti-debug interrupts (int3 x{int3}, int 2dh: {int2d})"),
        ));
    }

    // --- CPUID hypervisor-bit / vendor check (weak on its own) (T1497.001) ---
    if insns.iter().any(|i| i.mnemonic() == Mnemonic::Cpuid) {
        findings.push(Finding::new(
            "sandbox.evasion.cpuid",
            ThreatLevel::Suspicious,
            0.4,
            &["T1497.001"],
            "cpuid - may read the hypervisor-present bit / vendor string".into(),
        ));
    }

    findings
}

/// True if any operand of `insn` is an immediate equal to `value`.
fn has_immediate(insn: &Instruction, value: u64) -> bool {
    (0..insn.op_count()).any(|op| match insn.op_kind(op) {
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate64 => insn.immediate(op) == value,
        _ => false,
    })
}

/// True if `insn` has an 8-bit immediate equal to `value`.
fn immediate8_eq(insn: &Instruction, value: u8) -> bool {
    (0..insn.op_count())
        .any(|op| insn.op_kind(op) == OpKind::Immediate8 && insn.immediate8() == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{decode, Bitness};

    #[test]
    fn detects_rdtsc_timing() {
        // rdtsc; ...; rdtsc  (0F 31 twice)
        let insns = decode(Bitness::Bits64, &[0x0F, 0x31, 0x90, 0x0F, 0x31], 0x1000);
        let f = analyze(&insns);
        assert!(f.iter().any(|f| f.signature == "sandbox.evasion.timing"));
    }

    #[test]
    fn detects_red_pill_sidt() {
        // sidt [rsp]  (0F 01 0C 24)
        let insns = decode(Bitness::Bits64, &[0x0F, 0x01, 0x0C, 0x24], 0x1000);
        let f = analyze(&insns);
        assert!(f
            .iter()
            .any(|f| f.signature == "sandbox.evasion.descriptor_table"));
    }

    #[test]
    fn clean_code_has_no_findings() {
        // xor rax,rax ; ret
        let insns = decode(Bitness::Bits64, &[0x48, 0x31, 0xC0, 0xC3], 0x1000);
        assert!(analyze(&insns).is_empty());
    }
}
