//! Thin wrapper over `iced-x86` to decode a code buffer into instructions.
//!
//! Decoding is linear-sweep from the buffer start. That is intentionally simple:
//! the sandbox analyzers look for *instruction-level* tells (timing checks, VM
//! probes, PEB walks, hash loops), which a linear sweep surfaces well. Invalid
//! bytes are skipped one at a time so a few bad bytes don't abort the sweep.

use iced_x86::{Code, Decoder, DecoderOptions, Instruction};

/// Target bitness of the code under analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    pub fn value(self) -> u32 {
        match self {
            Bitness::Bits32 => 32,
            Bitness::Bits64 => 64,
        }
    }
}

/// Decode `code` (loaded at virtual address `base`) into a vector of valid
/// instructions.
pub fn decode(bitness: Bitness, code: &[u8], base: u64) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(bitness.value(), code, base, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut insn = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.code() != Code::INVALID {
            out.push(insn);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::Mnemonic;

    #[test]
    fn decodes_simple_x64() {
        // 48 31 c0 = xor rax, rax ; c3 = ret
        let insns = decode(Bitness::Bits64, &[0x48, 0x31, 0xC0, 0xC3], 0x1000);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic(), Mnemonic::Xor);
        assert_eq!(insns[1].mnemonic(), Mnemonic::Ret);
    }
}
