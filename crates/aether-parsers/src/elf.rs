//! ELF parser - Linux/Unix executables and shared objects.
//!
//! Feature extraction mirrors the PE parser so the heuristic/ML layers stay
//! format-agnostic: per-section entropy, RWX segments (the ELF analogue of a
//! W^X violation), and the dynamic dependency list.

use crate::section::SectionInfo;
use aether_common::{Error, Result};
use goblin::elf::Elf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfArch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Riscv,
    Other(u16),
}

impl ElfArch {
    fn from_machine(m: u16) -> ElfArch {
        // values from elf.h EM_*
        match m {
            3 => ElfArch::X86,
            62 => ElfArch::X86_64,
            40 => ElfArch::Arm,
            183 => ElfArch::Aarch64,
            243 => ElfArch::Riscv,
            other => ElfArch::Other(other),
        }
    }
}

/// Scanner-relevant view of an ELF object.
#[derive(Debug, Clone)]
pub struct ElfInfo {
    pub arch: ElfArch,
    pub is_lib: bool,
    pub entry: u64,
    pub sections: Vec<SectionInfo>,
    pub libraries: Vec<String>,
    /// True if any PT_LOAD segment is simultaneously writable and executable.
    pub has_rwx_segment: bool,
    /// True if the binary is statically linked (no interpreter / dynamic libs).
    pub is_static: bool,
}

impl ElfInfo {
    pub fn parse(data: &[u8]) -> Result<ElfInfo> {
        let elf = Elf::parse(data).map_err(|e| Error::Parser(format!("ELF parse failed: {e}")))?;

        // Program-header flags: PF_X=1, PF_W=2, PF_R=4. PT_LOAD=1.
        const PT_LOAD: u32 = 1;
        const PF_X: u32 = 1;
        const PF_W: u32 = 2;
        let has_rwx_segment = elf
            .program_headers
            .iter()
            .any(|ph| ph.p_type == PT_LOAD && (ph.p_flags & PF_W != 0) && (ph.p_flags & PF_X != 0));

        // Section header flags: SHF_WRITE=0x1, SHF_EXECINSTR=0x4.
        const SHF_WRITE: u64 = 0x1;
        const SHF_EXEC: u64 = 0x4;
        let sections = elf
            .section_headers
            .iter()
            .map(|sh| {
                let name = elf
                    .shdr_strtab
                    .get_at(sh.sh_name)
                    .unwrap_or("<invalid>")
                    .to_string();
                SectionInfo::from_range(
                    name,
                    data,
                    sh.sh_offset as usize,
                    sh.sh_size as usize,
                    sh.sh_size,
                    sh.sh_flags & SHF_WRITE != 0,
                    sh.sh_flags & SHF_EXEC != 0,
                )
            })
            .collect();

        let libraries = elf.libraries.iter().map(|s| s.to_string()).collect();
        let is_static = elf.interpreter.is_none() && elf.libraries.is_empty();

        Ok(ElfInfo {
            arch: ElfArch::from_machine(elf.header.e_machine),
            is_lib: elf.is_lib,
            entry: elf.entry,
            sections,
            libraries,
            has_rwx_segment,
            is_static,
        })
    }

    pub fn max_section_entropy(&self) -> f64 {
        self.sections
            .iter()
            .map(|s| s.entropy)
            .fold(0.0_f64, f64::max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(matches!(
            ElfInfo::parse(b"MZ not elf"),
            Err(Error::Parser(_))
        ));
    }

    #[test]
    fn arch_mapping() {
        assert_eq!(ElfArch::from_machine(62), ElfArch::X86_64);
        assert_eq!(ElfArch::from_machine(183), ElfArch::Aarch64);
        assert!(matches!(ElfArch::from_machine(999), ElfArch::Other(999)));
    }
}
