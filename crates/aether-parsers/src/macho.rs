//! Mach-O parser - macOS / iOS executables and dylibs.
//!
//! Phase 2 handles thin (single-architecture) Mach-O images. Fat/universal
//! binaries are detected by [`crate::FileFormat`] but their per-slice parsing
//! is a follow-up; we currently parse the first slice we can.

use crate::section::SectionInfo;
use aether_common::{Error, Result};
use goblin::mach::{Mach, MachO};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachArch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Other(u32),
}

impl MachArch {
    fn from_cputype(c: u32) -> MachArch {
        // CPU_TYPE_* from mach/machine.h (0x0100_0000 = CPU_ARCH_ABI64).
        match c {
            7 => MachArch::X86,
            0x0100_0007 => MachArch::X86_64,
            12 => MachArch::Arm,
            0x0100_000C => MachArch::Arm64,
            other => MachArch::Other(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MachoInfo {
    pub arch: MachArch,
    pub is_lib: bool,
    pub entry: u64,
    pub sections: Vec<SectionInfo>,
    pub libraries: Vec<String>,
    pub has_wx_section: bool,
}

impl MachoInfo {
    pub fn parse(data: &[u8]) -> Result<MachoInfo> {
        let macho = match Mach::parse(data)
            .map_err(|e| Error::Parser(format!("Mach-O parse failed: {e}")))?
        {
            Mach::Binary(m) => m,
            Mach::Fat(fat) => match fat.get(0) {
                Ok(goblin::mach::SingleArch::MachO(m)) => m,
                _ => return Err(Error::Parser("fat Mach-O: no parsable slice".into())),
            },
        };
        Ok(Self::from_macho(&macho, data))
    }

    fn from_macho(macho: &MachO, data: &[u8]) -> MachoInfo {
        // VM protections: VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4.
        const VM_WRITE: u32 = 2;
        const VM_EXEC: u32 = 4;

        let mut sections = Vec::new();
        for segment in &macho.segments {
            let seg_w = segment.initprot & VM_WRITE != 0;
            let seg_x = segment.initprot & VM_EXEC != 0;
            if let Ok(secs) = segment.sections() {
                for (sec, _raw) in secs {
                    let name = sec.name().unwrap_or("<invalid>").to_string();
                    sections.push(SectionInfo::from_range(
                        name,
                        data,
                        sec.offset as usize,
                        sec.size as usize,
                        sec.size,
                        seg_w,
                        seg_x,
                    ));
                }
            }
        }

        let has_wx_section = sections.iter().any(SectionInfo::is_wx);
        let libraries = macho.libs.iter().map(|s| s.to_string()).collect();

        MachoInfo {
            arch: MachArch::from_cputype(macho.header.cputype),
            is_lib: macho.header.filetype == goblin::mach::header::MH_DYLIB,
            entry: macho.entry,
            sections,
            libraries,
            has_wx_section,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_macho() {
        assert!(matches!(
            MachoInfo::parse(b"not macho"),
            Err(Error::Parser(_))
        ));
    }

    #[test]
    fn arch_mapping() {
        assert_eq!(MachArch::from_cputype(0x0100_0007), MachArch::X86_64);
        assert_eq!(MachArch::from_cputype(0x0100_000C), MachArch::Arm64);
    }
}
