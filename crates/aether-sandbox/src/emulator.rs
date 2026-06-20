//! Full CPU emulation backend (Unicorn Engine), behind the `unicorn` feature.
//!
//! Where the static analyzer reads instructions, this actually *executes* them
//! in an isolated CPU + memory, which unpacks self-modifying stubs and reveals
//! control flow that a linear sweep cannot. Instruction count and final IP are
//! the first signals; memory/API hooks (emitting `aether_behavior::Event`s) are
//! layered on next.

use crate::disasm::Bitness;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterX86, Unicorn};

/// Outcome of a dynamic emulation run.
#[derive(Debug, Clone)]
pub struct EmulationTrace {
    /// Instructions actually executed (vs. merely decoded).
    pub instructions_executed: usize,
    /// Instruction pointer when emulation stopped.
    pub final_ip: u64,
    /// True if control flow left the loaded code buffer (jump / unpack).
    pub left_buffer: bool,
}

const CODE_BASE: u64 = 0x1000;
const CODE_SIZE: u64 = 0x10000;
const STACK_BASE: u64 = 0x20_0000;
const STACK_SIZE: u64 = 0x10000;

/// Emulate up to `max_insns` instructions of `code`.
pub fn emulate(code: &[u8], bitness: Bitness, max_insns: usize) -> Result<EmulationTrace, String> {
    let mode = match bitness {
        Bitness::Bits32 => Mode::MODE_32,
        Bitness::Bits64 => Mode::MODE_64,
    };

    // The emulator's data slot holds our executed-instruction counter so the
    // 'static code hook can mutate it through the `Unicorn` handle.
    let mut emu = Unicorn::new_with_data(Arch::X86, mode, 0usize)
        .map_err(|e| format!("unicorn init failed: {e:?}"))?;

    emu.mem_map(CODE_BASE, CODE_SIZE, Prot::ALL)
        .map_err(|e| format!("mem_map code: {e:?}"))?;
    emu.mem_write(CODE_BASE, code)
        .map_err(|e| format!("mem_write code: {e:?}"))?;
    emu.mem_map(STACK_BASE, STACK_SIZE, Prot::ALL)
        .map_err(|e| format!("mem_map stack: {e:?}"))?;

    let (sp_reg, ip_reg) = match bitness {
        Bitness::Bits32 => (RegisterX86::ESP, RegisterX86::EIP),
        Bitness::Bits64 => (RegisterX86::RSP, RegisterX86::RIP),
    };
    emu.reg_write(sp_reg, STACK_BASE + STACK_SIZE / 2)
        .map_err(|e| format!("set sp: {e:?}"))?;

    emu.add_code_hook(CODE_BASE, CODE_BASE + CODE_SIZE, |uc, _addr, _size| {
        *uc.get_data_mut() += 1;
    })
    .map_err(|e| format!("add_code_hook: {e:?}"))?;

    // Emulation may legitimately fault (unmapped API call, ret to 0); that is
    // not an error for triage - we still report what executed.
    let end = CODE_BASE + code.len() as u64;
    let _ = emu.emu_start(CODE_BASE, end, 0, max_insns);

    let final_ip = emu.reg_read(ip_reg).unwrap_or(0);
    Ok(EmulationTrace {
        instructions_executed: *emu.get_data(),
        final_ip,
        left_buffer: !(CODE_BASE..CODE_BASE + CODE_SIZE).contains(&final_ip),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulates_simple_sequence() {
        // xor rax,rax; inc rax; nop; (then runs off the end -> faults, fine)
        // 48 31 C0   48 FF C0   90
        let code = [0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0x90];
        let trace = emulate(&code, Bitness::Bits64, 16).unwrap();
        assert!(trace.instructions_executed >= 3);
    }
}
