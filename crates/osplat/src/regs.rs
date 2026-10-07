//! Moving data between `libc::ucontext_t` and the core's `Registers`.
//!
//! The layout of `ucontext_t` is architecture-specific and unstable, so the
//! offset arithmetic lives in one place. On x86-64 Linux the guest registers are
//! in `gregs[]`, indexed by the `REG_*` constants.

use libc::{c_void, greg_t, ucontext_t};
use oscore::syscall::{Registers, MAX_ARGS};

/// Index of `rax` in `ucontext_t::gregs`. Holds the syscall number on entry.
pub const REG_RAX: usize = libc::REG_RAX as usize;
/// Index of `rip`.
pub const REG_RIP: usize = libc::REG_RIP as usize;
/// Index of `rsp`.
pub const REG_RSP: usize = libc::REG_RSP as usize;

/// Registers holding syscall arguments, in order: rdi, rsi, rdx, r10, r8, r9.
pub const ARG_GREGS: [usize; MAX_ARGS] = [
    libc::REG_RDI as usize,
    libc::REG_RSI as usize,
    libc::REG_RDX as usize,
    libc::REG_R10 as usize,
    libc::REG_R8 as usize,
    libc::REG_R9 as usize,
];

/// Reads guest registers out of a signal frame.
pub fn registers_from(uc: &ucontext_t) -> Registers {
    let g = &uc.uc_mcontext.gregs;
    let mut args = [0u64; MAX_ARGS];
    for (i, &idx) in ARG_GREGS.iter().enumerate() {
        args[i] = g[idx] as u64;
    }
    Registers {
        nr: g[REG_RAX] as i64,
        args,
        rip: g[REG_RIP] as u64,
        rsp: g[REG_RSP] as u64,
    }
}

/// Writes a syscall return value back into a signal frame.
///
/// On x86-64 Linux the kernel reads the syscall result from `rax`, and
/// negative values are interpreted as `-errno`. That is the whole contract.
pub fn set_return(uc: &mut ucontext_t, value: i64) {
    unsafe {
        let base = &mut uc.uc_mcontext.gregs as *mut greg_t as *mut u64;
        *base.add(REG_RAX) = value as u64;
    }
}

/// Returns the instruction pointer the guest will resume at.
pub fn instruction_pointer(uc: &ucontext_t) -> u64 {
    uc.uc_mcontext.gregs[REG_RIP] as u64
}

/// Sets the instruction pointer, used when resuming a restarted syscall.
pub fn set_instruction_pointer(uc: &mut ucontext_t, rip: u64) {
    unsafe {
        let base = &mut uc.uc_mcontext.gregs as *mut greg_t as *mut u64;
        *base.add(REG_RIP) = rip;
    }
}

/// Rewinds `rip` to the instruction that faulted, so it can be retried once
/// the cause is dealt with. x86-64 `syscall` is two bytes.
///
/// This is the mechanism that makes demand paging possible without
/// `userfaultfd`: fault, back up, supply the page, retry.
pub fn rewind_to_syscall(uc: &mut ucontext_t) {
    let rip = instruction_pointer(uc);
    set_instruction_pointer(uc, rip.saturating_sub(2));
}

/// Advances `rip` past the two-byte `syscall` instruction.
pub fn skip_syscall(uc: &mut ucontext_t) {
    let rip = instruction_pointer(uc);
    set_instruction_pointer(uc, rip.saturating_add(2));
}

/// Raw guest memory read through the host's own address space.
///
/// # Safety
///
/// The caller must ensure `addr`/`len` are inside a mapped guest region.
pub unsafe fn read_guest(addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 {
        return None;
    }
    let p = addr as *const u8;
    Some(std::slice::from_raw_parts(p, len).to_vec())
}

/// Raw guest memory write through the host's own address space.
///
/// # Safety
///
/// The caller must ensure `addr`/`len` are inside a mapped, writable region.
pub unsafe fn write_guest(addr: u64, data: &[u8]) -> bool {
    if addr == 0 || data.is_empty() {
        return false;
    }
    let p = addr as *mut u8;
    std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
    true
}

/// Copies a NUL-terminated guest string, bounded by `max`.
pub unsafe fn read_cstr_guest(addr: u64, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut a = addr;
    while out.len() < max {
        let b = *(a as *const u8);
        if b == 0 {
            return Some(out);
        }
        out.push(b);
        a += 1;
    }
    None
}

/// Pointer to opaque host data stashed in the signal frame's `void*`.
pub fn opaque(uc: &ucontext_t) -> *mut c_void {
    uc.uc_mcontext.fpregs as *mut c_void
}
