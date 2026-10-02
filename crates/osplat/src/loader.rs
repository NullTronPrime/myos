//! Loading a guest ELF into this process and entering it.
//!
//! There is no `execve` here, and that is the point. `execve` resets caught
//! signal dispositions, so the `SIGSYS` handler that services the guest would be
//! discarded and the guest's first trapped syscall would kill it. Loading the
//! image in-process keeps the handler alive across the transition.
//!
//! Everything here is host-facing and unsafe; the parsing and validation it
//! relies on lives in `oscore::elf` and is unit-tested.

use libc::{c_void, MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use oscore::addr::{align_down, align_up, PAGE_SIZE};
use oscore::elf::class::Type;
use oscore::elf::ElfImage;
use oscore::Perms;
use std::ffi::CString;

/// Size of the guest stack, placed just below the image's own address range.
const STACK_SIZE: usize = 8 * 1024 * 1024;

/// Bytes handed to the guest as `AT_RANDOM`, seeding its pointer guard.
const AT_RANDOM_BYTES: [u8; 16] = [0x5a; 16];
/// Platform string handed to the guest as `AT_PLATFORM`.
const AT_PLATFORM_STR: &[u8] = b"x86_64\0";

/// Fixed low address for the guest stack, far above any realistic image.
///
/// The stack is guest-owned memory, so it belongs in the low region we manage
/// alongside the image. Leaving it to the kernel would place it above 4 GiB,
/// where `ld.so` and libc also want to map several megabytes: the loader's
/// mappings would then contend with a mapping it neither knows about nor can
/// relocate, and which binary happened to work would change with ASLR.
const STACK_BASE: u64 = 0x4000_0000;

/// `AT_*` auxiliary vector tags the guest may read at startup.
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;
const AT_NULL: u64 = 0;

/// An image laid out in memory and ready to enter.
#[derive(Clone, Copy, Debug)]
pub struct Loaded {
    /// Address the guest starts executing at.
    pub entry: u64,
    /// Initial stack pointer (points at `argc`).
    pub stack_top: u64,
    /// First address past the image, page-aligned. The guest's initial program
    /// break, so `brk` growth starts where the image ends rather than at zero.
    pub brk: u64,
    /// Load address of the dynamic linker, for `AT_BASE`.
    ///
    /// Zero for a static guest: there is no interpreter, and glibc's own
    /// startup treats `AT_BASE == 0` as "no dynamic linker" and runs the
    /// relocations itself.
    pub at_base: u64,
}

/// Maps `image` into this process and builds its initial stack.
///
/// Must be called before the seccomp filter is installed: it uses `mmap`,
/// `mprotect` and `/proc` reads that the filter would otherwise trap.
pub fn prepare(
    image: &ElfImage,
    bytes: &[u8],
    argv: &[CString],
    envp: &[CString],
) -> Result<Loaded, String> {
    let (base, reservation) = load_base(image, true)?;
    ensure_unmapped(image, base, reservation)?;
    map_segments(image, bytes, base)?;

    // A dynamically linked image names its interpreter in PT_INTERP. Control has
    // to start there rather than at the image's own entry point, and the
    // interpreter's base has to reach it through AT_BASE.
    let interpreter = load_interpreter(image, bytes)?;
    // A static PIE is a shared object with no interpreter. Nothing else will
    // relocate it -- there is no ld.so, and our own `crt0.S` deliberately does
    // not self-relocate -- so we apply its base-relative fixups here.
    if interpreter.is_none() && image.header.etype == Type::SharedObject {
        apply_static_relocations(image, bytes, base)?;
    }
    // Two distinct addresses, and conflating them is why a dynamic guest dies.
    // We jump to the interpreter's entry point, but `AT_ENTRY` names the
    // *executable's* entry: that is where `ld.so` transfers control once it has
    // finished relocating, and it is the only way it learns where `main` is.
    let entry = base + image.header.entry;
    let at_base = match &interpreter {
        Some(i) => i.base,
        None => 0,
    };
    let start = match &interpreter {
        Some(i) => i.entry,
        None => entry,
    };

    let stack_top = build_stack(image, entry, base, at_base, argv, envp)?;
    let (_lo, hi) = image
        .image_span()
        .ok_or_else(|| "image has no loadable segments".to_string())?;
    let brk = align_up(base + hi).ok_or_else(|| "image end overflowed".to_string())?;
    Ok(Loaded { entry: start, stack_top, brk, at_base })
}

/// A dynamic linker, mapped and ready to run.
struct Interpreter {
    entry: u64,
    base: u64,
}

/// Loads and maps the image named by `PT_INTERP`, if the guest has one.
///
/// This is the whole dynamic-linking support, and it is deliberately thin: the
/// guest's own interpreter does the relocation work. All this does is put the
/// interpreter in memory and record where it landed, because control must start
/// at its entry point rather than the guest's.
///
/// Returns `None` for a static guest, which needs nothing.
fn load_interpreter(image: &ElfImage, bytes: &[u8]) -> Result<Option<Interpreter>, String> {
    let Some(ph) = image.segments.iter().find(|p| p.is_interp()) else {
        return Ok(None);
    };
    // A path is short and NUL-terminated. Anything wildly off means a malformed
    // or hostile image, not an unusual system.
    if ph.filesz == 0 || ph.filesz > 4096 {
        return Err(format!("PT_INTERP has an implausible size ({})", ph.filesz));
    }
    let off = ph.offset as usize;
    let end = off
        .checked_add(ph.filesz as usize)
        .ok_or_else(|| "PT_INTERP file range overflowed".to_string())?;
    let raw = bytes
        .get(off..end)
        .ok_or_else(|| "PT_INTERP lies outside the file".to_string())?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "PT_INTERP path is not NUL-terminated".to_string())?;
    let path = std::str::from_utf8(&raw[..nul])
        .map_err(|_| "PT_INTERP path is not valid UTF-8".to_string())?;

    let interp_bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read the dynamic linker {path}: {e}"))?;
    let img = ElfImage::parse(&interp_bytes)
        .map_err(|e| format!("dynamic linker {path} is not a valid ELF: {}", e.as_str()))?;
    if img.header.etype != Type::SharedObject {
        return Err(format!("dynamic linker {path} is not a shared object"));
    }

    let (base, reservation) = load_base(&img, false)?;
    ensure_unmapped(&img, base, reservation)?;
    map_segments(&img, &interp_bytes, base)?;

    Ok(Some(Interpreter {
        entry: base + img.header.entry,
        base,
    }))
}

/// Applies a static PIE's base-relative relocations.
///
/// Only `R_X86_64_RELATIVE` entries are expected: a fully linked static image
/// has no undefined symbols, so there is nothing to resolve and no library to
/// map. The stores land in segments the program headers mark writable, which is
/// why this can run after `map_segments` applied the final protections.
fn apply_static_relocations(image: &ElfImage, bytes: &[u8], base: u64) -> Result<(), String> {
    let relocs = oscore::link::relocations(bytes, image)
        .map_err(|e| format!("cannot read dynamic relocations: {}", e.as_str()))?;
    if relocs.is_empty() {
        return Ok(());
    }
    // Gather first so a bad relocation type is rejected before any store
    // touches the image.
    let mut stores: Vec<(u64, u64)> = Vec::with_capacity(relocs.len());
    oscore::link::apply_static(&relocs, base, |addr, value| stores.push((addr, value)))
        .map_err(|t| format!("unsupported relocation type {t} in a static PIE"))?;
    for (addr, value) in stores {
        unsafe { *(addr as *mut u64) = value };
    }
    Ok(())
}

/// Chooses where the image is placed.
///
/// A fixed-address (`ET_EXEC`) image states its own addresses, so the base is
/// zero. A position-independent (`ET_DYN`) image is reserved somewhere the
/// kernel picks, and the reservation's address becomes the base.
///
/// Returns the base and, for a reserved image, the span held aside. The caller
/// needs the reservation so the overlap check does not mistake our own
/// reservation for a pre-existing mapping.
fn load_base(image: &ElfImage, low: bool) -> Result<(u64, Option<(u64, u64)>), String> {
    match image.header.etype {
        Type::Executable => Ok((0, None)),
        Type::SharedObject => {
            let (lo, hi) = image
                .image_span()
                .ok_or_else(|| "image has no loadable segments".to_string())?;
            let span = (hi - lo) as usize;
            if low {
                reserve_below_4gib(lo, span)
            } else {
                reserve_kernel_picked(lo, span)
            }
        }
        other => Err(format!("unsupported ELF type {other:?}")),
    }
}

/// Reserves `span` bytes wherever the kernel likes, and uses that as the base.
///
/// Used for the dynamic linker. It has to be high: `ld.so` exists to map and
/// relocate further libraries, which needs `openat`/`mmap` against the real
/// filesystem. Those calls are only mediated for low addresses, so placing the
/// linker high is what lets it reach the host and load libc normally.
fn reserve_kernel_picked(lo: u64, span: usize) -> Result<(u64, Option<(u64, u64)>), String> {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            span,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == MAP_FAILED {
        return Err("cannot reserve address space for a shared object".into());
    }
    let start = p as u64;
    Ok((start.wrapping_sub(lo), Some((start, start + span as u64))))
}

/// Low addresses tried in turn for a position-independent image.
const BASE_HINTS: [u64; 4] = [0x0001_0000, 0x0020_0000, 0x0040_0000, 0x2000_0000];

/// Reserves `span` bytes for a PIE image at an address below 4 GiB.
///
/// The address must be low. The seccomp filter decides whether a syscall is
/// mediated by testing the high word of the instruction pointer: a guest
/// running above 4 GiB looks exactly like kernel code, so *every* syscall it
/// made would pass through unmediated. A low guest also keeps clear of the
/// high region where the host and its libraries live, so a dynamic linker
/// mapping further libraries cannot collide with the image.
///
/// Returns the chosen base and the reserved span.
fn reserve_below_4gib(lo: u64, span: usize) -> Result<(u64, Option<(u64, u64)>), String> {
    for hint in BASE_HINTS {
        let start = hint.wrapping_sub(lo);
        if start >= 1 << 32 {
            continue;
        }
        // MAP_FIXED_NOREPLACE keeps an occupied address as a failure instead of
        // silently replacing whatever is there.
        let p = unsafe {
            libc::mmap(
                start as *mut c_void,
                span,
                PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if p == start as *mut c_void {
            return Ok((start, Some((start, start + span as u64))));
        }
        if p != MAP_FAILED {
            unsafe { libc::munmap(p, span) };
        }
    }
    Err(format!(
        "cannot reserve {span} bytes below 4 GiB for a position-independent image"
    ))
}

/// Refuses to load over anything the host already has mapped.
///
/// `MAP_FIXED` would silently replace existing mappings, so an overlap is a
/// clobbered launcher or libc rather than an error. Detect it first.
///
/// `reservation` is the span `load_base` just claimed for a PIE image. It is
/// ours, not a collision, and is skipped.
fn ensure_unmapped(
    image: &ElfImage,
    base: u64,
    reservation: Option<(u64, u64)>,
) -> Result<(), String> {
    let (lo, hi) = image
        .image_span()
        .ok_or_else(|| "image has no loadable segments".to_string())?;
    let want_lo = base + lo;
    let want_hi = base + hi;
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|e| format!("cannot read /proc/self/maps: {e}"))?;
    for line in maps.lines() {
        let Some(range) = line.split_whitespace().next() else { continue };
        let Some((s, e)) = range.split_once('-') else { continue };
        let (Ok(s), Ok(e)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else {
            continue;
        };
        // `mmap` rounds the reservation up to a whole page, so the kernel's
        // line can end past ours. Compare only the start, which we chose.
        if let Some((rs, _)) = reservation {
            if s == rs {
                continue;
            }
        }
        if s < want_hi && want_lo < e {
            return Err(format!(
                "guest would be loaded at {want_lo:#x}..{want_hi:#x}, \
                 which overlaps existing mapping {s:#x}..{e:#x}; \
                 the guest must not be a fixed-address image that collides with myos"
            ));
        }
    }
    Ok(())
}

/// Maps every loadable segment with its final permissions and copies file data.
fn map_segments(image: &ElfImage, bytes: &[u8], base: u64) -> Result<(), String> {
    for ph in image.segments.iter().filter(|p| p.is_load()) {
        let perms = ph.perms();
        if perms.is_none() {
            continue;
        }
        let start = base + ph.vaddr;
        let end = start
            .checked_add(ph.memsz)
            .ok_or_else(|| "segment end overflowed".to_string())?;
        let map_start = align_down(start);
        let map_end = align_up(end).ok_or_else(|| "segment end overflowed".to_string())?;
        let len = (map_end - map_start) as usize;

        // Map writable so the file contents can be copied in, then apply the
        // segment's real permissions.
        let p = unsafe {
            libc::mmap(
                map_start as *mut c_void,
                len,
                prot_bits(perms) | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                -1,
                0,
            )
        };
        if p == MAP_FAILED {
            return Err(format!("mmap of segment at {start:#x} failed"));
        }

        if ph.filesz > 0 {
            let foff = ph.offset as usize;
            let fend = foff + ph.filesz as usize;
            let src = bytes
                .get(foff..fend)
                .ok_or_else(|| "segment file range is out of bounds".to_string())?;
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), start as *mut u8, src.len());
            }
        }

        let rc = unsafe { libc::mprotect(map_start as *mut c_void, len, prot_bits(perms)) };
        if rc != 0 {
            return Err(format!("mprotect of segment at {start:#x} failed"));
        }
    }
    Ok(())
}

/// Sizes of the initial-stack block, laid out from `stack_top` downwards.
///
/// `strings_bytes` sits highest, then `pad`, then the contiguous
/// `argc`/`argv`/`envp`/`auxv` arrays (`arrays_bytes`) whose base is `rsp`.
struct StackLayout {
    strings_bytes: usize,
    arrays_bytes: usize,
    pad: usize,
}

/// Plans the initial stack so `rsp` lands 16-byte aligned with `argc` directly
/// below the pointer arrays it indexes.
///
/// `pad` is the only slack; it is placed above the string block so nothing is
/// ever inserted between `argc` and `argv[0]`. `auxv_entries` counts every
/// `(tag, value)` pair including the terminating `AT_NULL`.
fn plan_stack(argv: &[CString], envp: &[CString], auxv_entries: usize) -> StackLayout {
    let raw = argv.iter().map(|a| a.as_bytes_with_nul().len()).sum::<usize>()
        + envp.iter().map(|e| e.as_bytes_with_nul().len()).sum::<usize>()
        + AT_RANDOM_BYTES.len()
        + AT_PLATFORM_STR.len();
    let strings_bytes = (raw + 7) & !7;
    let arrays_bytes = 8               // argc
        + 8 * (argv.len() + 1)         // argv and its NULL
        + 8 * (envp.len() + 1)         // envp and its NULL
        + 16 * auxv_entries;           // auxv, ending in AT_NULL
    let pad = if (strings_bytes + arrays_bytes) % 16 == 0 { 0 } else { 8 };
    StackLayout { strings_bytes, arrays_bytes, pad }
}

/// Builds the System V initial stack: `argc`, `argv`, `envp`, then `auxv`.
fn build_stack(
    image: &ElfImage,
    entry: u64,
    base: u64,
    at_base: u64,
    argv: &[CString],
    envp: &[CString],
) -> Result<u64, String> {
    // The stack lives at a fixed low address (`STACK_BASE`), below 4 GiB, so
    // guest stack accesses are covered by the same mediation as the image.
    let want = STACK_BASE as *mut c_void;
    let p = unsafe {
        libc::mmap(
            want,
            STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if p == MAP_FAILED {
        return Err("cannot reserve the guest stack".into());
    }
    if p != want {
        unsafe { libc::munmap(p, STACK_SIZE) };
        return Err("guest stack address is already occupied".into());
    }

    let stack_top = p as u64 + STACK_SIZE as u64;

    // The guest finds argv, envp and auxv by walking outwards from `argc`, so
    // those arrays have to be contiguous with it. `rsp` must still be 16-byte
    // aligned at entry, and the only place padding may go is above the whole
    // block: padding between `argc` and `argv[0]` would hide every argument
    // and every auxiliary-vector entry from the guest.
    let auxv_entries = 17 + usize::from(phdr_addr(image, base).is_some()) + 1;
    let layout = plan_stack(argv, envp, auxv_entries);
    let mut sp = stack_top - layout.pad as u64;

    // String data first, at the highest addresses.
    let push_bytes = |sp: &mut u64, bytes: &[u8]| -> u64 {
        *sp -= bytes.len() as u64;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), *sp as *mut u8, bytes.len());
        }
        *sp
    };
    let mut arg_ptrs = Vec::with_capacity(argv.len());
    for a in argv {
        arg_ptrs.push(push_bytes(&mut sp, a.as_bytes_with_nul()));
    }
    let mut env_ptrs = Vec::with_capacity(envp.len());
    for e in envp {
        env_ptrs.push(push_bytes(&mut sp, e.as_bytes_with_nul()));
    }
    // Static glibc dereferences AT_RANDOM to seed its pointer guard, so a
    // missing vector is an immediate crash. The bytes only need to exist and
    // be non-trivial here.
    let random = push_bytes(&mut sp, &AT_RANDOM_BYTES);
    let platform = push_bytes(&mut sp, AT_PLATFORM_STR);
    let execfn = arg_ptrs.first().copied().unwrap_or(0);

    // Pointer arrays are 8-byte aligned.
    sp &= !7u64;

    // auxv, terminated by AT_NULL.
    let mut auxv: Vec<(u64, u64)> = vec![
        (AT_PAGESZ, PAGE_SIZE as u64),
        (AT_ENTRY, entry),
        (AT_PHNUM, image.header.phnum as u64),
        (AT_PHENT, image.header.phentsize as u64),
        (AT_BASE, at_base),
        (AT_FLAGS, 0),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_CLKTCK, 100),
        (AT_HWCAP, 0),
        (AT_HWCAP2, 0),
        (AT_RANDOM, random),
        (AT_PLATFORM, platform),
        (AT_EXECFN, execfn),
    ];
    if let Some(ph) = phdr_addr(image, base) {
        auxv.push((AT_PHDR, ph));
    }
    auxv.push((AT_NULL, 0));
    for &(k, v) in auxv.iter().rev() {
        sp -= 16;
        unsafe {
            *(sp as *mut u64) = k;
            *((sp + 8) as *mut u64) = v;
        }
    }

    // envp, then its NULL terminator.
    sp -= 8;
    unsafe { *(sp as *mut u64) = 0 };
    for &ep in env_ptrs.iter().rev() {
        sp -= 8;
        unsafe { *(sp as *mut u64) = ep };
    }

    // argv, then its NULL terminator.
    sp -= 8;
    unsafe { *(sp as *mut u64) = 0 };
    for &ap in arg_ptrs.iter().rev() {
        sp -= 8;
        unsafe { *(sp as *mut u64) = ap };
    }

    // argc last, so `rsp` points at it. The alignment padding was already
    // reserved above the block, so nothing may be inserted here.
    sp -= 8;
    unsafe { *(sp as *mut u64) = argv.len() as u64 };

    // The plan put `rsp` exactly `strings_bytes + arrays_bytes` below the pad
    // that was reserved at the top. Check it rather than trusting the pushes.
    let planned = stack_top - layout.pad as u64 - layout.strings_bytes as u64 - layout.arrays_bytes as u64;
    assert_eq!(sp, planned, "initial stack did not match its plan");

    Ok(sp)
}

/// Address of the program header table once the image is mapped.
fn phdr_addr(image: &ElfImage, base: u64) -> Option<u64> {
    let e_phoff = image.header.phoff;
    for ph in image.segments.iter().filter(|p| p.is_load() && p.filesz > 0) {
        if e_phoff >= ph.offset && e_phoff < ph.offset + ph.filesz {
            return Some(base + ph.vaddr + (e_phoff - ph.offset));
        }
    }
    None
}

fn prot_bits(perms: Perms) -> i32 {
    let mut prot = 0;
    if perms.contains(Perms::READ) {
        prot |= PROT_READ;
    }
    if perms.contains(Perms::WRITE) {
        prot |= PROT_WRITE;
    }
    if perms.contains(Perms::EXEC) {
        prot |= PROT_EXEC;
    }
    prot
}

std::arch::global_asm!(
    ".globl __myos_enter",
    ".hidden __myos_enter",
    ".type __myos_enter,@function",
    "__myos_enter:",
    "mov rsp, rsi",
    // A freshly exec'd static image starts with every register but `rsp` zeroed
    // by the kernel. `_start` reads `%rdx` as `rtld_fini` and pushes `%rax`;
    // leaving host leftovers here sends `exit` into a host address.
    "xor ebp, ebp",
    "xor eax, eax",
    "xor ebx, ebx",
    "xor ecx, ecx",
    "xor edx, edx",
    "xor esi, esi",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "jmp rdi",
    ".size __myos_enter, .-__myos_enter",
);

extern "C" {
    fn __myos_enter(entry: u64, stack_top: u64) -> !;
}

/// Transfers control to a loaded guest. Never returns.
///
/// # Safety
///
/// `entry` and `stack_top` must come from [`prepare`] for an image that is still
/// mapped. After this call the guest owns the thread.
pub unsafe fn enter(entry: u64, stack_top: u64) -> ! {
    __myos_enter(entry, stack_top)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(lens: &[usize]) -> Vec<CString> {
        lens.iter()
            .map(|&n| CString::new(vec![b'a'; n]).unwrap())
            .collect()
    }

    #[test]
    fn rsp_lands_16_byte_aligned_for_every_size() {
        // The bug this guards: miscounting a fixed block (e.g. a platform
        // string's NUL) shifted the padding and misaligned `rsp`, which made
        // glibc walk the auxiliary vector off by one and read a NULL
        // `AT_RANDOM`/`argv[0]`.
        for argc in 0..8usize {
            for envc in 0..4usize {
                for len in 1..24usize {
                    for auxv in [18usize, 19, 20] {
                        let argv = strings(&vec![len; argc]);
                        let envp = strings(&vec![len; envc]);
                        let l = plan_stack(&argv, &envp, auxv);
                        assert_eq!(
                            (l.pad + l.strings_bytes + l.arrays_bytes) % 16,
                            0,
                            "argc={argc} envc={envc} len={len} auxv={auxv}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn arrays_account_for_argc_argv_envp_and_auxv() {
        for (argc, envc, auxv) in [(0, 0, 18), (1, 0, 19), (3, 2, 18), (10, 4, 20)] {
            let argv = strings(&vec![3; argc]);
            let envp = strings(&vec![3; envc]);
            let l = plan_stack(&argv, &envp, auxv);
            assert_eq!(
                l.arrays_bytes,
                8 + 8 * (argc + 1) + 8 * (envc + 1) + 16 * auxv
            );
        }
    }

    #[test]
    fn strings_block_uses_real_fixed_lengths() {
        let argv = strings(&[1]);
        let envp: Vec<CString> = Vec::new();
        let l = plan_stack(&argv, &envp, 18);
        let raw = 2 + AT_RANDOM_BYTES.len() + AT_PLATFORM_STR.len();
        assert_eq!(l.strings_bytes, (raw + 7) & !7);
        // "x86_64\0": six characters plus the NUL, not eight bytes.
        assert_eq!(AT_PLATFORM_STR.len(), 7);
    }
}
