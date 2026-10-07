//! Installing a seccomp-bpf filter that traps the guest's syscalls, and the
//! SIGSYS handler that services them.
//!
//! Mechanism, in the order the kernel sees it:
//!
//! 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` so an unprivileged filter is allowed.
//! 2. `seccomp(SECCOMP_SET_MODE_FILTER, ...)` with a BPF program that traps a
//!    syscall when its *instruction pointer* is a guest address, and allows it
//!    otherwise. Guest code is loaded below 4 GiB (a fixed-address image at
//!    `0x400000`, or a PIE reserved low); the kernel, libc and the loader all
//!    live in the high half. The upper 32 bits of `instruction_pointer` are
//!    therefore zero exactly for guest syscalls, which is all the filter needs
//!    to tell the two apart.
//!
//!    This is what lets the handler call `mmap`, `write`, `exit` and so on to
//!    service the guest: those calls come from kernel code at a high address
//!    and pass straight through, while every guest call is trapped. Without it,
//!    seccomp's process-wide scope would force the handler's own syscalls to be
//!    allow-listed, and those allowances would leak to the guest.
//! 3. The `SIGSYS` handler reads the syscall number and arguments out of
//!    `ucontext_t`, runs the pure dispatcher from `oscore`, and writes the
//!    result back into `rax`. The kernel has already stepped `rip` past the
//!    `syscall` instruction, so only `rax` needs adjusting.
//!
//! The only escape is that the guest shares the address space, so it could in
//! principle jump into high-address code that contains a `syscall`. Real
//! separation needs a separate address space, which this design deliberately
//! does not have.
//!
//! There is no VM exit anywhere in that path, which is the whole difference
//! from a hypervisor.

use crate::regs;
use libc::{c_char, c_int, c_void, sigaction, siginfo_t, ucontext_t};
use oscore::syscall::{
    dispatch, FdKind, FdTable, GuestMemory, GuestState, Registers, MAP_ANONYMOUS, MAP_FIXED,
    PROT_READ, PROT_WRITE, SYS_BRK, SYS_CLONE, SYS_CLOSE, SYS_DUP, SYS_DUP2, SYS_DUP3, SYS_EXECVE,
    SYS_FORK, SYS_GETPID, SYS_IOCTL, SYS_KILL, SYS_PIPE, SYS_PIPE2, SYS_READ, SYS_RT_SIGRETURN,
    SYS_SYNC_FS, SYS_WAIT4, SYS_WRITE,
};
use oscore::vfs::{Fd, Vfs};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Guest syscalls that bypass the trap and reach the host.
///
/// Empty by default: the whole point is that the kernel services every guest
/// syscall, so nothing is passed through unless a caller opts in with
/// `--allow`. The IP gate means this list applies only to guest calls; the
/// handler's own syscalls are always allowed because they come from kernel
/// addresses.
pub const ALLOWED_SYSCALLS: &[i64] = &[];

/// BPF opcodes, kept local so the filter needs no dependency.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Action returned by the filter for any syscall we want to handle.
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
/// Action for syscalls we pass straight to the host.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `siginfo_t::si_code` value for a syscall stopped by seccomp. The kernel sets
/// this (not `SECCOMP_RET_TRAP`, which lives in the filter program) and puts
/// the syscall number in `si_syscall`. libc does not export the name.
const SYS_SECCOMP: c_int = 1;

/// Offset of the syscall number within `seccomp_data`, which is
/// `nr` after the architecture number.
const OFF_NR: u32 = 0;

/// Offset of the upper 32 bits of `instruction_pointer` within `seccomp_data`.
///
/// `seccomp_data` is `{ int nr; u32 arch; u64 instruction_pointer; u64 args[6] }`,
/// so `instruction_pointer` begins at byte 8 and its high word at byte 12.
const OFF_IP_HI: u32 = 12;

/// Builds the BPF program that traps guest syscalls.
///
/// The filter first checks the high word of `instruction_pointer`. A non-zero
/// high word means the syscall came from the kernel side (the loader, libc, or
/// this handler), which is allowed unconditionally. A zero high word means a
/// guest address below 4 GiB: those are mediated, and `allow` names the few
/// that may still reach the host.
///
/// Layout:
///
/// ```text
/// 0        load ip_hi
/// 1        if ip_hi != 0 -> ALLOW
/// 2        load nr
/// 3..3+n   if nr == allow[i] -> ALLOW
/// 3+n      RET TRAP
/// 4+n      RET ALLOW
/// ```
pub fn build_filter(allow: &[i64]) -> Vec<libc::sock_filter> {
    let n = allow.len();
    // Index of the trailing ALLOW instruction, which every JEQ targets.
    let allow_index = (4 + n) as u8;

    let mut prog = Vec::with_capacity(n + 4);
    prog.push(libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_IP_HI,
    });
    // A zero high word is the guest: fall through to the number check. A
    // non-zero high word is kernel code: jump straight to ALLOW.
    prog.push(libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: (allow_index - 2) as u8,
        k: 0,
    });
    prog.push(libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_NR,
    });
    for (i, &nr) in allow.iter().enumerate() {
        let here = (3 + i) as u8;
        prog.push(libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: allow_index - here - 1,
            jf: 0,
            k: nr as u32,
        });
    }
    prog.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_TRAP,
    });
    prog.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    prog
}

/// State shared between the SIGSYS handler and the main thread.
///
/// Every field the dispatcher mutates has to live here rather than in a fresh
/// `GuestState`, which is built per trap. `brk` and `pid` would otherwise reset
/// on every syscall, and `file_pos` would restart every read.
pub struct TrapState {
    /// The guest's filesystem.
    pub vfs: Vfs,
    /// The guest's open descriptors.
    pub fds: FdTable,
    /// Bytes the guest wrote to fd 1, drained to the terminal by the handler.
    pub stdout: Vec<u8>,
    /// Set when the guest called `exit`.
    pub exited: Option<i32>,
    /// The guest's program break, carried between `brk` calls.
    pub brk: u64,
    /// Highest break the host has actually mapped. The dispatcher tracks the
    /// logical break; this tracks the memory realised behind it.
    pub mapped_brk: u64,
    /// Fake pid, incremented per `getpid`.
    pub pid: i64,
    /// `%fs` base the guest wants while its code runs. Starts equal to the
    /// host's own base, so a guest that never calls `arch_prctl` is unaffected.
    pub guest_fs: u64,
    /// The guest's display and window model.
    pub display: oscore::gfx::Display,
    /// PPM bytes produced by the last `display_present`, drained by the handler.
    pub frame: Vec<u8>,
    /// Wall and monotonic time, refreshed from the host before every trap so a
    /// guest's clock moves even when it makes no syscalls of its own.
    pub clock: oscore::clock::Clock,
    /// Whether `clock` has been seeded with a host reading yet.
    pub clock_started: bool,
    /// Signal dispositions, blocked mask and pending queue.
    pub signals: oscore::signal::SignalTable,
    /// Keyboard and mouse events waiting for the guest.
    pub input: oscore::input::InputQueue,
    /// The guest's working directory, used to resolve relative paths.
    pub cwd: String,
    /// The guest's file mode creation mask.
    pub umask: u32,
    /// Frames composited so far, so a guest loop can pace itself.
    pub frame_counter: u64,
    /// Set while the guest is parked in `input_wait`.
    pub waiting_for_input: bool,
    /// The descriptor input events are read from, carried between traps so a
    /// guest that asks on every frame does not leak one per frame.
    pub input_fd: Option<u32>,
}

impl TrapState {
    fn new() -> Self {
        TrapState {
            vfs: Vfs::new(),
            fds: FdTable::new(),
            stdout: Vec::new(),
            exited: None,
            brk: 0,
            mapped_brk: 0,
            pid: 0,
            guest_fs: 0,
            display: oscore::gfx::Display::new(display_width(), display_height()),
            frame: Vec::new(),
            clock: oscore::clock::Clock::default(),
            clock_started: false,
            signals: oscore::signal::SignalTable::new(),
            input: oscore::input::InputQueue::new(),
            cwd: "/".to_string(),
            umask: 0o022,
            frame_counter: 0,
            waiting_for_input: false,
            input_fd: None,
        }
    }
}

/// Nanoseconds from the host for the named clock.
///
/// A failure leaves the clock at zero rather than aborting: a guest that only
/// wants a non-decreasing sequence is better served by a frozen clock than by a
/// kernel that will not start.
fn host_clock_ns(id: libc::clockid_t) -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64
}

/// Blocks the host thread until the monotonic clock reaches `deadline_ns`.
///
/// The wait is chunked rather than handed to `clock_nanosleep` in one call so
/// that input arriving in the meantime is picked up; a guest that sleeps for an
/// hour must still see the mouse move.
fn sleep_until(deadline_ns: u64) {
    loop {
        let now = host_clock_ns(libc::CLOCK_MONOTONIC).max(0) as u64;
        if now >= deadline_ns {
            return;
        }
        let remaining = deadline_ns - now;
        // Cap each nap so input is polled at a reasonable rate.
        let chunk = remaining.min(50_000_000);
        let ts = libc::timespec {
            tv_sec: (chunk / 1_000_000_000) as libc::time_t,
            tv_nsec: (chunk % 1_000_000_000) as i64,
        };
        // `CLOCK_MONOTONIC` is a high-address syscall the filter allows, so this
        // does not re-enter the guest trap path.
        unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts, std::ptr::null_mut()) };
        pump_input();
    }
}

/// Pumps host input until something arrives or the deadline passes.
fn wait_for_input(deadline_ns: u64) {
    loop {
        pump_input();
        let have = match state().lock() {
            Ok(g) => !g.input.is_empty(),
            Err(p) => !p.into_inner().input.is_empty(),
        };
        if have {
            return;
        }
        let now = host_clock_ns(libc::CLOCK_MONOTONIC).max(0) as u64;
        if now >= deadline_ns {
            return;
        }
        let chunk = deadline_ns.saturating_sub(now).min(16_000_000);
        let ts = libc::timespec {
            tv_sec: (chunk / 1_000_000_000) as libc::time_t,
            tv_nsec: (chunk % 1_000_000_000) as i64,
        };
        unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts, std::ptr::null_mut()) };
    }
}

/// Moves any host window-system events into the guest's input queue.
///
/// A guest that never opens a window gets nothing, so the pump is a no-op until
/// one exists; that keeps a console-only run free of any display dependency.
fn pump_input() {
    let events = crate::display::poll_events();
    if events.is_empty() {
        return;
    }
    if let Ok(mut g) = state().lock() {
        for e in events {
            g.input.push(e);
        }
    }
}

/// Forgets a sleep request once it has been served, so a later trap does not
/// repeat it.
fn clear_sleep() {
    if let Ok(mut g) = state().lock() {
        g.waiting_for_input = false;
    }
}

/// Rewinds the instruction pointer to the `syscall` that trapped.
///
/// The kernel has already advanced `rip` past the instruction, so a syscall that
/// needs to run again has to be stepped back over. Subtracting two bytes is the
/// size of `syscall` on x86-64 and nothing else can produce that trap here.
fn rewind(uc: &mut libc::ucontext_t) {
    unsafe {
        let p = &mut uc.uc_mcontext.gregs[libc::REG_RIP as usize] as *mut i64;
        *p -= 2;
    }
}

/// Writes the guest's filesystem out to its host directory.
///
/// Called when the guest asks for a `sync` and again before the process exits,
/// so a guest that never syncs explicitly still finds its files on disk next
/// time.
pub fn sync_filesystem() -> Option<oscore::persist::SyncStats> {
    let root = ROOT.get()?;
    let g = state().lock().unwrap_or_else(|p| p.into_inner());
    match oscore::persist::write_all(&g.vfs, root) {
        Ok(stats) => Some(stats),
        Err(e) => {
            eprintln!("myos: filesystem sync failed: {e}");
            None
        }
    }
}

static STATE: OnceLock<Mutex<TrapState>> = OnceLock::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);
static TRACE: AtomicBool = AtomicBool::new(false);
static KERNEL_FS: AtomicU64 = AtomicU64::new(0);

/// Host directory the guest's `/` is backed by, when a rootfs was configured.
static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Host file the last composited frame is written to as a PPM, when configured
/// through `MYOS_FB_OUT`.
static FB_OUT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Display width, from `MYOS_DISPLAY` (`WxH`) or the model's default.
fn display_width() -> u32 {
    parse_display().0
}

/// Display height, from `MYOS_DISPLAY` (`WxH`) or the model's default.
fn display_height() -> u32 {
    parse_display().1
}

/// Parses `MYOS_DISPLAY`, falling back to the model defaults.
fn parse_display() -> (u32, u32) {
    let (mut w, mut h) = (oscore::gfx::DEFAULT_WIDTH, oscore::gfx::DEFAULT_HEIGHT);
    if let Ok(spec) = std::env::var("MYOS_DISPLAY") {
        let mut it = spec.split(['x', 'X', ',']);
        if let (Some(a), Some(b)) = (it.next(), it.next()) {
            if let (Ok(pw), Ok(ph)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                if pw > 0 && ph > 0 {
                    w = pw;
                    h = ph;
                }
            }
        }
    }
    (w, h)
}

/// Points `%fs` at `base` via `arch_prctl(ARCH_SET_FS)`.
///
/// Done with a raw `syscall` rather than the libc wrapper so no errno (a TLS
/// access) happens before or after the pointer moves. This runs on the host
/// thread, so the kernel must restore its own `%fs` before touching any libc or
/// Rust state, and only leave the guest's value in place when about to resume
/// guest code.
#[inline]
unsafe fn set_fs(base: u64) {
    let mut rax: u64 = 158;
    std::arch::asm!(
        "syscall",
        inlateout("rax") rax,
        in("rdi") 0x1002u64,
        in("rsi") base,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    let _ = rax;
}

/// Renders one decimal `i64` into `buf`, returning the used slice.
fn write_i64(buf: &mut [u8], mut v: i64) -> usize {
    let neg = v < 0;
    let mut n = 0;
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 24];
    if neg {
        // i64::MIN would overflow on negation; fold it via wrapping.
        v = v.wrapping_neg();
    }
    let mut len = 0;
    while v != 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    if neg {
        buf[n] = b'-';
        n += 1;
    }
    while len > 0 {
        len -= 1;
        buf[n] = tmp[len];
        n += 1;
    }
    n
}

/// Logs one trapped syscall to stderr when `MYOS_TRACE=1` is set.
fn trace(nr: i64, arg0: u64, ip: u64, ret: Result<u64, oscore::vfs::Errno>) {
    if !TRACE.load(Ordering::Relaxed) {
        return;
    }
    let mut buf = [0u8; 130];
    let mut n = 0;
    buf[n] = b's';
    n += 1;
    n += write_i64(&mut buf[n..], nr);
    for &b in b" a0=" {
        buf[n] = b;
        n += 1;
    }
    n += write_hex(&mut buf[n..], arg0);
    for &b in b" ip=" {
        buf[n] = b;
        n += 1;
    }
    n += write_hex(&mut buf[n..], ip);
    for &b in b" ret=" {
        buf[n] = b;
        n += 1;
    }
    match ret {
        Ok(v) => n += write_i64(&mut buf[n..], v as i64),
        Err(e) => {
            buf[n] = b'-';
            n += 1;
            n += write_i64(&mut buf[n..], e as i64);
        }
    }
    buf[n] = b'\n';
    n += 1;
    unsafe { libc::write(2, buf.as_ptr() as *const c_void, n) };
}

/// Renders one `u64` in hex into `buf`, returning the used slice.
fn write_hex(buf: &mut [u8], v: u64) -> usize {
    buf[0] = b'0';
    buf[1] = b'x';
    let mut n = 2;
    let mut started = false;
    for i in (0..16).rev() {
        let d = ((v >> (i * 4)) & 0xf) as u8;
        if d != 0 || started || i == 0 {
            started = true;
            buf[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
            n += 1;
        }
    }
    n
}

/// Turns the first fatal guest fault into a guest signal, then reports if none
/// was handled.
///
/// Without this the launcher just dies with a signal and gives no clue where.
/// The fault address and instruction pointer say whether the guest jumped to a
/// bad address or touched unmapped memory, and that report is kept because it is
/// the only evidence available when the guest has no handler for the fault.
///
/// A guest that *has* installed a handler gets it: the frame is built on the
/// guest's own stack and the context is rewritten so the guest resumes inside
/// the handler, exactly as it would on a real system.
extern "C" fn fault_handler(sig: c_int, info: *mut siginfo_t, uc: *mut c_void) {
    let mut cur_fs: u64 = 0;
    unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003u64, &mut cur_fs as *mut u64) };
    let kfs = KERNEL_FS.load(Ordering::SeqCst);
    if kfs != 0 {
        unsafe { set_fs(kfs) };
    }
    if !info.is_null() && !uc.is_null() {
        let addr = unsafe { (*info).si_addr() } as u64;
        // The guest's handler goes first: if one is installed, the guest is
        // about to resume and must not be killed underneath it.
        if deliver_fault(sig, addr, unsafe { &mut *(uc as *mut ucontext_t) }) {
            return;
        }
        let uc = unsafe { &*(uc as *const ucontext_t) };
        let rip = regs::instruction_pointer(uc);
        let rsp = regs::registers_from(uc).rsp;
        let retaddr = if rsp > 0x1000 && rsp < 0x0000_8000_0000_0000 {
            unsafe { *(rsp as *const u64) }
        } else {
            0
        };
        let tcache = if cur_fs > 0x1000 && cur_fs < 0x0000_8000_0000_0000 {
            unsafe { *((cur_fs.wrapping_sub(0x50)) as *const u64) }
        } else {
            0
        };
        let (w0, w8, wm8, wm48) = if cur_fs > 0x1000 && cur_fs < 0x0000_8000_0000_0000 {
            unsafe {
                (
                    *(cur_fs as *const u64),
                    *((cur_fs + 8) as *const u64),
                    *((cur_fs.wrapping_sub(8)) as *const u64),
                    *((cur_fs.wrapping_sub(0x48)) as *const u64),
                )
            }
        } else {
            (0, 0, 0, 0)
        };
        // Sized for the whole one-line report below. Oversizing is free here:
        // this frame only ever runs on the way to `_exit`, and a fixed buffer
        // that fits the worst case is simpler than a bounds-checked writer.
        let mut buf = [0u8; 512];
        let mut n = 0;
        for &b in b"myos: fault sig=" {
            buf[n] = b;
            n += 1;
        }
        n += write_i64(&mut buf[n..], sig as i64);
        for &b in b" addr=" {
            buf[n] = b;
            n += 1;
        }
        n += write_hex(&mut buf[n..], addr);
        for &b in b" rip=" {
            buf[n] = b;
            n += 1;
        }
        n += write_hex(&mut buf[n..], rip);
        for &b in b" rsp=" {
            buf[n] = b;
            n += 1;
        }
        n += write_hex(&mut buf[n..], rsp);
        for &b in b" ra=" {
            buf[n] = b;
            n += 1;
        }
        n += write_hex(&mut buf[n..], retaddr);
        for &b in b" fs=" {
            buf[n] = b;
            n += 1;
        }
        n += write_hex(&mut buf[n..], cur_fs);
        // The guest runs natively, so the bytes at the reported `rip` are
        // readable here. When `rip` is the guest's that names the instruction; a
        // `#GP` on the way back out of a handler reports the address it was
        // trying to reach instead, which is how that shows up.
        for &b in b" insn=" {
            buf[n] = b;
            n += 1;
        }
        if rip > 0x1000 && rip < 0x0000_8000_0000_0000 {
            for i in 0..8 {
                let byte = unsafe { *((rip + i) as *const u8) };
                buf[n] = b"0123456789abcdef"[(byte >> 4) as usize];
                n += 1;
                buf[n] = b"0123456789abcdef"[(byte & 0xf) as usize];
                n += 1;
            }
        } else {
            for _ in 0..16 {
                buf[n] = b'-';
                n += 1;
            }
        }
        for &b in b" tcache=" {
            buf[n] = b;
            n += 1;
        }
        n += write_hex(&mut buf[n..], tcache);
        let labels: [(&[u8], u64); 4] = [
            (b" w0=", w0),
            (b" w8=", w8),
            (b" wm8=", wm8),
            (b" wm48=", wm48),
        ];
        for &(label, val) in &labels {
            for &b in label {
                buf[n] = b;
                n += 1;
            }
            n += write_hex(&mut buf[n..], val);
        }
        buf[n] = b'\n';
        n += 1;
        unsafe { libc::write(2, buf.as_ptr() as *const c_void, n) };

        if TRACE.load(Ordering::Relaxed) {
            let rax = uc.uc_mcontext.gregs[libc::REG_RAX as usize] as u64;
            let rdi = uc.uc_mcontext.gregs[libc::REG_RDI as usize] as u64;
            let rbp = uc.uc_mcontext.gregs[libc::REG_RBP as usize] as u64;
            let mut line = [0u8; 128];
            let mut n = 0;
            for &b in b"rax=" {
                line[n] = b;
                n += 1;
            }
            n += write_hex(&mut line[n..], rax);
            for &b in b" rdi=" {
                line[n] = b;
                n += 1;
            }
            n += write_hex(&mut line[n..], rdi);
            for &b in b" rbp=" {
                line[n] = b;
                n += 1;
            }
            n += write_hex(&mut line[n..], rbp);
            line[n] = b'\n';
            n += 1;
            unsafe { libc::write(2, line.as_ptr() as *const c_void, n) };
            for i in 0..8u64 {
                let v = unsafe { *((rsp + i * 8) as *const u64) };
                let mut b = [0u8; 64];
                let mut m = write_hex(&mut b, v);
                b[m] = b'\n';
                m += 1;
                unsafe { libc::write(2, b.as_ptr() as *const c_void, m) };
            }
            let mut b = [0u8; 80];
            let mut m = 0;
            for &c in b"got: " {
                b[m] = c;
                m += 1;
            }
            unsafe { libc::write(2, b.as_ptr() as *const c_void, m) };
            for i in 0..22u64 {
                let v = unsafe { *((0x4b0000 + i * 8) as *const u64) };
                let mut b = [0u8; 64];
                let mut m = write_hex(&mut b, v);
                b[m] = b' ';
                m += 1;
                unsafe { libc::write(2, b.as_ptr() as *const c_void, m) };
            }
            unsafe { libc::write(2, b"\n".as_ptr() as *const c_void, 1) };
            let pg = unsafe { *((cur_fs + 0x30) as *const u64) };
            let mut b = [0u8; 64];
            let mut m = 0;
            for &c in b"ptrguard: " {
                b[m] = c;
                m += 1;
            }
            m += write_hex(&mut b[m..], pg);
            b[m] = b'\n';
            m += 1;
            unsafe { libc::write(2, b.as_ptr() as *const c_void, m) };
        }
    }
    unsafe { libc::_exit(128 + sig) };
}

/// Restores the host's `%fs` base, then queues the fault for the guest and
/// delivers it if the guest is listening.
///
/// Returns `true` when the guest has been sent into its own handler, in which
/// case this function must return rather than exit so the rewritten context is
/// restored.
fn deliver_fault(sig: c_int, addr: u64, uc: &mut ucontext_t) -> bool {
    let kfs = KERNEL_FS.load(Ordering::SeqCst);
    if kfs != 0 {
        unsafe { set_fs(kfs) };
    }
    let Some(pending) = crate::signal::fault_pending(sig, addr) else {
        return false;
    };
    let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
    st.signals.queue(pending);
    let delivered = matches!(
        crate::signal::deliver(&mut st.signals, uc),
        crate::signal::Delivered::Went(_)
    );
    // The guest's `%fs` base is read while the lock is held and switched back
    // after it is dropped: the guest resumes on its own stack immediately after
    // this returns, and anything that touched TLS in between would fault.
    let gfs = st.guest_fs;
    drop(st);
    if delivered && gfs != 0 && gfs != kfs {
        unsafe { set_fs(gfs) };
    }
    delivered
}

fn state() -> &'static Mutex<TrapState> {
    STATE.get_or_init(|| Mutex::new(TrapState::new()))
}

/// Installs the SIGSYS handler and the seccomp filter.
///
/// Must be called after `PR_SET_NO_NEW_PRIVS`. Returns `Err` if the host
/// refuses, which is the expected outcome on kernels built without
/// `CONFIG_SECCOMP_FILTER`.
pub fn install(extra_allow: &[i64]) -> Result<(), String> {
    install_handler()?;
    install_filter(extra_allow)?;
    INSTALLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Installs only the SIGSYS handler, leaving any inherited filter in place.
///
/// Used after an `execve` trampoline: a seccomp filter survives `execve` but
/// the signal disposition is reset, so the handler must be re-armed or the
/// restored guest's first trapped syscall would kill it.
pub fn install_handler_only() -> Result<(), String> {
    install_handler()?;
    INSTALLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Arms the SIGSYS, SIGPIPE and fatal-fault handlers, and captures `%fs`.
fn install_handler() -> Result<(), String> {
    unsafe {
        // Remember the host thread's own `%fs` base so every trap can restore
        // it before touching libc, and only hand `%fs` to the guest on the way
        // back out.
        let mut fs: u64 = 0;
        let rc = libc::syscall(libc::SYS_arch_prctl, 0x1003u64, &mut fs as *mut u64);
        if rc == 0 {
            KERNEL_FS.store(fs, Ordering::SeqCst);
            state().lock().unwrap_or_else(|p| p.into_inner()).guest_fs = fs;
        }

        let mut sa: sigaction = std::mem::zeroed();
        // Cast through a function pointer rather than casting the item itself,
        // which the compiler warns about for `extern "C"` handlers.
        let handler: extern "C" fn(c_int, *mut siginfo_t, *mut c_void) = sigsys_handler;
        sa.sa_sigaction = handler as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);

        // The guest has its own stack and `%fs`. Running the trap handler (with
        // its Rust frames and libc calls) on that same stack lets the handler's
        // frame land on top of the guest's live frame, so give the handler a
        // stack of its own. `SA_ONSTACK` makes the kernel build the signal frame
        // and run the handler there instead.
        let alt_size: usize = 128 * 1024;
        let alt = libc::mmap(
            std::ptr::null_mut(),
            alt_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        );
        if alt != libc::MAP_FAILED {
            let mut ss: libc::stack_t = std::mem::zeroed();
            ss.ss_sp = alt;
            ss.ss_size = alt_size;
            ss.ss_flags = 0;
            if libc::sigaltstack(&ss, std::ptr::null_mut()) == 0 {
                sa.sa_flags |= libc::SA_ONSTACK;
            }
        }

        if libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) != 0 {
            return Err("sigaction(SIGSYS) failed".into());
        }

        // Ignore SIGPIPE: a guest writing to a closed pipe should see EPIPE
        // from the dispatcher, not die from a signal it cannot trap.
        let mut ign: sigaction = std::mem::zeroed();
        ign.sa_sigaction = libc::SIG_IGN;
        libc::sigaction(libc::SIGPIPE, &ign, std::ptr::null_mut());

        // Report fatal guest faults instead of dying silently.
        let mut fa: sigaction = std::mem::zeroed();
        let fhandler: extern "C" fn(c_int, *mut siginfo_t, *mut c_void) = fault_handler;
        fa.sa_sigaction = fhandler as usize;
        fa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut fa.sa_mask);
        for s in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE] {
            libc::sigaction(s, &fa, std::ptr::null_mut());
        }
    }
    TRACE.store(std::env::var_os("MYOS_TRACE").is_some(), Ordering::SeqCst);
    Ok(())
}

/// Installs the seccomp filter that traps guest-address syscalls.
fn install_filter(extra_allow: &[i64]) -> Result<(), String> {
    // Guest syscalls are all trapped; the caller's list names the few that
    // should still reach the host.
    let mut allow: Vec<i64> = ALLOWED_SYSCALLS.to_vec();
    for &nr in extra_allow {
        if !allow.contains(&nr) {
            allow.push(nr);
        }
    }

    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("PR_SET_NO_NEW_PRIVS failed".into());
        }

        let prog = build_filter(&allow);
        let mut fprog: libc::sock_fprog = std::mem::zeroed();
        fprog.len = prog.len() as u16;
        fprog.filter = prog.as_ptr() as *mut libc::sock_filter;

        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog) != 0 {
            return Err("PR_SET_SECCOMP failed (no CONFIG_SECCOMP_FILTER?)".into());
        }
    }
    Ok(())
}

/// Whether the filter is active in this process.
pub fn is_installed() -> bool {
    INSTALLED.load(Ordering::SeqCst)
}

/// Guest memory backed by the host's own address space.
///
/// Guest and kernel share one address space here, which is what makes this a
/// library OS rather than a hypervisor. Access checks are therefore the
/// dispatcher's job, not the MMU's.
pub struct HostMemory;

impl GuestMemory for HostMemory {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, oscore::vfs::Errno> {
        if addr == 0 || len == 0 {
            return Err(oscore::vfs::Errno::Inval);
        }
        unsafe { regs::read_guest(addr, len) }.ok_or(oscore::vfs::Errno::Inval)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), oscore::vfs::Errno> {
        if addr == 0 {
            return Err(oscore::vfs::Errno::Inval);
        }
        if unsafe { regs::write_guest(addr, data) } {
            Ok(())
        } else {
            Err(oscore::vfs::Errno::Inval)
        }
    }

    fn map(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
    ) -> Result<u64, oscore::vfs::Errno> {
        use oscore::syscall::{MAP_ANONYMOUS, MAP_FIXED};
        use oscore::vfs::Errno;
        if len == 0 {
            return Err(Errno::Inval);
        }
        let size = oscore::addr::align_up(len).ok_or(Errno::Inval)? as usize;

        // Guest and kernel share one address space, so a guest `mmap` becomes a
        // real `mmap` of this process. That is what makes the guest's memory
        // genuinely usable rather than a bookkeeping illusion. `monotonic` `brk`
        // aside, this is the whole of memory mediation.
        let mut mflags = libc::MAP_PRIVATE;
        if flags & MAP_ANONYMOUS != 0 {
            mflags |= libc::MAP_ANONYMOUS;
        }
        let mut hint = std::ptr::null_mut();
        if flags & MAP_FIXED != 0 {
            if addr == 0 {
                return Err(Errno::Inval);
            }
            mflags |= libc::MAP_FIXED;
            hint = (oscore::addr::align_down(addr)) as *mut c_void;
        }
        let p = unsafe { libc::mmap(hint, size, prot as i32, mflags, -1, 0) };
        if p == libc::MAP_FAILED {
            return Err(Errno::NoMem);
        }
        Ok(p as u64)
    }

    fn unmap(&mut self, addr: u64, len: u64) -> Result<(), oscore::vfs::Errno> {
        use oscore::vfs::Errno;
        if len == 0 {
            return Err(Errno::Inval);
        }
        let size = oscore::addr::align_up(len).ok_or(Errno::Inval)? as usize;
        let rc = unsafe { libc::munmap(addr as *mut c_void, size) };
        if rc != 0 {
            return Err(Errno::Inval);
        }
        Ok(())
    }

    fn protect(&mut self, addr: u64, len: u64, prot: u32) -> Result<(), oscore::vfs::Errno> {
        use oscore::vfs::Errno;
        if len == 0 {
            return Err(Errno::Inval);
        }
        // Guest and kernel share one address space, so a guest `mprotect` is a
        // real `mprotect` of this process's pages. That is what makes the guest's
        // protections binding: once glibc marks its GOT read-only for RELRO, a
        // guest write to it faults for real rather than being silently allowed.
        let size = oscore::addr::align_up(len).ok_or(Errno::Inval)? as usize;
        let rc = unsafe { libc::mprotect(addr as *mut c_void, size, prot as i32) };
        if rc != 0 {
            // The only failure the host reports for a guest request is a range
            // that is not mapped, which Linux also reports as `ENOMEM`.
            return Err(Errno::NoMem);
        }
        Ok(())
    }

    fn read_cstr(&self, addr: u64) -> Result<Vec<u8>, oscore::vfs::Errno> {
        if addr == 0 {
            return Err(oscore::vfs::Errno::Inval);
        }
        unsafe { regs::read_cstr_guest(addr, 4096) }.ok_or(oscore::vfs::Errno::NameTooLong)
    }
}

/// Host errno for the most recent failed libc call.
fn last_errno() -> i64 {
    unsafe { *libc::__errno_location() as i64 }
}

/// Reads a NULL-terminated `char *[]` from guest memory.
///
/// # Safety
/// Pointers must be within mapped guest memory; out-of-range reads are
/// rejected by `read_guest`.
unsafe fn read_guest_argv(mut ptr: u64) -> Result<Vec<Vec<u8>>, i64> {
    let mut out = Vec::new();
    if ptr == 0 {
        return Ok(out);
    }
    loop {
        let raw = regs::read_guest(ptr, 8).ok_or(libc::EFAULT as i64)?;
        let p = u64::from_ne_bytes(raw.try_into().unwrap());
        if p == 0 {
            return Ok(out);
        }
        let s = regs::read_cstr_guest(p, 4096).ok_or(libc::ENAMETOOLONG as i64)?;
        out.push(s);
        ptr += 8;
        if out.len() > 4096 {
            return Err(libc::E2BIG as i64);
        }
    }
}

/// Configures the host directory that backs the guest's `/`.
pub fn set_root(root: PathBuf) {
    let _ = ROOT.set(root);
}

/// The configured rootfs, if any.
pub fn root() -> Option<&'static Path> {
    ROOT.get().map(|p| p.as_path())
}

/// Translates a guest path to the host path under the configured root.
///
/// With no root configured the path is returned unchanged. `Vfs::normalize`
/// resolves `.`/`..` and rejects escapes, so a guest cannot climb out of the
/// root with `..`.
fn resolve_path(guest: &[u8]) -> Vec<u8> {
    let Some(root) = root() else {
        return guest.to_vec();
    };
    // A path the VFS refuses (non-UTF-8, `..` escape) must not fall back to the
    // host path. An empty path fails the metadata check, so `execve` sees
    // ENOENT instead of escaping the root.
    let Ok(s) = std::str::from_utf8(guest) else {
        return Vec::new();
    };
    let Ok(comps) = Vfs::normalize(s) else {
        return Vec::new();
    };
    let mut p = root.to_path_buf();
    for c in comps {
        p.push(c);
    }
    p.to_string_lossy().into_owned().into_bytes()
}

/// Replaces the current guest with a fresh `myos` that loads `path`.
///
/// `guest` is the path as the guest named it (kept as `argv[0]`); `host` is
/// where that path resolves on the host. The caller is already a forked guest,
/// so `myos --exec` loads the new image in place instead of forking again. A
/// seccomp filter survives `execve`; the SIGSYS disposition does not, so the
/// re-exec'd launcher re-arms the handler (and skips re-installing the filter,
/// which is already in force).
fn exec_trampoline(guest: &[u8], host: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>]) -> ! {
    let to_c = |s: &[u8]| {
        CString::new(s.iter().copied().filter(|b| *b != 0).collect::<Vec<u8>>()).unwrap_or_default()
    };

    // `myos --exec <argv0> <host-program> [args...]`: argv[0] and the file to
    // load are separate so the guest keeps seeing the name it invoked.
    let mut args_owned: Vec<CString> = Vec::new();
    args_owned.push(CString::new("myos").unwrap());
    args_owned.push(CString::new("--exec").unwrap());
    args_owned.push(to_c(if argv.is_empty() { guest } else { &argv[0] }));
    args_owned.push(to_c(host));
    for a in argv.iter().skip(1) {
        args_owned.push(to_c(a));
    }
    let mut argv_ptrs: Vec<*const c_char> = args_owned.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let mut env_owned: Vec<CString> = envp.iter().map(|e| to_c(e)).collect();
    // The re-exec'd launcher rebuilds the same rootfs and display from its
    // environment.
    if let Some(root) = root() {
        if let Ok(e) = CString::new(format!("MYOS_ROOT={}", root.display())) {
            env_owned.push(e);
        }
    }
    for key in ["MYOS_DISPLAY", "MYOS_FB_OUT"] {
        if let Ok(v) = std::env::var(key) {
            if let Ok(e) = CString::new(format!("{key}={v}")) {
                env_owned.push(e);
            }
        }
    }
    let mut env_ptrs: Vec<*const c_char> = env_owned.iter().map(|c| c.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());

    unsafe {
        libc::execve(
            b"/proc/self/exe\0".as_ptr() as *const c_char,
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
        );
        // Only reached if execve failed.
        libc::_exit(127);
    }
}

/// The host fd behind a guest descriptor, if it is host-backed.
///
/// Standard streams and pipes live in the host; VFS files return `None` and are
/// left to the dispatcher.
fn host_fd_of(fd: u32) -> Option<i32> {
    let g = state().lock().unwrap_or_else(|p| p.into_inner());
    match g.fds.get(Fd(fd)) {
        Ok(FdKind::Host(h)) => Some(h),
        _ => None,
    }
}

/// Services the syscalls that change process control flow or touch the host's
/// own file descriptors. Returns `true` when it handled the call.
///
/// These cannot go through the pure dispatcher: `fork`/`execve` replace or copy
/// the process, and `wait4`/host-fd I/O need the host kernel. Keeping them here
/// also means the trap state lock is never held across `fork`.
fn process_syscall(regs_in: &Registers, uc: &mut ucontext_t) -> bool {
    match regs_in.nr {
        // Returning from a handler restores the guest from the frame it was
        // given. This is not a normal syscall: it must run even while the
        // signal that caused the handler is still blocked, and it rewrites the
        // instruction pointer and stack rather than just `rax`.
        SYS_RT_SIGRETURN => {
            // The handler returned with `ret`, which already popped `pretcode`
            // from the top of the frame, so the frame itself is one word below
            // the stack pointer the guest arrives with. The kernel makes the
            // same adjustment.
            let sp = regs_in.rsp.wrapping_sub(8);
            let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
            let restored = crate::signal::sigreturn(uc, sp, &mut st.signals);
            drop(st);
            if !restored {
                // A handler that cannot return has left nothing sensible to
                // resume, so the guest ends here rather than running on.
                eprintln!("myos: rt_sigreturn could not restore the signal frame");
                unsafe { libc::_exit(139) };
            }
            true
        }
        // `kill` is the guest's own way of raising a signal. Only the guest
        // itself is addressable: there is one guest per host process, so a pid
        // of 0 or our own pid means "me" and anything else is `ESRCH`.
        SYS_KILL => {
            let pid = regs_in.arg(0) as i32;
            let signum = regs_in.arg(1) as i32;
            if signum < 1 || signum > 64 {
                regs::set_return(uc, -(libc::EINVAL as i64));
                return true;
            }
            let me = unsafe { libc::getpid() } as i32;
            if pid != 0 && pid != me {
                regs::set_return(uc, -(libc::ESRCH as i64));
                return true;
            }
            let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
            st.signals.queue(oscore::signal::Pending::kernel(
                signum,
                oscore::signal::SI_USER,
                0,
            ));
            drop(st);
            regs::set_return(uc, 0);
            true
        }
        // glibc's `fork` issues a fork-like `clone` (no new stack) rather than
        // the legacy `fork` syscall, so both are serviced the same way.
        SYS_CLONE if regs_in.arg(1) == 0 => {
            let child_tid = regs_in.arg(3);
            let set_tid = (regs_in.arg(0) & libc::CLONE_CHILD_SETTID as u64) != 0;
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                regs::set_return(uc, -last_errno());
            } else if pid == 0 {
                if set_tid && child_tid != 0 {
                    let tid = unsafe { libc::getpid() } as i32;
                    unsafe { regs::write_guest(child_tid, &tid.to_ne_bytes()) };
                }
                regs::set_return(uc, 0);
            } else {
                regs::set_return(uc, pid as i64);
            }
            true
        }
        SYS_FORK => {
            // `fork` while holding no lock: the child must not inherit a locked
            // mutex, or its next trap would deadlock.
            let pid = unsafe { libc::fork() };
            let ret = if pid < 0 { -last_errno() } else { pid as i64 };
            regs::set_return(uc, ret);
            true
        }
        SYS_GETPID => {
            regs::set_return(uc, unsafe { libc::getpid() } as i64);
            true
        }
        // Host-backed descriptors: the standard streams and pipes. Anything
        // else (a VFS file) falls through to the dispatcher.
        SYS_READ => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let buf = regs_in.arg(1);
            let len = regs_in.arg(2) as usize;
            if len == 0 {
                regs::set_return(uc, 0);
                return true;
            }
            // Read into a kernel buffer first so a bad guest pointer becomes an
            // error instead of a host fault.
            let mut tmp = vec![0u8; len.min(1 << 20)];
            let n = unsafe { libc::read(host, tmp.as_mut_ptr() as *mut c_void, tmp.len()) };
            if n < 0 {
                regs::set_return(uc, -last_errno());
            } else {
                unsafe { regs::write_guest(buf, &tmp[..n as usize]) };
                regs::set_return(uc, n as i64);
            }
            true
        }
        SYS_WRITE => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let buf = regs_in.arg(1);
            let len = regs_in.arg(2) as usize;
            let data = match unsafe { regs::read_guest(buf, len) } {
                Some(d) => d,
                None if len == 0 => Vec::new(),
                None => {
                    regs::set_return(uc, -(libc::EFAULT as i64));
                    return true;
                }
            };
            let n = unsafe { libc::write(host, data.as_ptr() as *const c_void, data.len()) };
            regs::set_return(uc, if n < 0 { -last_errno() } else { n as i64 });
            true
        }
        SYS_CLOSE => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            {
                let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
                let _ = g.fds.close(Fd(fd));
            }
            let r = unsafe { libc::close(host) };
            regs::set_return(uc, if r < 0 { -last_errno() } else { 0 });
            true
        }
        SYS_DUP | SYS_DUP2 | SYS_DUP3 => {
            let old = regs_in.arg(0) as u32;
            let new = regs_in.arg(1) as u32;
            let kind = {
                let g = state().lock().unwrap_or_else(|p| p.into_inner());
                g.fds.get(Fd(old))
            };
            let kind = match kind {
                Ok(k) => k,
                Err(_) => {
                    regs::set_return(uc, -(libc::EBADF as i64));
                    return true;
                }
            };
            // Only host-backed descriptors need the host to duplicate them. A
            // VFS file or an input stream is handled by the dispatcher, which
            // knows how to share an open file description properly.
            if !matches!(kind, FdKind::Host(_)) {
                return false;
            }
            if regs_in.nr == SYS_DUP {
                // `dup` returns the lowest free guest descriptor.
                let dup = match kind {
                    FdKind::Host(h) => {
                        let n = unsafe { libc::dup(h) };
                        if n < 0 {
                            regs::set_return(uc, -last_errno());
                            return true;
                        }
                        FdKind::Host(n)
                    }
                    FdKind::File(_) => kind,
                    _ => unreachable!("only host descriptors reach this arm"),
                };
                let fd = {
                    let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
                    g.fds.alloc_kind(dup).0
                };
                regs::set_return(uc, fd as i64);
                return true;
            }
            if old == new {
                regs::set_return(uc, new as i64);
                return true;
            }
            match kind {
                FdKind::Host(h) => {
                    let r = unsafe { libc::dup2(h, new as i32) };
                    if r < 0 {
                        regs::set_return(uc, -last_errno());
                    } else {
                        let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
                        g.fds.set(Fd(new), FdKind::Host(new as i32));
                        regs::set_return(uc, new as i64);
                    }
                }
                // Unreachable: host descriptors are filtered out above.
                _ => {
                    regs::set_return(uc, -(libc::EBADF as i64));
                }
            }
            true
        }
        SYS_PIPE | SYS_PIPE2 => {
            let mut pipe_fds = [0i32; 2];
            let flags = if regs_in.nr == SYS_PIPE2 {
                regs_in.arg(1) as c_int
            } else {
                0
            };
            if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), flags) } < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            let (rd, wr) = {
                let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
                (
                    g.fds.alloc_host(pipe_fds[0]).0,
                    g.fds.alloc_host(pipe_fds[1]).0,
                )
            };
            let ptr = regs_in.arg(0);
            unsafe {
                regs::write_guest(ptr, &rd.to_ne_bytes());
                regs::write_guest(ptr + 4, &wr.to_ne_bytes());
            }
            regs::set_return(uc, 0);
            true
        }
        SYS_IOCTL => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let req = regs_in.arg(1) as libc::c_ulong;
            let argp = regs_in.arg(2);
            let r = unsafe { libc::ioctl(host, req, argp as libc::c_ulong) };
            regs::set_return(uc, if r < 0 { -last_errno() } else { r as i64 });
            true
        }
        SYS_WAIT4 => {
            let mut status: c_int = 0;
            let r = unsafe {
                libc::wait4(
                    regs_in.arg(0) as libc::pid_t,
                    &mut status,
                    regs_in.arg(2) as c_int,
                    std::ptr::null_mut(),
                )
            };
            if r < 0 {
                regs::set_return(uc, -last_errno());
            } else {
                if regs_in.arg(1) != 0 {
                    unsafe { regs::write_guest(regs_in.arg(1), &status.to_ne_bytes()) };
                }
                regs::set_return(uc, r as i64);
            }
            true
        }
        SYS_EXECVE => {
            let path = unsafe { regs::read_cstr_guest(regs_in.arg(0), 4096) };
            let argv = unsafe { read_guest_argv(regs_in.arg(1)) };
            let envp = unsafe { read_guest_argv(regs_in.arg(2)) };
            match (path, argv, envp) {
                (Some(path), Ok(argv), Ok(envp)) => {
                    // Resolve through the rootfs, then report a missing target
                    // here: it is loaded by a fresh `myos`, so otherwise the
                    // failure would surface as that launcher's exit rather than
                    // an `execve` errno.
                    let host = resolve_path(&path);
                    let host_str = String::from_utf8_lossy(&host);
                    if let Err(e) = std::fs::metadata(host_str.as_ref()) {
                        let errno = e.raw_os_error().unwrap_or(libc::ENOENT as i32);
                        regs::set_return(uc, -(errno as i64));
                        return true;
                    }
                    exec_trampoline(&path, &host, &argv, &envp)
                }
                _ => {
                    regs::set_return(uc, -(libc::EFAULT as i64));
                    true
                }
            }
        }
        _ => false,
    }
}

/// The SIGSYS handler.
///
/// Runs on the guest's stack. Takes the global lock, runs the pure dispatcher,
/// and writes the result back into the saved `rax`.
extern "C" fn sigsys_handler(_sig: c_int, info: *mut siginfo_t, uc: *mut c_void) {
    if info.is_null() || uc.is_null() {
        return;
    }
    let info = unsafe { &*info };
    let uc = unsafe { &mut *(uc as *mut ucontext_t) };

    // Only traps we raised are ours. The kernel tags a seccomp trap with
    // `si_code == SYS_SECCOMP` and the syscall number in `si_syscall`; the
    // filter's action (`SECCOMP_RET_TRAP`) is not what appears here. Anything
    // else — a fault in the filter, a stray SIGSYS — must not be serviced as a
    // syscall.
    if info.si_code != SYS_SECCOMP {
        unsafe {
            libc::_exit(159);
        }
    }

    // The guest may have pointed `%fs` at its own TLS. Every libc and Rust
    // access below resolves thread-locals through `%fs`, so the host's base has
    // to be back in place before any of it runs.
    let kfs = KERNEL_FS.load(Ordering::SeqCst);
    if kfs != 0 {
        unsafe { set_fs(kfs) };
    }

    let regs_in = regs::registers_from(uc);

    // Process-control and host-fd syscalls are serviced directly, before the
    // dispatcher and without the trap lock.
    if process_syscall(&regs_in, uc) {
        // A `kill` serviced above queues a signal, and that signal has to be
        // delivered before the guest resumes: a real kernel delivers it as part
        // of returning from the `kill` itself, not at some later boundary.
        deliver_pending(uc);
        // The guest resumes as soon as this handler returns, so hand `%fs` back
        // to it here too; the normal path does this after the dispatcher.
        let gfs = match state().lock() {
            Ok(g) => g.guest_fs,
            Err(p) => p.into_inner().guest_fs,
        };
        if gfs != 0 && gfs != kfs {
            unsafe { set_fs(gfs) };
        }
        return;
    }

    let mut mem = HostMemory;

    let (result, out, present, exit, guest_fs, sleep, parked) = {
        let mut st = match state().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // The clock is refreshed before the syscall runs, not after, so a guest
        // that reads the time and then sleeps sees the deadline it just read.
        if !st.clock_started {
            st.clock = oscore::clock::Clock::new(
                host_clock_ns(libc::CLOCK_REALTIME),
                host_clock_ns(libc::CLOCK_MONOTONIC),
            );
            st.clock_started = true;
        } else {
            st.clock.advance_to(host_clock_ns(libc::CLOCK_MONOTONIC));
        }

        // Destructure so the vfs and fd borrows are provably disjoint; taking
        // both through `st` directly would be a double mutable borrow.
        let TrapState {
            vfs,
            fds,
            stdout,
            exited,
            brk,
            mapped_brk,
            pid,
            guest_fs,
            display,
            frame,
            clock,
            clock_started: _,
            signals,
            input,
            cwd,
            umask,
            frame_counter,
            waiting_for_input,
            input_fd,
        } = &mut *st;
        let mut gs = GuestState {
            vfs,
            brk: *brk,
            exited: *exited,
            pid: *pid,
            pending_mmap: Vec::new(),
            stdout: std::mem::take(stdout),
            fs_base: 0,
            fs_set: false,
            display: std::mem::take(display),
            frame: std::mem::take(frame),
            clock: *clock,
            signals: std::mem::take(signals),
            input: std::mem::take(input),
            cwd: std::mem::take(cwd),
            umask: *umask,
            frame_counter: *frame_counter,
            pending_sleep: None,
            pending_input_wait: *waiting_for_input,
            input_fd: *input_fd,
            sync: None,
        };
        // A `present` is one composited frame; the counter lets a guest that is
        // redrawing in a loop keep a steady cadence.
        if !gs.frame.is_empty() {
            gs.frame_counter += 1;
        }
        let r = dispatch(&regs_in, &mut mem, &mut gs, fds);
        *exited = gs.exited;
        *brk = gs.brk;
        *pid = gs.pid;
        *clock = gs.clock;
        *signals = std::mem::take(&mut gs.signals);
        *input = std::mem::take(&mut gs.input);
        *cwd = std::mem::take(&mut gs.cwd);
        *umask = gs.umask;
        *frame_counter = gs.frame_counter;
        *waiting_for_input = gs.pending_input_wait;
        *input_fd = gs.input_fd;
        // `arch_prctl(ARCH_SET_FS)` is recorded by the dispatcher but must not
        // take effect until the guest resumes, so carry it out here.
        if gs.fs_set {
            *guest_fs = gs.fs_base;
        }
        // `brk` is pure bookkeeping in the dispatcher, which keeps it testable
        // without a host. The host realises the growth here. The break is
        // byte-granular but memory is mapped a page at a time, so growth is
        // rounded up: mapping from a non-page-aligned break would pull the
        // start of the range down onto the previous page and wipe whatever is
        // already there (glibc's TLS block, for one).
        if regs_in.nr == SYS_BRK {
            if let (Some(old), Some(new)) = (
                oscore::addr::align_up(*mapped_brk),
                oscore::addr::align_up(gs.brk),
            ) {
                if new > old {
                    let _ = mem.map(
                        old,
                        new - old,
                        PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_FIXED,
                    );
                    *mapped_brk = new;
                }
            }
        }
        let out = std::mem::take(&mut gs.stdout);
        let present = std::mem::take(&mut gs.frame);
        // Carry the window model back so state survives between traps.
        *display = gs.display;

        (
            r,
            out,
            present,
            gs.exited,
            *guest_fs,
            gs.pending_sleep,
            gs.pending_input_wait,
        )
    };

    trace(regs_in.nr, regs_in.arg(0), regs_in.rip, result);

    // A guest that asked to sleep is served here rather than in the dispatcher,
    // which has no way to pass the time. The instruction pointer is rewound to
    // the `syscall` so the guest re-executes it once the wait is over, which is
    // what makes `nanosleep` restartable and lets an interval timer work.
    if let Some(sleep) = sleep {
        if parked {
            wait_for_input(sleep.deadline_ns);
        } else {
            sleep_until(sleep.deadline_ns);
        }
        if parked {
            // The guest parked in `input_wait` and has just been given the
            // chance to receive events. Re-run the call so it observes them and
            // returns a real count rather than the placeholder the dispatcher
            // wrote; this is what makes `input_wait` a wait rather than a poll
            // that always says "nothing yet".
            rewind(&mut *uc);
        }
        clear_sleep();
    }

    // Forward anything the guest wrote to fd 1. The handler runs from kernel
    // code, so this `write` is a high-address syscall the filter allows.
    if !out.is_empty() {
        unsafe { libc::write(1, out.as_ptr() as *const c_void, out.len()) };
    }

    // A composited frame is written out only when `MYOS_FB_OUT` names a file,
    // which is what makes the display observable without a real window.
    if !present.is_empty() {
        if let Some(path) =
            FB_OUT.get_or_init(|| std::env::var_os("MYOS_FB_OUT").map(PathBuf::from))
        {
            if let Err(e) = std::fs::write(path, &present) {
                eprintln!("myos: framebuffer -> {}: {e}", path.display());
            }
        } else {
            // With no file configured, push the frame to the real window.
            crate::display::present(&present);
        }
    }

    // An explicit `sync` writes the filesystem out immediately.
    if regs_in.nr == SYS_SYNC_FS {
        if let Some(stats) = sync_filesystem() {
            if TRACE.load(Ordering::Relaxed) {
                eprintln!(
                    "myos: sync {} files, {} dirs, {} bytes",
                    stats.files, stats.dirs, stats.bytes
                );
            }
        }
    }

    // `exit` is a mediated syscall: the dispatcher records the status, and the
    // host process is ended here. Returning to the guest after it asked to exit
    // would resume the instruction after `syscall`, which no longer exists.
    // The filesystem is written out first, because after `_exit` there is no
    // second chance and a guest that never called `sync` would lose its work.
    if let Some(code) = exit {
        sync_filesystem();
        unsafe { libc::_exit(code) };
    }

    // Linux reports failure as a negative errno in rax.
    let ret = match result {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    };
    // Release every host-owned allocation now, while `%fs` still points at the
    // host's TLS. The allocator reads its per-thread cache through `%fs`, so a
    // `drop` running after the switch below would read the guest's TLS and
    // fault. Calling this out explicitly keeps it ahead of the `set_fs`.
    drop(out);
    drop(present);

    // The syscall's own result goes in before any signal is delivered. A frame
    // built now saves `rax` as it stands and `rt_sigreturn` puts it back, so a
    // result written afterwards would be thrown away and the guest would resume
    // with whatever `rax` held before the syscall.
    //
    // For a seccomp TRAP the kernel has already advanced `rip` past the
    // `syscall` instruction, so only `rax` needs writing; touching `rip` would
    // resume in the middle of the next instruction.
    regs::set_return(uc, ret);

    // A signal raised by this syscall, or left over from a fault, is delivered
    // now that the guest is at a syscall boundary — the one place it can be
    // interrupted safely. Delivery rewrites `rip`/`rsp` to enter the handler.
    if regs_in.nr != SYS_RT_SIGRETURN {
        deliver_pending(uc);
    }

    // Hand `%fs` back to the guest. This is the last thing that may run before
    // the guest resumes: any TLS access after it would use the guest's base.
    if guest_fs != 0 && guest_fs != kfs {
        unsafe { set_fs(guest_fs) };
    }
}

/// Hands the guest any signal it is ready to receive.
///
/// Called with `%fs` still pointing at the host, because building the frame
/// allocates. Returns without touching `uc` when there is nothing to deliver,
/// which is the overwhelmingly common case.
fn deliver_pending(uc: &mut ucontext_t) {
    let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
    if st.signals.pending_len() == 0 {
        return;
    }
    match crate::signal::deliver(&mut st.signals, uc) {
        crate::signal::Delivered::Dropped | crate::signal::Delivered::Undeliverable => {}
        crate::signal::Delivered::Fatal(signum) => {
            drop(st);
            // No handler and a fatal default: end the guest the way the signal
            // would have, so a shell still sees 128+signum.
            unsafe { libc::_exit(128 + signum) };
        }
        crate::signal::Delivered::Went(_) => {
            // Nothing more to do: `rax` already holds the syscall's result, and
            // the frame saved it so `rt_sigreturn` will hand it back.
        }
    }
}

/// Drains anything the guest wrote to stdout.
pub fn take_stdout() -> Vec<u8> {
    match state().lock() {
        Ok(mut g) => std::mem::take(&mut g.stdout),
        Err(p) => std::mem::take(&mut p.into_inner().stdout),
    }
}

/// The guest's exit status, if it called `exit`.
pub fn exit_status() -> Option<i32> {
    state().lock().ok().and_then(|g| g.exited)
}

/// Runs `f` against the guest's filesystem.
pub fn with_vfs<R>(f: impl FnOnce(&mut Vfs) -> R) -> R {
    let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g.vfs)
}

/// Runs `f` against the guest's fd table.
pub fn with_fds<R>(f: impl FnOnce(&mut FdTable) -> R) -> R {
    let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g.fds)
}

/// Registers a file in the guest's filesystem so it can be opened by path.
pub fn provide_file(path: &str, data: &[u8]) -> Result<(), oscore::vfs::Errno> {
    with_vfs(|vfs| vfs.create(path, data)).map(|_ino| ())
}

/// Registers a directory in the guest's filesystem.
pub fn provide_dir(path: &str) -> Result<(), oscore::vfs::Errno> {
    with_vfs(|vfs| vfs.mkdir(path)).map(|_ino| ())
}

/// Mirrors a host directory into the guest filesystem.
///
/// The direction is chosen by what is already there. A directory that was never
/// written to is pulled in; one the guest has modified is pushed back out. That
/// makes the filesystem survive a run without a guest ever calling `sync`, while
/// still letting a guest change its own tree.
pub fn preload_root(root: &Path) -> Result<usize, String> {
    let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
    oscore::persist::read_all(root, &mut g.vfs)
}

/// Sets the guest's initial program break, normally the page-aligned end of the
/// loaded image. `brk(0)` then reports this address and growth is measured from
/// here, instead of from zero.
pub fn set_initial_brk(addr: u64) {
    let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
    st.brk = addr;
    st.mapped_brk = addr;
}
