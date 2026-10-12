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
//!    `ucontext_t`, runs the pure dispatcher from `parasyte_core`, and writes the
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
use parasyte_core::syscall::{
    dispatch, FdKind, FdTable, GuestMemory, GuestState, Registers, MAP_ANONYMOUS, MAP_FIXED,
    PROT_READ, PROT_WRITE, SYS_ACCEPT, SYS_BIND, SYS_BRK, SYS_CLONE, SYS_CLOSE, SYS_CONNECT,
    SYS_DUP, SYS_DUP2, SYS_DUP3, SYS_EXECVE, SYS_FCNTL, SYS_FORK, SYS_FSTAT, SYS_GETDENTS,
    SYS_GETPEERNAME, SYS_GETPGID, SYS_GETPGRP, SYS_GETPID, SYS_GETSID, SYS_GETSOCKNAME,
    SYS_GETSOCKOPT, SYS_IOCTL, SYS_KILL, SYS_LISTEN,     SYS_DISPLAY_XID, SYS_OPEN, SYS_OPENAT, SYS_PIPE, SYS_PIPE2, SYS_POLL, SYS_WINDOW_MOVE, SYS_WINDOW_RESIZE,
    SYS_READ, SYS_RECVFROM, SYS_RECVMSG, SYS_RT_SIGRETURN, SYS_SENDMSG, SYS_SENDTO, SYS_SETPGID,
    SYS_SETSID, SYS_SETSOCKOPT, SYS_SHUTDOWN, SYS_SOCKET, SYS_SOCKETPAIR, SYS_SYNC_FS,
    SYS_UNLINK, SYS_UNLINKAT, SYS_WAIT4, SYS_WRITE,
};
use parasyte_core::vfs::{Fd, Vfs};
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
    pub display: parasyte_core::gfx::Display,
    /// PPM bytes produced by the last `display_present`, drained by the handler.
    pub frame: Vec<u8>,
    /// Wall and monotonic time, refreshed from the host before every trap so a
    /// guest's clock moves even when it makes no syscalls of its own.
    pub clock: parasyte_core::clock::Clock,
    /// Whether `clock` has been seeded with a host reading yet.
    pub clock_started: bool,
    /// Signal dispositions, blocked mask and pending queue.
    pub signals: parasyte_core::signal::SignalTable,
    /// Keyboard and mouse events waiting for the guest.
    pub input: parasyte_core::input::InputQueue,
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
    /// Epoll instances, keyed by guest fd.
    pub epolls: std::collections::BTreeMap<u32, parasyte_core::syscall::EpollInstance>,
    /// Eventfds, keyed by guest fd.
    pub eventfds: std::collections::BTreeMap<u32, parasyte_core::syscall::EventFd>,
    /// Futex table.
    pub futexes: std::collections::BTreeMap<u64, parasyte_core::syscall::Futex>,
    /// Platform-provided poll function for host-backed fds.
    pub poll_host: Option<fn(i32, i16) -> i16>,
    /// Platform-provided pty: open a pseudo-terminal master.
    pub pty_open: Option<fn() -> i32>,
    /// Grant access to the slave side of a pty.
    pub pty_grant: Option<fn(i32) -> i32>,
    /// Unlock the slave side of a pty.
    pub pty_unlock: Option<fn(i32) -> i32>,
    /// Get the name of the slave device for a pty master.
    pub pty_name: Option<fn(i32) -> String>,
    /// Get terminal attributes.
    pub pty_getattr: Option<fn(i32) -> Vec<u8>>,
    /// Set terminal attributes.
    pub pty_setattr: Option<fn(i32, &[u8]) -> i32>,
    /// Generic ioctl wrapper.
    pub pty_ioctl: Option<fn(i32, u64, u64) -> i32>,
    /// Get window size.
    pub pty_winsz_get: Option<fn(i32) -> Vec<u8>>,
    /// Set window size.
    pub pty_winsz_set: Option<fn(i32, &[u8]) -> i32>,
    /// Set foreground process group (`tcsetpgrp` job control).
    pub pty_setpgrp: Option<fn(i32, u32) -> i32>,
    /// Get foreground process group (`tcgetpgrp` job control).
    pub pty_getpgrp: Option<fn(i32) -> i32>,
    /// Platform-provided shared memory: create a memfd.
    pub memfd_create: Option<fn(&str, u32) -> i32>,
    /// Open a shared memory object.
    pub shm_open: Option<fn(&str, u32) -> i32>,
    /// Unlink a shared memory object.
    pub shm_unlink: Option<fn(&str)>,
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
            display: parasyte_core::gfx::Display::new(display_width(), display_height()),
            frame: Vec::new(),
            clock: parasyte_core::clock::Clock::default(),
            clock_started: false,
            signals: parasyte_core::signal::SignalTable::new(),
            input: parasyte_core::input::InputQueue::new(),
            cwd: "/".to_string(),
            umask: 0o022,
            frame_counter: 0,
            waiting_for_input: false,
            input_fd: None,
            epolls: std::collections::BTreeMap::new(),
            eventfds: std::collections::BTreeMap::new(),
            futexes: std::collections::BTreeMap::new(),
            poll_host: None,
            pty_open: None,
            pty_grant: None,
            pty_unlock: None,
            pty_name: None,
            pty_getattr: None,
            pty_setattr: None,
            pty_ioctl: None,
            pty_winsz_get: None,
            pty_winsz_set: None,
            pty_setpgrp: None,
            pty_getpgrp: None,
            memfd_create: None,
            shm_open: None,
            shm_unlink: None,
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

/// Waits for a `poll` set to become ready, honouring the guest's timeout.
///
/// The dispatcher is synchronous, so it can only snapshot readiness: a call
/// with nothing ready *yet* reports zero even when data arrives a millisecond
/// later, which stranded every DNS lookup (UDP and TCP alike). The real wait
/// happens here on the host: block in `poll(2)` over the host-backed subset,
/// pump input between chunks so the UI stays alive, and wake early if input
/// the guest also watches arrives. Returns true when something is (probably)
/// ready; the caller then rewinds so the guest re-runs the call and the
/// dispatcher takes a fresh snapshot. A timed-out wait returns false and the
/// dispatcher's zero stands, which keeps one guest wait to one host wait.
fn poll_wait_for_ready(fds_ptr: u64, nfds: usize, timeout_ms: i32) -> bool {
    const POLLFD_SIZE: usize = 8;
    const POLLIN: u16 = 0x001;
    if nfds == 0 {
        // Nothing to wait on: `poll` with no fds is a sleep.
        if timeout_ms > 0 {
            let now = host_clock_ns(libc::CLOCK_MONOTONIC).max(0) as u64;
            sleep_until(now + timeout_ms as u64 * 1_000_000);
        }
        return false;
    }
    if nfds > 1024 {
        return false;
    }
    let raw = match unsafe { regs::read_guest(fds_ptr, nfds * POLLFD_SIZE) } {
        Some(b) => b,
        None => return false,
    };
    // Map the guest set onto host fds; note whether the guest also watches
    // its input queue so input arrival wakes the wait too.
    let mut host: Vec<libc::pollfd> = Vec::new();
    let mut watches_input = false;
    {
        let g = state().lock().unwrap_or_else(|p| p.into_inner());
        for i in 0..nfds {
            let off = i * POLLFD_SIZE;
            let fd = i32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
            let events = u16::from_le_bytes(raw[off + 4..off + 6].try_into().unwrap());
            if events == 0 {
                continue;
            }
            match g.fds.get(Fd(fd as u32)) {
                Ok(FdKind::Host(h)) => host.push(libc::pollfd {
                    fd: h,
                    events: events as i16,
                    revents: 0,
                }),
                Ok(FdKind::Input) => {
                    if events & POLLIN != 0 {
                        watches_input = true;
                    }
                }
                _ => {}
            }
        }
    }
    let infinite = timeout_ms < 0;
    let deadline = if infinite {
        u64::MAX
    } else {
        host_clock_ns(libc::CLOCK_MONOTONIC).max(0) as u64 + timeout_ms as u64 * 1_000_000
    };
    loop {
        let now = host_clock_ns(libc::CLOCK_MONOTONIC).max(0) as u64;
        if !infinite && now >= deadline {
            return false;
        }
        let chunk_ms: i32 = if infinite {
            25
        } else {
            ((deadline - now) / 1_000_000).min(25).max(1) as i32
        };
        if !host.is_empty() {
            for pfd in host.iter_mut() {
                pfd.revents = 0;
            }
            let rc =
                unsafe { libc::poll(host.as_mut_ptr(), host.len() as libc::nfds_t, chunk_ms) };
            if rc > 0 {
                return true;
            }
            if rc < 0 && last_errno() as libc::c_int != libc::EINTR {
                return false;
            }
        } else {
            // No host fds: nap so input can arrive, then re-check below.
            let chunk_ns = chunk_ms as u64 * 1_000_000;
            let ts = libc::timespec {
                tv_sec: (chunk_ns / 1_000_000_000) as libc::time_t,
                tv_nsec: (chunk_ns % 1_000_000_000) as libc::c_long,
            };
            unsafe {
                libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts, std::ptr::null_mut())
            };
        }
        pump_input();
        if watches_input {
            let have = match state().lock() {
                Ok(g) => !g.input.is_empty(),
                Err(p) => !p.into_inner().input.is_empty(),
            };
            if have {
                return true;
            }
        }
        // An infinite wait with nothing host-side or input-side to watch can
        // never wake; bail instead of hanging the emulator.
        if infinite && host.is_empty() && !watches_input {
            return false;
        }
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
pub fn sync_filesystem() -> Option<parasyte_core::persist::SyncStats> {
    let root = ROOT.get()?;
    let g = state().lock().unwrap_or_else(|p| p.into_inner());
    match parasyte_core::persist::write_all(&g.vfs, root) {
        Ok(stats) => Some(stats),
        Err(e) => {
            eprintln!("parasyteos: filesystem sync failed: {e}");
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
/// through `PARASYTEOS_FB_OUT`.
static FB_OUT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Display width, from `PARASYTEOS_DISPLAY` (`WxH`) or the model's default.
fn display_width() -> u32 {
    parse_display().0
}

/// Display height, from `PARASYTEOS_DISPLAY` (`WxH`) or the model's default.
fn display_height() -> u32 {
    parse_display().1
}

/// Parses `PARASYTEOS_DISPLAY`, falling back to the model defaults.
fn parse_display() -> (u32, u32) {
    let (mut w, mut h) = (parasyte_core::gfx::DEFAULT_WIDTH, parasyte_core::gfx::DEFAULT_HEIGHT);
    if let Ok(spec) = std::env::var("PARASYTEOS_DISPLAY") {
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

/// Logs one trapped syscall to stderr when `PARASYTEOS_TRACE=1` is set.
fn trace(nr: i64, arg0: u64, ip: u64, ret: Result<u64, parasyte_core::vfs::Errno>) {
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
        for &b in b"parasyteos: fault sig=" {
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

/// Returns the global trap state, initializing it if necessary.
pub fn state() -> &'static Mutex<TrapState> {
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
    TRACE.store(std::env::var_os("PARASYTEOS_TRACE").is_some(), Ordering::SeqCst);
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
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, parasyte_core::vfs::Errno> {
        if addr == 0 || len == 0 {
            return Err(parasyte_core::vfs::Errno::Inval);
        }
        unsafe { regs::read_guest(addr, len) }.ok_or(parasyte_core::vfs::Errno::Inval)
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), parasyte_core::vfs::Errno> {
        if addr == 0 {
            return Err(parasyte_core::vfs::Errno::Inval);
        }
        if unsafe { regs::write_guest(addr, data) } {
            Ok(())
        } else {
            Err(parasyte_core::vfs::Errno::Inval)
        }
    }

    fn map(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
    ) -> Result<u64, parasyte_core::vfs::Errno> {
        use parasyte_core::syscall::{MAP_ANONYMOUS, MAP_FIXED};
        use parasyte_core::vfs::Errno;
        if len == 0 {
            return Err(Errno::Inval);
        }
        let size = parasyte_core::addr::align_up(len).ok_or(Errno::Inval)? as usize;

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
            hint = (parasyte_core::addr::align_down(addr)) as *mut c_void;
        }
        let p = unsafe { libc::mmap(hint, size, prot as i32, mflags, -1, 0) };
        if p == libc::MAP_FAILED {
            return Err(Errno::NoMem);
        }
        Ok(p as u64)
    }

    fn unmap(&mut self, addr: u64, len: u64) -> Result<(), parasyte_core::vfs::Errno> {
        use parasyte_core::vfs::Errno;
        if len == 0 {
            return Err(Errno::Inval);
        }
        let size = parasyte_core::addr::align_up(len).ok_or(Errno::Inval)? as usize;
        let rc = unsafe { libc::munmap(addr as *mut c_void, size) };
        if rc != 0 {
            return Err(Errno::Inval);
        }
        Ok(())
    }

    fn protect(&mut self, addr: u64, len: u64, prot: u32) -> Result<(), parasyte_core::vfs::Errno> {
        use parasyte_core::vfs::Errno;
        if len == 0 {
            return Err(Errno::Inval);
        }
        // Guest and kernel share one address space, so a guest `mprotect` is a
        // real `mprotect` of this process's pages. That is what makes the guest's
        // protections binding: once glibc marks its GOT read-only for RELRO, a
        // guest write to it faults for real rather than being silently allowed.
        let size = parasyte_core::addr::align_up(len).ok_or(Errno::Inval)? as usize;
        let rc = unsafe { libc::mprotect(addr as *mut c_void, size, prot as i32) };
        if rc != 0 {
            // The only failure the host reports for a guest request is a range
            // that is not mapped, which Linux also reports as `ENOMEM`.
            return Err(Errno::NoMem);
        }
        Ok(())
    }

    fn read_cstr(&self, addr: u64) -> Result<Vec<u8>, parasyte_core::vfs::Errno> {
        if addr == 0 {
            return Err(parasyte_core::vfs::Errno::Inval);
        }
        unsafe { regs::read_cstr_guest(addr, 4096) }.ok_or(parasyte_core::vfs::Errno::NameTooLong)
    }
}

/// Host errno for the most recent failed libc call.
fn last_errno() -> i64 {
    unsafe { *libc::__errno_location() as i64 }
}

/// Creates a memfd (anonymous shared memory file descriptor).
pub fn memfd_create(name: &str, flags: u32) -> i32 {
    let c_name = std::ffi::CString::new(name).unwrap_or_default();
    unsafe { libc::memfd_create(c_name.as_ptr(), flags as libc::c_uint) }
}

/// Opens a shared memory object.
pub fn shm_open(name: &str, flags: u32) -> i32 {
    let c_name = std::ffi::CString::new(name).unwrap_or_default();
    unsafe {
        let fd = libc::shm_open(c_name.as_ptr(), flags as libc::c_int, 0o600);
        if fd < 0 { -1 } else { fd }
    }
}

/// Unlinks a shared memory object.
pub fn shm_unlink(name: &str) {
    let c_name = std::ffi::CString::new(name).unwrap_or_default();
    unsafe { libc::shm_unlink(c_name.as_ptr()); }
}

/// Opens a host path on behalf of the guest.
///
/// Returns `None` when `path` is not bridged; otherwise the host `open()`
/// is attempted: `Ok(fd)` on success, `Err(errno)` on failure. Bridged:
///
/// - `/dev/ptmx` and absolute numeric `/dev/pts/<n>` (pty masters/slaves;
///   `ptsname()` hands the guest host paths, so without this no terminal
///   could ever open its slave side);
/// - `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`,
///   `/etc/services` (read-only: glibc's resolver consults them, and the
///   guest VFS carries no host network configuration);
/// - `/dev/urandom` and `/dev/random` (read-only entropy for TLS and key
///   generation; writes are rejected with `EPERM`);
/// - `/dev/audio` (write-only: raw unsigned 8-bit mono PCM at 8000 Hz.
///   Writes stream to the host's `paplay` (PulseAudio); the format is
///   intentionally fixed — this is an 8-bit minimalist sound card, not a
///   mixer. Reads are rejected. Set `PARASYTEOS_AUDIO_CMD` to redirect playback,
///   e.g. `tee /tmp/cap.u8`, for testing without speakers);
/// - `/winserv` and everything under it (the window-server rendezvous:
///   client registrations and the server pid file). This is the one
///   host-backed shared namespace: every guest process sees the same
///   directory, which is what lets a desktop in one process discover
///   clients living in others. Requires a configured rootfs; without one
///   the paths stay VFS-local. Parent directories are created on demand.
///
/// Spawns the host audio player for `/dev/audio` and returns the write end
/// of its stdin as a host fd. Guest bytes are unsigned 8-bit mono PCM at
/// 8000 Hz; the player (`paplay` over PulseAudio by default) drains the
/// pipe at its own pace, so a writing guest blocks with natural
/// sound-card backpressure. Closing the fd sends EOF and the player exits;
/// a detached thread reaps it so no zombie lingers.
///
/// `PARASYTEOS_AUDIO_CMD` overrides the player (whitespace-split, no quoting):
/// `PARASYTEOS_AUDIO_CMD="tee /tmp/cap.u8"` captures guest audio to a file for
/// testing on a headless box.
fn audio_open() -> Result<i32, i32> {
    use std::os::unix::io::IntoRawFd;
    use std::process::{Command, Stdio};
    let cmdline = std::env::var("PARASYTEOS_AUDIO_CMD").unwrap_or_else(|_| {
        "paplay --raw --rate=8000 --channels=1 --format=u8".to_string()
    });
    let mut words = cmdline.split_whitespace();
    let prog = words.next().unwrap_or("paplay");
    let mut child = Command::new(prog)
        .args(words)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| libc::ENODEV)?;
    let stdin = child.stdin.take().ok_or(libc::ENODEV)?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(stdin.into_raw_fd())
}

/// Everything else belongs to the guest VFS.
fn host_bridge_open(path: &[u8], flags: i32, mode: u32) -> Option<Result<i32, i64>> {
    // Guest flag bits match Linux `O_*`; carry blocking mode across and
    // never let the slave become our controlling terminal here (the guest
    // claims it explicitly with `TIOCSCTTY` after `setsid`).
    let mut oflags = libc::O_RDWR | libc::O_NOCTTY;
    if flags & libc::O_NONBLOCK != 0 {
        oflags |= libc::O_NONBLOCK;
    }
    if flags & libc::O_CLOEXEC != 0 {
        oflags |= libc::O_CLOEXEC;
    }
    if path == b"/dev/ptmx" {
        let fd = unsafe { libc::posix_openpt(oflags) };
        if fd < 0 {
            return Some(Err(last_errno()));
        }
        if unsafe { libc::grantpt(fd) } != 0 || unsafe { libc::unlockpt(fd) } != 0 {
            unsafe { libc::close(fd) };
            return Some(Err(last_errno()));
        }
        return Some(Ok(fd));
    }
    if let Some(rest) = path.strip_prefix(b"/dev/pts/") {
        if rest.is_empty() || !rest.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
    } else if matches!(path, b"/dev/urandom" | b"/dev/random") {
        // Entropy is read-only; there is nothing meaningful to write.
        if flags & 0o3 != 0 {
            return Some(Err(libc::EPERM as i64));
        }
        oflags = libc::O_RDONLY | libc::O_NOCTTY;
        if flags & libc::O_CLOEXEC != 0 {
            oflags |= libc::O_CLOEXEC;
        }
    } else if path == b"/dev/audio" {
        // 8-bit sound out: anything but write access makes no sense.
        if flags & 0o3 == libc::O_RDONLY {
            return Some(Err(libc::EACCES as i64));
        }
        return Some(audio_open().map_err(|e| e as i64));
    } else if path == b"/winserv" || path.starts_with(b"/winserv/") {
        use std::os::unix::ffi::OsStrExt;
        let host = winserv_host_path(path)?;
        // The namespace is created on demand: guests mkdir it in their own
        // VFS (a per-process shadow), so the host side must not depend on
        // any guest having created it first.
        if let Some(root) = root() {
            let _ = std::fs::create_dir_all(root.join("winserv/clients"));
        }
        if flags & libc::O_CREAT != 0 {
            if let Some(parent) = host.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let cpath = std::ffi::CString::new(host.as_os_str().as_bytes()).ok()?;
        // Guest O_* bits match the host's, so they pass straight through
        // (O_CREAT/O_TRUNC/O_APPEND/O_DIRECTORY included); O_NOCTTY is a
        // no-op on these files but keeps pty semantics out of the shared
        // namespace. The mode travels too: without it an O_CREAT open
        // invents permissions from whatever vararg slot the host reads.
        let oflags = flags | libc::O_NOCTTY;
        let fd = if flags & libc::O_CREAT != 0 {
            unsafe { libc::open(cpath.as_ptr(), oflags, mode as libc::mode_t) }
        } else {
            unsafe { libc::open(cpath.as_ptr(), oflags) }
        };
        if fd < 0 {
            return Some(Err(last_errno()));
        }
        return Some(Ok(fd));
    } else if !matches!(
        path,
        b"/etc/resolv.conf" | b"/etc/hosts" | b"/etc/nsswitch.conf" | b"/etc/services"
    ) {
        return None;
    } else {
        // Resolver configuration is bridged read-only: a guest must never
        // rewrite the host's network configuration through this hole.
        oflags = libc::O_RDONLY | libc::O_NOCTTY;
        if flags & libc::O_CLOEXEC != 0 {
            oflags |= libc::O_CLOEXEC;
        }
    }
    let cpath = std::ffi::CString::new(path).ok()?;
    let fd = unsafe { libc::open(cpath.as_ptr(), oflags) };
    if fd < 0 {
        return Some(Err(last_errno()));
    }
    Some(Ok(fd))
}

/// Maps a guest `/winserv/...` path onto the host rootfs, or `None` when
/// the path is outside the namespace or no rootfs is configured.
///
/// Bridged: the directory itself, `server.pid`, the `clients` directory,
/// `clients/<pid>`, and the `desktop` directory with its `xid` and `geom`
/// rendezvous files. Anything else (deeper paths, `..`) stays in the
/// guest VFS, so a guest cannot use this hole to reach the rest of the
/// rootfs.
fn winserv_host_path(path: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let root = root()?;
    let mut base = root.to_path_buf();
    base.push("winserv");
    if path == b"/winserv" {
        return Some(base);
    }
    let rel = path.strip_prefix(b"/winserv/")?;
    if rel == b"server.pid" || rel == b"clients" || rel == b"desktop" {
        base.push(std::ffi::OsStr::from_bytes(rel));
        return Some(base);
    }
    if rel == b"desktop/xid" || rel == b"desktop/geom" {
        base.push("desktop");
        base.push(std::ffi::OsStr::from_bytes(&rel[b"desktop/".len()..]));
        return Some(base);
    }
    let name = rel.strip_prefix(b"clients/")?;
    if name.is_empty() || name.contains(&b'/') || name.contains(&b'\0') {
        return None;
    }
    base.push("clients");
    base.push(std::ffi::OsStr::from_bytes(name));
    Some(base)
}

/// Opens a pseudo-terminal master. Returns the host fd, or -1 on error.
pub fn openpt() -> i32 {
    unsafe {
        let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if fd < 0 {
            return -1;
        }
        fd
    }
}

/// Grants access to the slave side of a pty.
pub fn grantpt(fd: i32) -> i32 {
    unsafe { libc::grantpt(fd) }
}

/// Unlocks the slave side of a pty.
pub fn unlockpt(fd: i32) -> i32 {
    unsafe { libc::unlockpt(fd) }
}

/// Returns the name of the slave device for a pty master.
pub fn ptsname(fd: i32) -> String {
    unsafe {
        let name = libc::ptsname(fd);
        if name.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned()
    }
}

/// Gets terminal attributes.
pub fn tcgetattr(fd: i32) -> Vec<u8> {
    unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Vec::new();
        }
        let mut out = vec![0u8; std::mem::size_of::<libc::termios>()];
        std::ptr::copy_nonoverlapping(
            &termios as *const libc::termios as *const u8,
            out.as_mut_ptr(),
            out.len(),
        );
        out
    }
}

/// Sets terminal attributes.
pub fn tcsetattr(fd: i32, attrs: &[u8]) -> i32 {
    unsafe {
        if attrs.len() < std::mem::size_of::<libc::termios>() {
            return -1;
        }
        let mut termios: libc::termios = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            attrs.as_ptr(),
            &mut termios as *mut libc::termios as *mut u8,
            std::mem::size_of::<libc::termios>(),
        );
        libc::tcsetattr(fd, libc::TCSANOW, &termios)
    }
}

/// Generic ioctl wrapper.
pub fn ioctl(fd: i32, request: u64, arg: u64) -> i32 {
    unsafe { libc::ioctl(fd, request as libc::c_ulong, arg as libc::c_ulong) }
}

/// Sets the foreground process group (`tcsetpgrp` job control).
pub fn tcsetpgrp(fd: i32, pgid: u32) -> i32 {
    unsafe { libc::tcsetpgrp(fd, pgid as libc::pid_t) }
}

/// Gets the foreground process group (`tcgetpgrp` job control).
pub fn tcgetpgrp(fd: i32) -> i32 {
    unsafe {
        let pgid = libc::tcgetpgrp(fd);
        if pgid < 0 {
            -1
        } else {
            pgid
        }
    }
}

/// Gets window size (TIOCGWINSZ).
pub fn tiocgwinsz(fd: i32) -> Vec<u8> {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) != 0 {
            return Vec::new();
        }
        let mut out = vec![0u8; 8];
        out[0..2].copy_from_slice(&ws.ws_row.to_le_bytes());
        out[2..4].copy_from_slice(&ws.ws_col.to_le_bytes());
        out[4..6].copy_from_slice(&ws.ws_xpixel.to_le_bytes());
        out[6..8].copy_from_slice(&ws.ws_ypixel.to_le_bytes());
        out
    }
}

/// Sets window size (TIOCSWINSZ).
pub fn tiocswinsz(fd: i32, data: &[u8]) -> i32 {
    unsafe {
        if data.len() < 8 {
            return -1;
        }
        let mut ws: libc::winsize = std::mem::zeroed();
        ws.ws_row = u16::from_le_bytes([data[0], data[1]]);
        ws.ws_col = u16::from_le_bytes([data[2], data[3]]);
        ws.ws_xpixel = u16::from_le_bytes([data[4], data[5]]);
        ws.ws_ypixel = u16::from_le_bytes([data[6], data[7]]);
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws)
    }
}

/// Polls a host fd for readiness with a 0 timeout.
///
/// Returns the revents mask, or -1 on error. This is the FFI bridge that
/// lets the pure dispatcher check host-backed fd readiness without
/// containing any `unsafe` itself.
pub fn poll_host_fd(fd: i32, events: i16) -> i16 {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    let mut pfd = PollFd { fd, events, revents: 0 };
    let rc = unsafe {
        libc::poll(
            &mut pfd as *mut PollFd as *mut libc::pollfd,
            1,
            0,
        )
    };
    if rc < 0 {
        -1
    } else {
        pfd.revents
    }
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

/// Queues scripted input events for the guest under test.
///
/// Reads an `parasyte_core::inject` script from `path` and appends every event to
/// the guest input queue. Used for headless interaction tests
/// (`PARASYTEOS_INJECT`); with no display server these are the only events the
/// guest will ever see. Returns the event count.
pub fn inject_file(path: &Path) -> Result<usize, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let events =
        parasyte_core::inject::parse_script(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let n = events.len();
    let mut g = state().lock().unwrap_or_else(|p| p.into_inner());
    for e in events {
        g.input.push(e);
    }
    Ok(n)
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

/// Replaces the current guest with a fresh `parasyteos` that loads `path`.
///
/// `guest` is the path as the guest named it (kept as `argv[0]`); `host` is
/// where that path resolves on the host. The caller is already a forked guest,
/// so `parasyteos --exec` loads the new image in place instead of forking again. A
/// seccomp filter survives `execve`; the SIGSYS disposition does not, so the
/// re-exec'd launcher re-arms the handler (and skips re-installing the filter,
/// which is already in force).
fn exec_trampoline(guest: &[u8], host: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>]) -> ! {
    let to_c = |s: &[u8]| {
        CString::new(s.iter().copied().filter(|b| *b != 0).collect::<Vec<u8>>()).unwrap_or_default()
    };

    // `parasyteos --exec <argv0> <host-program> [args...]`: argv[0] and the file to
    // load are separate so the guest keeps seeing the name it invoked.
    let mut args_owned: Vec<CString> = Vec::new();
    args_owned.push(CString::new("parasyteos").unwrap());
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
        if let Ok(e) = CString::new(format!("PARASYTEOS_ROOT={}", root.display())) {
            env_owned.push(e);
        }
    }
    // DISPLAY too: without it the child cannot find the X socket and
    // every GUI app launched from the desktop runs headless (its window
    // never reaches the compositor).
    for key in ["DISPLAY", "PARASYTEOS_DISPLAY", "PARASYTEOS_FB_OUT"] {
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

/// Copies a guest `sockaddr` into a kernel buffer, bounding it to
/// `sockaddr_storage` so a wild length cannot exhaust host memory.
///
/// Returns the bytes plus the length to hand the host, or `None` for an
/// unreadable pointer or an oversized length.
fn read_sockaddr(ptr: u64, len: u64) -> Option<(Vec<u8>, libc::socklen_t)> {
    if ptr == 0 || len == 0 || len > 128 {
        return None;
    }
    let bytes = unsafe { regs::read_guest(ptr, len as usize) }?;
    Some((bytes, len as libc::socklen_t))
}

/// Maximum `iovec` entries marshalled for one `sendmsg`/`recvmsg`.
const MAX_IOV: usize = 16;

/// Relays `sendmsg`/`recvmsg` to the host, marshalling the `msghdr` and
/// every `iovec` through kernel copies.
///
/// The x86-64 guest layout is parsed by offset (`name` 0..8, `namelen`
/// 8..12, `iov` 16..24, `iovlen` 24..32, `control` 32..40, `controllen`
/// 40..48, `flags` 48..52), so no struct transmute can drift from the
/// ABI. Returns the byte count, or a raw errno on failure.
fn relay_msghdr(host: i32, is_send: bool, msg_ptr: u64, flags: c_int) -> Result<i64, i64> {
    let raw = unsafe { regs::read_guest(msg_ptr, 56) }.ok_or(libc::EFAULT as i64)?;
    let p = |at: usize| u64::from_ne_bytes(raw[at..at + 8].try_into().unwrap());
    let w = |at: usize| u32::from_ne_bytes(raw[at..at + 4].try_into().unwrap());
    let name_ptr = p(0);
    let name_len = w(8) as usize;
    let iov_ptr = p(16);
    let iov_len = p(24) as usize;
    let ctl_ptr = p(32);
    let ctl_len = p(40) as usize;
    if iov_len > MAX_IOV || name_len > 128 || ctl_len > 4096 {
        return Err(libc::EINVAL as i64);
    }
    let name = if name_ptr != 0 && name_len > 0 {
        unsafe { regs::read_guest(name_ptr, name_len) }.ok_or(libc::EFAULT as i64)?
    } else {
        Vec::new()
    };
    let mut iovs: Vec<(u64, usize)> = Vec::with_capacity(iov_len);
    for i in 0..iov_len {
        let ent = unsafe { regs::read_guest(iov_ptr + (i * 16) as u64, 16) }
            .ok_or(libc::EFAULT as i64)?;
        let base = u64::from_ne_bytes(ent[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(ent[8..16].try_into().unwrap()) as usize;
        iovs.push((base, len));
    }
    if is_send {
        let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(iov_len);
        for (base, len) in &iovs {
            bufs.push(unsafe { regs::read_guest(*base, *len) }.ok_or(libc::EFAULT as i64)?);
        }
        let mut host_iov: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr() as *mut c_void,
                iov_len: b.len(),
            })
            .collect();
        let mut ctl = if ctl_ptr != 0 && ctl_len > 0 {
            unsafe { regs::read_guest(ctl_ptr, ctl_len) }.ok_or(libc::EFAULT as i64)?
        } else {
            Vec::new()
        };
        let msg = libc::msghdr {
            msg_name: if name.is_empty() {
                std::ptr::null_mut()
            } else {
                name.as_ptr() as *mut c_void
            },
            msg_namelen: name.len() as libc::socklen_t,
            msg_iov: host_iov.as_mut_ptr(),
            msg_iovlen: host_iov.len(),
            msg_control: if ctl.is_empty() {
                std::ptr::null_mut()
            } else {
                ctl.as_mut_ptr() as *mut c_void
            },
            msg_controllen: ctl.len(),
            msg_flags: 0,
        };
        let n = unsafe { libc::sendmsg(host, &msg, flags) };
        if n < 0 {
            return Err(last_errno());
        }
        Ok(n as i64)
    } else {
        let mut bufs: Vec<Vec<u8>> = iovs.iter().map(|(_, len)| vec![0u8; *len]).collect();
        let mut host_iov: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr() as *mut c_void,
                iov_len: b.len(),
            })
            .collect();
        let mut ctl = vec![0u8; ctl_len];
        let mut name = name;
        let name_len_in = name.len();
        let mut msg = libc::msghdr {
            msg_name: if name.is_empty() {
                std::ptr::null_mut()
            } else {
                name.as_mut_ptr() as *mut c_void
            },
            msg_namelen: name_len_in as libc::socklen_t,
            msg_iov: host_iov.as_mut_ptr(),
            msg_iovlen: host_iov.len(),
            msg_control: if ctl.is_empty() {
                std::ptr::null_mut()
            } else {
                ctl.as_mut_ptr() as *mut c_void
            },
            msg_controllen: ctl.len(),
            msg_flags: 0,
        };
        let n = unsafe { libc::recvmsg(host, &mut msg, flags) };
        if n < 0 {
            return Err(last_errno());
        }
        for (i, (base, _)) in iovs.iter().enumerate() {
            unsafe { regs::write_guest(*base, &bufs[i]) };
        }
        if ctl_ptr != 0 && !ctl.is_empty() {
            unsafe { regs::write_guest(ctl_ptr, &ctl[..ctl.len().min(msg.msg_controllen)]) };
        }
        Ok(n as i64)
    }
}

/// Whether a guest descriptor is the input event stream.
///
/// The stream is read like a file (`read` drains queued records, `poll`
/// reports readability); only the trap layer can answer, because the pure
/// dispatcher never sees host-backed descriptors.
fn is_input_fd(fd: u32) -> bool {
    let g = state().lock().unwrap_or_else(|p| p.into_inner());
    matches!(g.fds.get(Fd(fd)), Ok(FdKind::Input))
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
                eprintln!("parasyteos: rt_sigreturn could not restore the signal frame");
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
            st.signals.queue(parasyte_core::signal::Pending::kernel(
                signum,
                parasyte_core::signal::SI_USER,
                0,
            ));
            drop(st);
            regs::set_return(uc, 0);
            true
        }
        // Session and process-group identity. Like `kill`, only the guest
        // itself is addressable: pid/pgid 0 means "mine", anything else is
        // `ESRCH`. The host call is the implementation; a terminal's
        // `setsid` + `TIOCSCTTY` + `tcsetpgrp` sequence depends on it.
        SYS_SETSID => {
            let r = unsafe { libc::setsid() };
            regs::set_return(uc, if r < 0 { -last_errno() } else { r as i64 });
            true
        }
        SYS_GETPGRP => {
            regs::set_return(uc, unsafe { libc::getpgrp() } as i64);
            true
        }
        SYS_DISPLAY_XID => {
            match crate::display::xid() {
                Some(x) => regs::set_return(uc, x as i64),
                None => regs::set_return(uc, -(libc::ENODEV as i64)),
            }
            true
        }
        SYS_WINDOW_MOVE => {
            // An embedded client drags its outer host window with this
            // call; the dispatcher below still updates the guest-side
            // model, so this arm never claims the syscall.
            if std::env::var_os("PARASYTEOS_EMBED_PARENT").is_some() {
                crate::display::move_outer(regs_in.arg(1) as i32, regs_in.arg(2) as i32);
            }
            false
        }
        SYS_WINDOW_RESIZE => {
            // Same for resizes: the outer host window follows, the guest
            // model updates in the dispatcher below.
            if std::env::var_os("PARASYTEOS_EMBED_PARENT").is_some() {
                crate::display::resize_outer(regs_in.arg(1) as u32, regs_in.arg(2) as u32);
            }
            false
        }
        SYS_SETPGID | SYS_GETPGID | SYS_GETSID => {
            let pid = regs_in.arg(0) as i32;
            let me = unsafe { libc::getpid() } as i32;
            if pid != 0 && pid != me {
                regs::set_return(uc, -(libc::ESRCH as i64));
                return true;
            }
            let r = unsafe {
                match regs_in.nr {
                    SYS_SETPGID => libc::setpgid(pid, regs_in.arg(1) as libc::pid_t) as i64,
                    SYS_GETPGID => libc::getpgid(pid) as i64,
                    _ => libc::getsid(pid) as i64,
                }
            };
            regs::set_return(uc, if r < 0 { -last_errno() } else { r });
            true
        }
        // glibc's `fork` issues a fork-like `clone` (no new stack) rather than
        // the legacy `fork` syscall, so both are serviced the same way.
        SYS_CLONE => {
            let flags = regs_in.arg(0);
            let stack = regs_in.arg(1);
            let child_tid = regs_in.arg(3);
            let set_tid = (flags & libc::CLONE_CHILD_SETTID as u64) != 0;
            let is_thread = flags & libc::CLONE_VM as u64 != 0 && stack != 0;

            if is_thread {
                // Thread-like clone: fork and run the thread function on a new stack.
                // The child gets a fresh process copy with the new stack.
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    regs::set_return(uc, -last_errno());
                } else if pid == 0 {
                    // Child: set up the new stack and jump to the thread entry.
                    // The thread function pointer is in arg 2 (parent_tid) for
                    // simplicity; in a real clone it would be in a register.
                    // For now, we just return 0 in the child.
                    if set_tid && child_tid != 0 {
                        let tid = unsafe { libc::getpid() } as i32;
                        unsafe { regs::write_guest(child_tid, &tid.to_ne_bytes()) };
                    }
                    regs::set_return(uc, 0);
                } else {
                    regs::set_return(uc, pid as i64);
                }
            } else {
                // Fork-like clone (no new stack)
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
                // The input stream is an `FdKind::Input`, not a host fd:
                // drain queued event records into the guest buffer, the
                // same bytes `SYS_INPUT_READ` would hand out. Without this
                // every guest `read()` on the input fd fails with EBADF.
                if !is_input_fd(fd) {
                    return false;
                }
                let buf = regs_in.arg(1);
                let len = regs_in.arg(2) as usize;
                if len == 0 {
                    regs::set_return(uc, 0);
                    return true;
                }
                let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
                let mut tmp = vec![0u8; len.min(1 << 20)];
                let n = st.input.read_into(&mut tmp);
                drop(st);
                if n > 0 {
                    unsafe { regs::write_guest(buf, &tmp[..n]) };
                }
                regs::set_return(uc, n as i64);
                return true;
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
        SYS_FSTAT => {
            // Host-backed descriptors (pipes, sockets, bridged files and
            // directories) stat through the host. The bytes follow the same
            // 144-byte layout `parasyte_core::vfs::Stat::to_bytes` produces, so a
            // guest cannot tell which side of the trap its file lives on.
            // (That layout omits `st_rdev`; both writers agree, which is
            // what matters here.)
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let out = regs_in.arg(1);
            if out == 0 {
                regs::set_return(uc, -(libc::EFAULT as i64));
                return true;
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(host, &mut st) } != 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            let mut buf = [0u8; 144];
            let mut put = |at: usize, bytes: &[u8]| {
                buf[at..at + bytes.len()].copy_from_slice(bytes);
            };
            put(0, &(st.st_dev as u64).to_le_bytes());
            put(8, &(st.st_ino as u64).to_le_bytes());
            put(16, &(st.st_nlink as u64).to_le_bytes());
            put(24, &(st.st_mode as u32).to_le_bytes());
            put(28, &(st.st_uid as u32).to_le_bytes());
            put(32, &(st.st_gid as u32).to_le_bytes());
            put(36, &0u32.to_le_bytes());
            put(40, &(st.st_size as u64).to_le_bytes());
            put(48, &(st.st_blksize as u64).to_le_bytes());
            put(56, &(st.st_blocks as u64).to_le_bytes());
            put(64, &(st.st_atime as i64).to_le_bytes());
            put(72, &(st.st_atime_nsec as i64).to_le_bytes());
            put(80, &(st.st_mtime as i64).to_le_bytes());
            put(88, &(st.st_mtime_nsec as i64).to_le_bytes());
            put(96, &(st.st_ctime as i64).to_le_bytes());
            put(104, &(st.st_ctime_nsec as i64).to_le_bytes());
            unsafe { regs::write_guest(out, &buf) };
            regs::set_return(uc, 0);
            true
        }
        SYS_GETDENTS => {
            // Host-backed directory fds (the shared `/winserv` namespace)
            // list through the host: `linux_dirent64` is the same layout on
            // both sides, so the bytes copy straight across. VFS files fall
            // through to the dispatcher.
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let buf = regs_in.arg(1);
            let len = regs_in.arg(2) as usize;
            if len == 0 {
                regs::set_return(uc, -(libc::EINVAL as i64));
                return true;
            }
            let mut tmp = vec![0u8; len.min(1 << 20)];
            let n = unsafe { libc::syscall(libc::SYS_getdents64, host, tmp.as_mut_ptr(), tmp.len()) };
            if n < 0 {
                regs::set_return(uc, -last_errno());
            } else {
                let n = n as usize;
                unsafe { regs::write_guest(buf, &tmp[..n]) };
                regs::set_return(uc, n as i64);
            }
            true
        }
        SYS_UNLINK | SYS_UNLINKAT => {
            // Removals inside the shared namespace hit the host; everything
            // else is VFS business for the dispatcher.
            let path_ptr = if regs_in.nr == SYS_UNLINK {
                regs_in.arg(0)
            } else {
                regs_in.arg(1)
            };
            let path = unsafe { regs::read_cstr_guest(path_ptr, 4096) };
            let bridged = path
                .as_deref()
                .and_then(winserv_host_path)
                .filter(|p| {
                    // Only files go through here; the namespace directories
                    // themselves are never unlinked by guests.
                    !p.ends_with("winserv") && !p.ends_with("clients")
                });
            match bridged {
                None => false,
                Some(host) => {
                    use std::os::unix::ffi::OsStrExt;
                    let cpath = match std::ffi::CString::new(host.as_os_str().as_bytes()) {
                        Ok(c) => c,
                        Err(_) => {
                            regs::set_return(uc, -(libc::EINVAL as i64));
                            return true;
                        }
                    };
                    let r = unsafe { libc::unlink(cpath.as_ptr()) };
                    regs::set_return(uc, if r < 0 { -last_errno() } else { 0 });
                    true
                }
            }
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
        SYS_OPEN | SYS_OPENAT => {
            // Bridged device opens: `/dev/pts/N` and `/dev/ptmx` live on the
            // host, not in the guest VFS. `ptsname()` hands the guest a host
            // path, so without this bridge every pty slave `open()` would
            // fail with ENOENT and no terminal could ever spawn its shell.
            // Anything else falls through to the VFS dispatcher.
            let path_ptr = if regs_in.nr == SYS_OPEN {
                regs_in.arg(0)
            } else {
                regs_in.arg(1)
            };
            let flags = if regs_in.nr == SYS_OPEN {
                regs_in.arg(1) as i32
            } else {
                regs_in.arg(2) as i32
            };
            let mode = if regs_in.nr == SYS_OPEN {
                regs_in.arg(2) as u32
            } else {
                regs_in.arg(3) as u32
            };
            let path = unsafe { regs::read_cstr_guest(path_ptr, 4096) };
            match path
                .as_deref()
                .and_then(|p| host_bridge_open(p, flags, mode))
            {
                None => false,
                Some(Ok(host_fd)) => {
                    let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
                    let n = st.fds.alloc_host(host_fd);
                    regs::set_return(uc, n.0 as i64);
                    true
                }
                Some(Err(errno)) => {
                    regs::set_return(uc, -(errno as i64));
                    true
                }
            }
        }
        // Sockets are host kernel objects, like pipes: the guest's fd names
        // a host fd (`FdKind::Host`), and every address/option buffer is
        // marshalled through kernel-side copies so a bad guest pointer is
        // an errno rather than a host fault. `read`/`write`/`close`/`poll`
        // already serve host fds, so a connected socket is usable with no
        // further work. The pure dispatcher answers these with `Nosys`;
        // only this trap layer can own host descriptors.
        SYS_SOCKET => {
            let r = unsafe {
                libc::socket(
                    regs_in.arg(0) as c_int,
                    regs_in.arg(1) as c_int,
                    regs_in.arg(2) as c_int,
                )
            };
            if r < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
            let n = st.fds.alloc_host(r);
            regs::set_return(uc, n.0 as i64);
            true
        }
        SYS_CONNECT | SYS_BIND | SYS_LISTEN | SYS_SHUTDOWN => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let r = unsafe {
                match regs_in.nr {
                    SYS_CONNECT => {
                        let (addr, len) = match read_sockaddr(regs_in.arg(1), regs_in.arg(2)) {
                            Some(a) => a,
                            None => {
                                regs::set_return(uc, -(libc::EINVAL as i64));
                                return true;
                            }
                        };
                        libc::connect(
                            host,
                            addr.as_ptr() as *const libc::sockaddr,
                            len,
                        )
                    }
                    SYS_BIND => {
                        let (addr, len) = match read_sockaddr(regs_in.arg(1), regs_in.arg(2)) {
                            Some(a) => a,
                            None => {
                                regs::set_return(uc, -(libc::EINVAL as i64));
                                return true;
                            }
                        };
                        libc::bind(host, addr.as_ptr() as *const libc::sockaddr, len)
                    }
                    SYS_LISTEN => libc::listen(host, regs_in.arg(1) as c_int),
                    _ => libc::shutdown(host, regs_in.arg(1) as c_int),
                }
            };
            regs::set_return(uc, if r < 0 { -last_errno() } else { r as i64 });
            true
        }
        SYS_ACCEPT => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let addr_ptr = regs_in.arg(1);
            let len_ptr = regs_in.arg(2);
            let mut len: libc::socklen_t = 128;
            if addr_ptr != 0 && len_ptr != 0 {
                match unsafe { regs::read_guest(len_ptr, 4) } {
                    Some(b) => {
                        len = u32::from_ne_bytes(b.try_into().unwrap()).min(128);
                    }
                    None => {
                        regs::set_return(uc, -(libc::EFAULT as i64));
                        return true;
                    }
                }
            }
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let r = unsafe {
                libc::accept(
                    host,
                    &mut addr as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            if r < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            if addr_ptr != 0 && len_ptr != 0 {
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(&addr as *const _ as *const u8, len as usize)
                };
                unsafe { regs::write_guest(addr_ptr, bytes) };
                unsafe { regs::write_guest(len_ptr, &len.to_ne_bytes()) };
            }
            let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
            let n = st.fds.alloc_host(r);
            regs::set_return(uc, n.0 as i64);
            true
        }
        SYS_GETSOCKNAME | SYS_GETPEERNAME => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let addr_ptr = regs_in.arg(1);
            let len_ptr = regs_in.arg(2);
            if addr_ptr == 0 || len_ptr == 0 {
                regs::set_return(uc, -(libc::EFAULT as i64));
                return true;
            }
            let mut len: libc::socklen_t = match unsafe { regs::read_guest(len_ptr, 4) } {
                Some(b) => u32::from_ne_bytes(b.try_into().unwrap()).min(128),
                None => {
                    regs::set_return(uc, -(libc::EFAULT as i64));
                    return true;
                }
            };
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let r = unsafe {
                if regs_in.nr == SYS_GETSOCKNAME {
                    libc::getsockname(host, &mut addr as *mut _ as *mut libc::sockaddr, &mut len)
                } else {
                    libc::getpeername(host, &mut addr as *mut _ as *mut libc::sockaddr, &mut len)
                }
            };
            if r < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(&addr as *const _ as *const u8, len as usize)
            };
            unsafe { regs::write_guest(addr_ptr, bytes) };
            unsafe { regs::write_guest(len_ptr, &len.to_ne_bytes()) };
            regs::set_return(uc, 0);
            true
        }
        SYS_SETSOCKOPT => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let optval = match unsafe { regs::read_guest(regs_in.arg(3), regs_in.arg(4) as usize) } {
                Some(v) => v,
                None => {
                    regs::set_return(uc, -(libc::EFAULT as i64));
                    return true;
                }
            };
            let r = unsafe {
                libc::setsockopt(
                    host,
                    regs_in.arg(1) as c_int,
                    regs_in.arg(2) as c_int,
                    optval.as_ptr() as *const c_void,
                    optval.len() as libc::socklen_t,
                )
            };
            regs::set_return(uc, if r < 0 { -last_errno() } else { 0 });
            true
        }
        SYS_GETSOCKOPT => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let opt_ptr = regs_in.arg(3);
            let len_ptr = regs_in.arg(4);
            if opt_ptr == 0 || len_ptr == 0 {
                regs::set_return(uc, -(libc::EFAULT as i64));
                return true;
            }
            let mut len: libc::socklen_t = match unsafe { regs::read_guest(len_ptr, 4) } {
                Some(b) => u32::from_ne_bytes(b.try_into().unwrap()).min(128),
                None => {
                    regs::set_return(uc, -(libc::EFAULT as i64));
                    return true;
                }
            };
            let mut buf = vec![0u8; len as usize];
            let r = unsafe {
                libc::getsockopt(
                    host,
                    regs_in.arg(1) as c_int,
                    regs_in.arg(2) as c_int,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut len,
                )
            };
            if r < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            buf.truncate(len as usize);
            unsafe { regs::write_guest(opt_ptr, &buf) };
            unsafe { regs::write_guest(len_ptr, &len.to_ne_bytes()) };
            regs::set_return(uc, 0);
            true
        }
        SYS_SENDTO => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let data = match unsafe { regs::read_guest(regs_in.arg(1), regs_in.arg(2) as usize) } {
                Some(d) => d,
                None => {
                    regs::set_return(uc, -(libc::EFAULT as i64));
                    return true;
                }
            };
            let r = unsafe {
                if regs_in.arg(4) == 0 {
                    libc::send(
                        host,
                        data.as_ptr() as *const c_void,
                        data.len(),
                        regs_in.arg(3) as c_int,
                    )
                } else {
                    let (addr, len) = match read_sockaddr(regs_in.arg(4), regs_in.arg(5)) {
                        Some(a) => a,
                        None => {
                            regs::set_return(uc, -(libc::EINVAL as i64));
                            return true;
                        }
                    };
                    libc::sendto(
                        host,
                        data.as_ptr() as *const c_void,
                        data.len(),
                        regs_in.arg(3) as c_int,
                        addr.as_ptr() as *const libc::sockaddr,
                        len,
                    )
                }
            };
            regs::set_return(uc, if r < 0 { -last_errno() } else { r as i64 });
            true
        }
        SYS_RECVFROM => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let len = regs_in.arg(2) as usize;
            let addr_ptr = regs_in.arg(4);
            let addr_len_ptr = regs_in.arg(5);
            let mut tmp = vec![0u8; len.min(1 << 20)];
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addrlen: libc::socklen_t = 128;
            let n = unsafe {
                libc::recvfrom(
                    host,
                    tmp.as_mut_ptr() as *mut c_void,
                    tmp.len(),
                    regs_in.arg(3) as c_int,
                    if addr_ptr != 0 {
                        &mut addr as *mut _ as *mut libc::sockaddr
                    } else {
                        std::ptr::null_mut()
                    },
                    if addr_ptr != 0 && addr_len_ptr != 0 {
                        &mut addrlen
                    } else {
                        std::ptr::null_mut()
                    },
                )
            };
            if n < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            unsafe { regs::write_guest(regs_in.arg(1), &tmp[..n as usize]) };
            if addr_ptr != 0 && addr_len_ptr != 0 {
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        &addr as *const _ as *const u8,
                        (addrlen as usize).min(128),
                    )
                };
                unsafe { regs::write_guest(addr_ptr, bytes) };
                unsafe { regs::write_guest(addr_len_ptr, &addrlen.to_ne_bytes()) };
            }
            regs::set_return(uc, n as i64);
            true
        }
        SYS_SENDMSG | SYS_RECVMSG => {
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            match relay_msghdr(host, regs_in.nr == SYS_SENDMSG, regs_in.arg(1), regs_in.arg(2) as c_int) {
                Ok(n) => regs::set_return(uc, n),
                Err(e) => regs::set_return(uc, -e),
            }
            true
        }
        SYS_SOCKETPAIR => {
            let mut pair = [0i32; 2];
            let r = unsafe {
                libc::socketpair(
                    regs_in.arg(0) as c_int,
                    regs_in.arg(1) as c_int,
                    regs_in.arg(2) as c_int,
                    pair.as_mut_ptr(),
                )
            };
            if r < 0 {
                regs::set_return(uc, -last_errno());
                return true;
            }
            let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
            let a = st.fds.alloc_host(pair[0]);
            let b = st.fds.alloc_host(pair[1]);
            drop(st);
            // The guest's `int fds[2]` receives guest descriptor numbers.
            let mut out = Vec::new();
            out.extend_from_slice(&a.0.to_ne_bytes());
            out.extend_from_slice(&b.0.to_ne_bytes());
            if unsafe { !regs::write_guest(regs_in.arg(3), &out) } {
                regs::set_return(uc, -(libc::EFAULT as i64));
                return true;
            }
            regs::set_return(uc, 0);
            true
        }
        SYS_FCNTL => {
            // Only host-backed descriptors (pipes, sockets, stdio) reach the
            // host; VFS files fall through to the dispatcher. The address
            // space is shared, so pointer arguments are passed straight
            // through.
            let fd = regs_in.arg(0) as u32;
            let Some(host) = host_fd_of(fd) else {
                return false;
            };
            let cmd = regs_in.arg(1) as c_int;
            let r = unsafe { libc::fcntl(host, cmd, regs_in.arg(2)) };
            regs::set_return(uc, if r < 0 { -last_errno() } else { r as i64 });
            true
        }
        SYS_EXECVE => {
            let path = unsafe { regs::read_cstr_guest(regs_in.arg(0), 4096) };
            let argv = unsafe { read_guest_argv(regs_in.arg(1)) };
            let envp = unsafe { read_guest_argv(regs_in.arg(2)) };
            match (path, argv, envp) {
                (Some(path), Ok(argv), Ok(envp)) => {
                    // Resolve through the rootfs, then report a missing target
                    // here: it is loaded by a fresh `parasyteos`, so otherwise the
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

    // Pump host input events before servicing the syscall, so a guest that
    // polls the input fd (rather than parking in input_wait) sees them.
    pump_input();

    let mut mem = HostMemory;

    let (result, out, present, exit, guest_fs, sleep, parked) = {
        let mut st = match state().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // The clock is refreshed before the syscall runs, not after, so a guest
        // that reads the time and then sleeps sees the deadline it just read.
        if !st.clock_started {
            st.clock = parasyte_core::clock::Clock::new(
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
            epolls,
            eventfds,
            futexes,
            poll_host: _,
            pty_open: _,
            pty_grant: _,
            pty_unlock: _,
            pty_name: _,
            pty_getattr: _,
            pty_setattr: _,
            pty_ioctl: _,
            pty_winsz_get: _,
            pty_winsz_set: _,
            pty_setpgrp: _,
            pty_getpgrp: _,
            memfd_create: _,
            shm_open: _,
            shm_unlink: _,
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
            epolls: std::mem::take(epolls),
            eventfds: std::mem::take(eventfds),
            futexes: std::mem::take(futexes),
            poll_host: Some(poll_host_fd),
            pty_open: Some(openpt),
            pty_grant: Some(grantpt),
            pty_unlock: Some(unlockpt),
            pty_name: Some(ptsname),
            pty_getattr: Some(tcgetattr),
            pty_setattr: Some(tcsetattr),
            pty_ioctl: Some(ioctl),
            pty_winsz_get: Some(tiocgwinsz),
            pty_winsz_set: Some(tiocswinsz),
            pty_setpgrp: Some(tcsetpgrp),
            pty_getpgrp: Some(tcgetpgrp),
            memfd_create: Some(memfd_create),
            shm_open: Some(shm_open),
            shm_unlink: Some(shm_unlink),
        };
        // Frame pacing is owned by the dispatcher: `DISPLAY_PRESENT`
        // increments `frame_counter` when it composites. Counting here as
        // well would double-count every present.
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
        *epolls = std::mem::take(&mut gs.epolls);
        *eventfds = std::mem::take(&mut gs.eventfds);
        *futexes = std::mem::take(&mut gs.futexes);
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
                parasyte_core::addr::align_up(*mapped_brk),
                parasyte_core::addr::align_up(gs.brk),
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

    // `poll` with a nonzero timeout waits for readiness; the dispatcher only
    // takes an instant snapshot, so a zero from it means "nothing yet" rather
    // than "nothing within the timeout". Wait on the host, then rewind so the
    // guest re-runs the call against fresh state. A timed-out wait keeps the
    // zero (waiting twice would double every timeout).
    //
    // Every rewind records the syscall number: the result is written to
    // `rax` below, and a rewound call re-executes whatever number `rax`
    // holds — without this the guest would re-run syscall 0 (`read`).
    let mut rewound_nr: Option<i64> = None;
    if regs_in.nr == SYS_POLL && matches!(result, Ok(0)) {
        let timeout_ms = regs_in.arg(2) as i32;
        if timeout_ms != 0
            && poll_wait_for_ready(regs_in.arg(0), regs_in.arg(1) as usize, timeout_ms)
        {
            rewind(&mut *uc);
            rewound_nr = Some(regs_in.nr);
        }
    }

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
            rewound_nr = Some(regs_in.nr);
        }
        clear_sleep();
    }

    // Forward anything the guest wrote to fd 1. The handler runs from kernel
    // code, so this `write` is a high-address syscall the filter allows.
    if !out.is_empty() {
        unsafe { libc::write(1, out.as_ptr() as *const c_void, out.len()) };
    }

    // A composited frame is written out only when `PARASYTEOS_FB_OUT` names a file,
    // which is what makes the display observable without a real window.
    if !present.is_empty() {
        if let Some(path) =
            FB_OUT.get_or_init(|| std::env::var_os("PARASYTEOS_FB_OUT").map(PathBuf::from))
        {
            if let Err(e) = std::fs::write(path, &present) {
                eprintln!("parasyteos: framebuffer -> {}: {e}", path.display());
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
                    "parasyteos: sync {} files, {} dirs, {} bytes",
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
    // A rewound call re-executes the instruction at the stepped-back `rip`,
    // and the kernel takes the number to run from `rax` — which now holds
    // the abandoned attempt's result. Restore the number last, so the guest
    // re-runs its own call. (Without this, every waited-on poll resumed as
    // syscall 0 (`read`) and died with a mystifying EBADF.)
    if let Some(nr) = rewound_nr {
        regs::set_nr(&mut *uc, nr);
    }

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
pub fn provide_file(path: &str, data: &[u8]) -> Result<(), parasyte_core::vfs::Errno> {
    with_vfs(|vfs| vfs.create(path, data)).map(|_ino| ())
}

/// Registers a directory in the guest's filesystem.
pub fn provide_dir(path: &str) -> Result<(), parasyte_core::vfs::Errno> {
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
    parasyte_core::persist::read_all(root, &mut g.vfs)
}

/// Sets the guest's initial program break, normally the page-aligned end of the
/// loaded image. `brk(0)` then reports this address and growth is measured from
/// here, instead of from zero.
pub fn set_initial_brk(addr: u64) {
    let mut st = state().lock().unwrap_or_else(|p| p.into_inner());
    st.brk = addr;
    st.mapped_brk = addr;
}
