//! Syscall ABI: decoding guest registers, dispatch, and errno mapping.
//!
//! The dispatcher is a pure function from `(nr, args, &mut Guest)` to a return
//! value. Nothing here touches the host, so every syscall's logic is testable
//! by constructing a guest state and calling it directly. The `osplat` layer
//! only has to move registers in and out.

use crate::addr::{PAGE_SIZE, Perms};
use crate::vfs::{Errno, Fd, Vfs};
use std::collections::BTreeMap;

/// x86-64 Linux syscall numbers used by this kernel.
pub const SYS_READ: i64 = 0;
pub const SYS_WRITE: i64 = 1;
pub const SYS_OPEN: i64 = 2;
pub const SYS_CLOSE: i64 = 3;
pub const SYS_MMAP: i64 = 9;
pub const SYS_MPROTECT: i64 = 10;
pub const SYS_MUNMAP: i64 = 11;
pub const SYS_BRK: i64 = 12;
pub const SYS_IOCTL: i64 = 16;
pub const SYS_WRITEV: i64 = 20;
pub const SYS_PIPE: i64 = 22;
pub const SYS_DUP: i64 = 32;
pub const SYS_DUP2: i64 = 33;
pub const SYS_DUP3: i64 = 292;
pub const SYS_PIPE2: i64 = 293;
pub const SYS_READLINK: i64 = 89;
pub const SYS_EXIT: i64 = 60;
pub const SYS_EXIT_GROUP: i64 = 231;
pub const SYS_CLONE: i64 = 56;
pub const SYS_FORK: i64 = 57;
pub const SYS_EXECVE: i64 = 59;
pub const SYS_GETPID: i64 = 39;
pub const SYS_WAIT4: i64 = 61;
pub const SYS_OPENAT: i64 = 257;
pub const SYS_READLINKAT: i64 = 267;
pub const SYS_ARCH_PRCTL: i64 = 158;
pub const SYS_SET_TID_ADDRESS: i64 = 218;
pub const SYS_CLOCK_GETTIME: i64 = 228;
pub const SYS_SET_ROBUST_LIST: i64 = 273;
pub const SYS_GETRANDOM: i64 = 318;
pub const SYS_PRLIMIT64: i64 = 302;

/// Custom display/window syscalls.
///
/// They sit far above every Linux syscall number so they can never be confused
/// with a real one; only our own guests issue them, and every low-address
/// syscall is mediated anyway.
pub const SYS_DISPLAY_INFO: i64 = 0x1000;
pub const SYS_WINDOW_CREATE: i64 = 0x1001;
pub const SYS_WINDOW_MAP: i64 = 0x1002;
pub const SYS_WINDOW_PRESENT: i64 = 0x1003;
pub const SYS_WINDOW_MOVE: i64 = 0x1004;
pub const SYS_WINDOW_DESTROY: i64 = 0x1005;
pub const SYS_DISPLAY_PRESENT: i64 = 0x1006;
pub const SYS_WINDOW_RAISE: i64 = 0x1007;
pub const SYS_WINDOW_DRAW_TEXT: i64 = 0x1008;

/// `arch_prctl` sub-functions for the thread-pointer (`%fs`) base.
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

/// Argument registers, in order: rdi, rsi, rdx, r10, r8, r9.
pub const MAX_ARGS: usize = 6;

/// A guest's register state at syscall entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Registers {
    pub nr: i64,
    pub args: [u64; MAX_ARGS],
    /// Instruction pointer the guest will resume at.
    pub rip: u64,
    /// Stack pointer.
    pub rsp: u64,
}

impl Registers {
    pub fn new(nr: i64) -> Self {
        Registers { nr, args: [0; MAX_ARGS], rip: 0, rsp: 0 }
    }

    pub fn with_args(mut self, args: [u64; MAX_ARGS]) -> Self {
        self.args = args;
        self
    }

    pub fn arg(&self, i: usize) -> u64 {
        self.args.get(i).copied().unwrap_or(0)
    }

    /// Converts argument `i` to a pointer, rejecting values that could not be
    /// a guest address. Guest pointers must be canonical.
    pub fn ptr(&self, i: usize) -> Result<u64, Errno> {
        let v = self.arg(i);
        if !crate::addr::is_canonical(v) {
            return Err(Errno::Inval);
        }
        Ok(v)
    }

    /// Converts argument `i` to a length, rejecting values that would overflow
    /// when added to a pointer. `isize::MAX` is the practical ceiling.
    pub fn len(&self, i: usize) -> Result<usize, Errno> {
        let v = self.arg(i);
        if v > isize::MAX as u64 {
            return Err(Errno::Inval);
        }
        Ok(v as usize)
    }
}

/// Outcome of a syscall. `Ok(v)` is a non-negative return; `Err(e)` becomes
/// `-errno`, which is how Linux reports failure.
pub type SysResult = Result<u64, Errno>;

/// Mutable state a syscall operates on.
pub struct GuestState<'a> {
    pub vfs: &'a mut Vfs,
    /// Guest's program break, used by `brk`.
    pub brk: u64,
    /// Set when the guest asks to terminate.
    pub exited: Option<i32>,
    /// Fake pid, incremented per `getpid`.
    pub pid: i64,
    /// Memory map requests, for tests and for the real loader.
    pub pending_mmap: Vec<MmapRequest>,
    /// Bytes the guest sent to stdout. The host drains this to the terminal.
    pub stdout: Vec<u8>,
    /// Per-inode file offset, so sequential reads advance like a real fd.
    pub file_pos: BTreeMap<u64, u64>,
    /// Thread-pointer (`%fs`) base the guest asked for via `arch_prctl`.
    pub fs_base: u64,
    /// Whether the guest has set `%fs` itself. Static glibc does this during
    /// startup; until then the host's own thread pointer must be left in place.
    pub fs_set: bool,
    /// The guest's display and window model.
    pub display: crate::gfx::Display,
    /// A PPM of the last `display_present`, for the platform layer to write out.
    pub frame: Vec<u8>,
}

/// A memory mapping the guest asked for but that the host must fulfil.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MmapRequest {
    pub addr: u64,
    pub len: u64,
    pub prot: u32,
    pub flags: u32,
}

/// Guest memory accessor, kept as a trait so tests can supply a simulated
/// space and `osplat` can supply the real one.
pub trait GuestMemory {
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, Errno>;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno>;
    fn map(&mut self, addr: u64, len: u64, prot: u32, flags: u32) -> Result<u64, Errno>;
    fn unmap(&mut self, addr: u64, len: u64) -> Result<(), Errno>;
    /// Changes the protection on an already-mapped range.
    fn protect(&mut self, addr: u64, len: u64, prot: u32) -> Result<(), Errno>;
    /// Copies a NUL-terminated string out of guest memory.
    fn read_cstr(&self, addr: u64) -> Result<Vec<u8>, Errno>;
}

/// PROT_* flags as Linux defines them.
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

/// The set of `PROT_*` bits this kernel understands.
pub const PROT_ALL: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// Decodes a `PROT_*` mask into [`Perms`], rejecting unknown bits.
///
/// Linux fails `mprotect`/`mmap` with `EINVAL` rather than silently ignoring
/// protection bits it does not recognise, and quietly downgrading `PROT_WRITE`
/// would be a security hole, so unknown bits are an error here.
pub fn perms_from_prot(prot: u32) -> Option<Perms> {
    if prot & !PROT_ALL != 0 {
        return None;
    }
    Some(Perms::from_bits(prot as u8))
}

/// MAP_* flags needed by the loader.
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;

/// What a guest descriptor refers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FdKind {
    /// A file in the guest VFS, identified by inode.
    File(crate::vfs::Ino),
    /// A descriptor owned by the host: a standard stream or a pipe. The number
    /// is the host fd, and reads/writes for it are realised by the platform
    /// layer rather than the dispatcher.
    Host(i32),
}

/// Owned open file descriptors.
#[derive(Default)]
pub struct FdTable {
    next: u32,
    open: BTreeMap<u32, FdKind>,
}

impl FdTable {
    pub fn new() -> Self {
        // The standard streams are the host's 0, 1 and 2.
        let mut open = BTreeMap::new();
        open.insert(0, FdKind::Host(0));
        open.insert(1, FdKind::Host(1));
        open.insert(2, FdKind::Host(2));
        FdTable { next: 3, open }
    }

    pub fn alloc(&mut self, ino: crate::vfs::Ino) -> Fd {
        self.alloc_kind(FdKind::File(ino))
    }

    /// Allocates the next free descriptor for an already-open host fd.
    pub fn alloc_host(&mut self, host: i32) -> Fd {
        self.alloc_kind(FdKind::Host(host))
    }

    pub fn alloc_kind(&mut self, kind: FdKind) -> Fd {
        let fd = self.next;
        self.next += 1;
        self.open.insert(fd, kind);
        Fd(fd)
    }

    pub fn get(&self, fd: Fd) -> Result<FdKind, Errno> {
        self.open.get(&fd.0).copied().ok_or(Errno::Badf)
    }

    /// Resolves a descriptor to a VFS inode, rejecting host-backed ones. The
    /// platform layer services those before the dispatcher sees them.
    pub fn get_file(&self, fd: Fd) -> Result<crate::vfs::Ino, Errno> {
        match self.open.get(&fd.0) {
            Some(FdKind::File(ino)) => Ok(*ino),
            _ => Err(Errno::Badf),
        }
    }

    pub fn close(&mut self, fd: Fd) -> Result<FdKind, Errno> {
        self.open.remove(&fd.0).ok_or(Errno::Badf)
    }

    /// Replaces the descriptor `fd`, as `dup2` does.
    pub fn set(&mut self, fd: Fd, kind: FdKind) {
        self.open.insert(fd.0, kind);
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

/// Executes one syscall against guest state.
pub fn dispatch<M: GuestMemory>(
    regs: &Registers,
    mem: &mut M,
    state: &mut GuestState<'_>,
    fds: &mut FdTable,
) -> SysResult {
    match regs.nr {
        SYS_EXIT | SYS_EXIT_GROUP => {
            state.exited = Some(regs.arg(0) as u8 as i32);
            Ok(0)
        }
        SYS_GETPID => {
            state.pid += 1;
            Ok(state.pid as u64)
        }
        SYS_WRITE => {
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            if fd == Fd(1) || fd == Fd(2) {
                // Standard output: handed to the host, which is where the
                // bytes actually get printed.
                let data = mem.read(buf, len)?;
                state.stdout.extend_from_slice(&data);
                return Ok(len as u64);
            }
            let ino = fds.get_file(fd)?;
            let data = mem.read(buf, len)?;
            state.vfs.write(ino, state.file_pos.get(&(fd.0 as u64)).copied().unwrap_or(0), &data)?;
            let pos = state.file_pos.entry(fd.0 as u64).or_insert(0);
            *pos += data.len() as u64;
            Ok(data.len() as u64)
        }
        SYS_READ => {
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            let ino = fds.get_file(fd)?;
            let pos = state.file_pos.get(&(fd.0 as u64)).copied().unwrap_or(0);
            let data = state.vfs.read(ino, pos, len)?;
            if !data.is_empty() {
                mem.write(buf, &data)?;
                let p = state.file_pos.entry(fd.0 as u64).or_insert(0);
                *p += data.len() as u64;
            }
            Ok(data.len() as u64)
        }
        SYS_OPEN => {
            let path_ptr = regs.ptr(0)?;
            let flags = regs.arg(1) as u32;
            let raw = mem.read_cstr(path_ptr)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let ino = state.vfs.open(&path, flags)?;
            Ok(fds.alloc(ino).0 as u64)
        }
        SYS_OPENAT => {
            // `dirfd` (arg 0) is accepted but not used: relative paths and
            // `AT_FDCWD` are not modelled yet, so every path resolves from the
            // root. Freestanding guests pass absolute paths, which is the case
            // this kernel targets.
            let path_ptr = regs.ptr(1)?;
            let flags = regs.arg(2) as u32;
            let raw = mem.read_cstr(path_ptr)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let ino = state.vfs.open(&path, flags)?;
            Ok(fds.alloc(ino).0 as u64)
        }
        SYS_CLOSE => {
            let fd = Fd(regs.arg(0) as u32);
            fds.close(fd)?;
            Ok(0)
        }
        SYS_MMAP => {
            let addr = regs.arg(0);
            let len = regs.len(1)? as u64;
            let prot = regs.arg(2) as u32;
            let flags = regs.arg(3) as u32;
            if len == 0 {
                return Err(Errno::Inval);
            }
            let got = mem.map(addr, len, prot, flags)?;
            state.pending_mmap.push(MmapRequest { addr: got, len, prot, flags });
            Ok(got)
        }
        SYS_MUNMAP => {
            let addr = regs.arg(0);
            let len = regs.len(1)? as u64;
            if len == 0 {
                return Err(Errno::Inval);
            }
            mem.unmap(addr, len)?;
            Ok(0)
        }
        SYS_BRK => {
            let requested = regs.arg(0);
            if requested >= state.brk {
                state.brk = requested;
                // Linux returns the new break regardless of whether the
                // mapping could be satisfied.
                return Ok(requested);
            }
            Ok(state.brk)
        }
        SYS_IOCTL => {
            // Only `isatty` matters for the shell's prompt handling.
            let request = regs.arg(1);
            if request == 0x5401 {
                return Err(Errno::Inval);
            }
            Ok(0)
        }
        SYS_ARCH_PRCTL => {
            // The guest runs on the host thread, so the kernel cannot let a
            // guest clobber the real `%fs` during a trap. The requested base is
            // recorded here and the platform layer applies it only when control
            // returns to guest code.
            match regs.arg(0) {
                ARCH_SET_FS => {
                    state.fs_base = regs.arg(1);
                    state.fs_set = true;
                    Ok(0)
                }
                ARCH_GET_FS => {
                    let p = regs.ptr(1)?;
                    mem.write(p, &state.fs_base.to_ne_bytes())?;
                    Ok(0)
                }
                _ => Err(Errno::Inval),
            }
        }
        SYS_MPROTECT => {
            // Real `mprotect`. The host layer applies the change to the actual
            // pages, so the guest's own protections are enforced by the MMU
            // rather than being recorded and ignored.
            let addr = regs.arg(0);
            let len = regs.arg(1);
            let prot = regs.arg(2) as u32;
            // Linux requires a page-aligned start, a non-zero length, and
            // recognised protection bits.
            if len == 0 || addr % PAGE_SIZE as u64 != 0 {
                return Err(Errno::Inval);
            }
            if perms_from_prot(prot).is_none() {
                return Err(Errno::Inval);
            }
            mem.protect(addr, len, prot)?;
            Ok(0)
        }
        SYS_WRITEV => {
            let fd = Fd(regs.arg(0) as u32);
            let iov = regs.ptr(1)?;
            let count = regs.len(2)?;
            let mut written = 0u64;
            for i in 0..count {
                let base = iov + (i * 16) as u64;
                let mut ent = [0u8; 16];
                ent.copy_from_slice(&mem.read(base, 16)?);
                let p = u64::from_ne_bytes(ent[0..8].try_into().unwrap());
                let n = u64::from_ne_bytes(ent[8..16].try_into().unwrap()) as usize;
                if n == 0 {
                    continue;
                }
                let data = mem.read(p, n)?;
                if fd == Fd(1) || fd == Fd(2) {
                    state.stdout.extend_from_slice(&data);
                } else {
                    let ino = fds.get_file(fd)?;
                    let pos = state.file_pos.get(&(fd.0 as u64)).copied().unwrap_or(0);
                    state.vfs.write(ino, pos, &data)?;
                    let slot = state.file_pos.entry(fd.0 as u64).or_insert(0);
                    *slot += data.len() as u64;
                }
                written += data.len() as u64;
            }
            Ok(written)
        }
        SYS_SET_TID_ADDRESS => {
            // The tid is only used as an identity; a constant is enough for a
            // single-threaded guest.
            Ok(1)
        }
        SYS_SET_ROBUST_LIST => Ok(0),
        SYS_CLOCK_GETTIME => {
            // No wall clock is modelled; report the epoch. Static glibc probes
            // this during startup and must not see an error.
            let p = regs.ptr(1)?;
            mem.write(p, &[0u8; 16])?;
            Ok(0)
        }
        SYS_GETRANDOM => {
            let p = regs.ptr(0)?;
            let len = regs.len(1)?;
            let mut out = Vec::with_capacity(len);
            let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
            for _ in 0..len {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                out.push((x >> 33) as u8);
            }
            mem.write(p, &out)?;
            Ok(len as u64)
        }
        SYS_PRLIMIT64 => {
            // Report RLIM_INFINITY for every resource. The address is optional.
            let p = regs.arg(3);
            if p != 0 {
                mem.write(p, &u64::MAX.to_ne_bytes())?;
                mem.write(p + 8, &u64::MAX.to_ne_bytes())?;
            }
            Ok(0)
        }
        SYS_READLINKAT => Err(Errno::NoEnt),
        SYS_CLONE | SYS_FORK => Err(Errno::Nosys),
        SYS_DISPLAY_INFO => {
            let p = regs.ptr(0)?;
            let (w, h) = state.display.dimensions();
            let mut info = [0u8; 16];
            info[0..4].copy_from_slice(&w.to_le_bytes());
            info[4..8].copy_from_slice(&h.to_le_bytes());
            info[8..12].copy_from_slice(&w.saturating_mul(4).to_le_bytes());
            info[12..16].copy_from_slice(&crate::gfx::FORMAT_XRGB8888.to_le_bytes());
            mem.write(p, &info)?;
            Ok(0)
        }
        SYS_WINDOW_CREATE => {
            let id = state.display.create(regs.arg(0) as u32, regs.arg(1) as u32)?;
            Ok(id as u64)
        }
        SYS_WINDOW_MAP => {
            let id = regs.arg(0) as u32;
            let win = *state.display.get(id).ok_or(Errno::NoEnt)?;
            // A window buffer is ordinary anonymous memory shared with the host,
            // which is what lets the guest draw with plain stores.
            let base = mem.map(0, win.byte_len(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS)?;
            state.display.map(id, base)?;
            let p = regs.ptr(1)?;
            let mut info = [0u8; 24];
            info[0..8].copy_from_slice(&base.to_le_bytes());
            info[8..12].copy_from_slice(&win.width.to_le_bytes());
            info[12..16].copy_from_slice(&win.height.to_le_bytes());
            info[16..20].copy_from_slice(&win.width.saturating_mul(4).to_le_bytes());
            info[20..24].copy_from_slice(&crate::gfx::FORMAT_XRGB8888.to_le_bytes());
            mem.write(p, &info)?;
            Ok(base)
        }
        SYS_WINDOW_PRESENT => {
            state.display.show(regs.arg(0) as u32)?;
            Ok(0)
        }
        SYS_WINDOW_MOVE => {
            state.display.move_to(regs.arg(0) as u32, regs.arg(1) as i32, regs.arg(2) as i32)?;
            Ok(0)
        }
        SYS_WINDOW_RAISE => {
            state.display.raise(regs.arg(0) as u32)?;
            Ok(0)
        }
        SYS_WINDOW_DESTROY => {
            let id = regs.arg(0) as u32;
            let win = *state.display.get(id).ok_or(Errno::NoEnt)?;
            let buf = state.display.destroy(id)?;
            if buf != 0 {
                let _ = mem.unmap(buf, win.byte_len());
            }
            Ok(0)
        }
        SYS_DISPLAY_PRESENT => {
            let fb = state.display.composite(|win| {
                let raw = mem.read(win.buffer, win.byte_len() as usize)?;
                Ok(raw
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect())
            })?;
            state.frame = fb.to_ppm();
            Ok(state.frame.len() as u64)
        }
        SYS_WINDOW_DRAW_TEXT => {
            let id = regs.arg(0) as u32;
            let win = *state.display.get(id).ok_or(Errno::NoEnt)?;
            if win.buffer == 0 {
                return Err(Errno::Inval);
            }
            let text = mem.read_cstr(regs.ptr(5)?)?;
            let text = String::from_utf8_lossy(&text);
            let raw = mem.read(win.buffer, win.byte_len() as usize)?;
            let mut fb = crate::gfx::Framebuffer::new(win.width, win.height);
            for (i, c) in raw.chunks_exact(4).enumerate() {
                fb.pixels_mut()[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            let bg = if regs.arg(4) == u32::MAX as u64 {
                None
            } else {
                Some(regs.arg(4) as u32)
            };
            fb.draw_text(regs.arg(1) as i32, regs.arg(2) as i32, &text, regs.arg(3) as u32, bg);
            let mut out = Vec::with_capacity(fb.len() * 4);
            for &p in fb.pixels() {
                out.extend_from_slice(&p.to_le_bytes());
            }
            mem.write(win.buffer, &out)?;
            Ok(0)
        }
        _ => Err(Errno::Nosys),
    }
}

impl<'a> GuestState<'a> {
    pub fn new(vfs: &'a mut Vfs) -> Self {
        GuestState {
            vfs,
            brk: 0,
            exited: None,
            pid: 0,
            pending_mmap: Vec::new(),
            stdout: Vec::new(),
            file_pos: BTreeMap::new(),
            fs_base: 0,
            fs_set: false,
            display: crate::gfx::Display::default(),
            frame: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::SimMem;
    use crate::space::AddressSpace;
    use crate::vfs::Ino;

    /// A guest memory implementation over a simulated address space.
    struct SimGuest {
        space: AddressSpace<SimMem>,
    }

    impl SimGuest {
        /// Maps a fixed 16-page region at `0x1000_0000` and leaves the rest of
        /// `frames` free for `mmap` to claim.
        ///
        /// Keeping the base region small means most of the simulated memory is
        /// genuinely available, so `mmap` exhaustion is reached by asking for
        /// too much rather than by being pre-arranged.
        fn new(frames: u64) -> Self {
            Self::with_region(frames, 16)
        }

        /// Maps `region_pages` pages at `0x1000_0000`.
        fn with_region(frames: u64, region_pages: u64) -> Self {
            let mut space = AddressSpace::new(SimMem::new(frames));
            assert!(
                frames > region_pages,
                "test asked for more base pages ({region_pages}) than frames ({frames})",
            );
            space
                .map_anon(0x1000_0000, region_pages * crate::PAGE_SIZE as u64, crate::addr::Perms::RWX)
                .expect("base region must fit in the simulated memory");
            SimGuest { space }
        }
    }

    impl GuestMemory for SimGuest {
        fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, Errno> {
            self.space.read_bytes(addr, len).map_err(|_| Errno::Inval)
        }

        fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno> {
            self.space.write_bytes(addr, data).map_err(|_| Errno::Inval)
        }

        fn map(&mut self, addr: u64, len: u64, prot: u32, flags: u32) -> Result<u64, Errno> {
            let perms = perms_from_prot(prot).ok_or(Errno::Inval)?;
            let fixed = flags & MAP_FIXED != 0;

            let target = if fixed {
                if addr == 0 {
                    return Err(Errno::Inval);
                }
                crate::addr::align_down(addr)
            } else {
                self.space
                    .find_free(len, 0x7f00_0000_0000)
                    .ok_or(Errno::NoMem)?
            };

            if fixed {
                self.space.unmap_range(target, len).map_err(|_| Errno::Inval)?;
            }
            self.space.map_anon(target, len, perms).map_err(|_| Errno::NoMem)?;
            Ok(target)
        }

        fn unmap(&mut self, addr: u64, len: u64) -> Result<(), Errno> {
            self.space.unmap_range(addr, len).map_err(|_| Errno::Inval)?;
            Ok(())
        }

        fn protect(&mut self, addr: u64, len: u64, prot: u32) -> Result<(), Errno> {
            let perms = perms_from_prot(prot).ok_or(Errno::Inval)?;
            // Check the whole range before touching anything, so a range that
            // runs off the end of the mappings changes nothing. Linux reports
            // that as `ENOMEM`.
            for vpage in crate::addr::page_range(addr, len) {
                if self.space.table.perms_at(vpage).is_none() {
                    return Err(Errno::NoMem);
                }
            }
            for vpage in crate::addr::page_range(addr, len) {
                self.space.table.protect(vpage, perms).map_err(|_| Errno::Inval)?;
            }
            Ok(())
        }

        fn read_cstr(&self, addr: u64) -> Result<Vec<u8>, Errno> {
            let mut out = Vec::new();
            let mut a = addr;
            loop {
                let page = self.space.read_bytes(a, 1).map_err(|_| Errno::Inval)?;
                if page[0] == 0 {
                    return Ok(out);
                }
                out.push(page[0]);
                a += 1;
                if out.len() > crate::vfs::PATH_MAX {
                    return Err(Errno::NameTooLong);
                }
            }
        }
    }

    fn put_str(g: &mut SimGuest, addr: u64, s: &str) {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        g.write(addr, &b).unwrap();
    }

    /// Builds a guest, its filesystem, state and fd table.
    ///
    /// The `Vfs` is leaked so `GuestState` can be returned alongside the other
    /// pieces without lifetime gymnastics; tests are short-lived processes.
    fn harness(frames: u64) -> (SimGuest, GuestState<'static>, FdTable) {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let state = GuestState::new(vfs);
        (SimGuest::new(frames), state, FdTable::new())
    }

    #[test]
    fn registers_decode_args_and_pointers() {
        let r = Registers::new(SYS_READ).with_args([1, 0x1000_0000, 100, 0, 0, 0]);
        assert_eq!(r.arg(0), 1);
        assert_eq!(r.arg(2), 100);
        assert_eq!(r.ptr(1).unwrap(), 0x1000_0000);
        assert_eq!(r.len(2).unwrap(), 100);
    }

    #[test]
    fn non_canonical_pointers_are_rejected_before_use() {
        let r = Registers::new(SYS_READ).with_args([0, 0x0000_8000_0000_0000, 4, 0, 0, 0]);
        assert_eq!(r.ptr(1), Err(Errno::Inval));
        let r = Registers::new(SYS_READ).with_args([0, 0, u64::MAX, 0, 0, 0]);
        assert_eq!(r.len(2), Err(Errno::Inval));
    }

    #[test]
    fn missing_args_read_as_zero() {
        let r = Registers::new(SYS_GETPID);
        assert_eq!(r.arg(3), 0);
        assert_eq!(r.arg(99), 0);
    }

    #[test]
    fn exit_sets_the_status_and_returns_zero() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_EXIT_GROUP).with_args([42, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.exited, Some(42));
    }

    #[test]
    fn exit_truncates_status_to_a_byte() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_EXIT).with_args([0x1234, 0, 0, 0, 0, 0]);
        dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert_eq!(s.exited, Some(0x34));
    }

    #[test]
    fn getpid_increments() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_GETPID);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(1));
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(2));
    }

    #[test]
    fn write_to_stdout_is_captured() {
        let (mut g, mut s, mut f) = harness(64);
        g.write(0x1000_0000, b"hello\n").unwrap();

        let r = Registers::new(SYS_WRITE).with_args([1, 0x1000_0000, 6, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(6));
        assert_eq!(s.stdout, b"hello\n".to_vec());
    }

    #[test]
    fn write_to_a_closed_fd_is_badf() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_WRITE).with_args([9, 0x1000_0000, 6, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Badf));
    }

    #[test]
    fn open_write_read_close_roundtrip() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);

        // open("/f", O_RDWR|O_CREAT)
        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0o102, 0, 0, 0, 0]);
        let fd = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert!(fd >= 3, "stdio must be reserved");

        // write(fd, "abc", 3)
        g.write(0x1000_0100, b"abc").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 3, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));

        // Position advanced, so a read at offset 0 sees nothing.
        let r = Registers::new(SYS_READ).with_args([fd, 0x1000_0200, 3, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));

        // Rewind and read.
        s.file_pos.insert(fd, 0);
        let r = Registers::new(SYS_READ).with_args([fd, 0x1000_0200, 3, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));
        assert_eq!(g.read(0x1000_0200, 3).unwrap(), b"abc".to_vec());

        let r = Registers::new(SYS_CLOSE).with_args([fd, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        // Second close fails.
        assert_eq!(
            dispatch(&r, &mut g, &mut s, &mut f),
            Err(Errno::Badf)
        );
    }

    #[test]
    fn open_missing_file_without_create_is_noent() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        put_str(&mut g, 0x1000_0000, "/absent");
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
    }

    #[test]
    fn openat_resolves_absolute_paths_and_ignores_dirfd() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        vfs.create("/motd", b"hi").unwrap();
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        put_str(&mut g, 0x1000_0000, "/motd");
        // dirfd = AT_FDCWD (-100), flags = O_RDONLY.
        let r = Registers::new(SYS_OPENAT)
            .with_args([(-100i64) as u64, 0x1000_0000, 0, 0, 0, 0]);
        let fd = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert!(fd >= 3, "stdio must be reserved");

        let r = Registers::new(SYS_READ).with_args([fd, 0x1000_0100, 2, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(2));
        assert_eq!(g.read(0x1000_0100, 2).unwrap(), b"hi".to_vec());
    }

    #[test]
    fn openat_missing_file_is_noent() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        put_str(&mut g, 0x1000_0000, "/nope");
        let r = Registers::new(SYS_OPENAT)
            .with_args([(-100i64) as u64, 0x1000_0000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
    }

    #[test]
    fn arch_prctl_records_fs_base_and_reads_it_back() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);

        let r = Registers::new(SYS_ARCH_PRCTL).with_args([ARCH_SET_FS, 0x5000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert!(s.fs_set);
        assert_eq!(s.fs_base, 0x5000);

        let r = Registers::new(SYS_ARCH_PRCTL).with_args([ARCH_GET_FS, 0x1000_0000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(g.read(0x1000_0000, 8).unwrap(), 0x5000u64.to_ne_bytes().to_vec());
    }

    #[test]
    fn read_cstr_stops_at_nul_and_errors_on_unmapped() {
        let mut g = SimGuest::new(64);
        put_str(&mut g, 0x1000_0000, "abc");
        assert_eq!(g.read_cstr(0x1000_0000).unwrap(), b"abc".to_vec());
        assert_eq!(g.read_cstr(0x9000_0000), Err(Errno::Inval));
    }

    #[test]
    fn read_cstr_rejects_runaway_strings() {
        let mut g = SimGuest::new(64);
        // More than PATH_MAX non-NUL bytes with no terminator anywhere in the
        // mapped region: the read must be refused, not looped forever.
        g.write(0x1000_0000, &vec![b'x'; 0x2000]).unwrap();
        assert_eq!(g.read_cstr(0x1000_0000), Err(Errno::NameTooLong));
    }

    #[test]
    fn mmap_records_the_request_and_returns_the_address() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(256);

        let r = Registers::new(SYS_MMAP).with_args([0, 0x10000, (PROT_READ | PROT_WRITE) as u64, MAP_ANONYMOUS as u64, 0, 0]);
        let got = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert!(got >= 0x7f00_0000_0000, "got {got:#x}");
        assert_eq!(s.pending_mmap.len(), 1);
        assert_eq!(s.pending_mmap[0].len, 0x10000);

        // The mapping is real: write then read back.
        g.write(got, b"mapped").unwrap();
        assert_eq!(g.read(got, 6).unwrap(), b"mapped".to_vec());
    }

    #[test]
    fn mmap_zero_length_is_invalid() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        let r = Registers::new(SYS_MMAP).with_args([0, 0, PROT_READ as u64, MAP_ANONYMOUS as u64, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
    }

    #[test]
    fn munmap_removes_the_mapping() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(256);

        let r = Registers::new(SYS_MMAP).with_args([0, 0x1000, (PROT_READ | PROT_WRITE) as u64, MAP_ANONYMOUS as u64, 0, 0]);
        let got = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        g.write(got, b"x").unwrap();

        let r = Registers::new(SYS_MUNMAP).with_args([got, 0x1000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(g.write(got, b"y"), Err(Errno::Inval));
    }

    #[test]
    fn mmap_fixed_honours_the_requested_address() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(256);

        let target = 0x5000_0000u64;
        let r = Registers::new(SYS_MMAP).with_args([
            target, 0x2000, (PROT_READ | PROT_WRITE) as u64, (MAP_ANONYMOUS | MAP_FIXED) as u64, 0, 0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(target));
        g.write(target, b"fixed").unwrap();
        assert_eq!(g.read(target, 5).unwrap(), b"fixed".to_vec());
    }

    #[test]
    fn mmap_fixed_with_null_address_is_invalid() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        let r = Registers::new(SYS_MMAP).with_args([0, 0x1000, PROT_READ as u64, (MAP_ANONYMOUS | MAP_FIXED) as u64, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
    }

    #[test]
    fn mmap_out_of_memory_is_reported_not_panicked() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        // Only a handful of frames free after the base region, so a request
        // far larger than memory must fail cleanly.
        let mut g = SimGuest::new(24);
        let r = Registers::new(SYS_MMAP).with_args([0, 0x10_00000, (PROT_READ | PROT_WRITE) as u64, MAP_ANONYMOUS as u64, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoMem));
        assert!(s.pending_mmap.is_empty(), "a failed mmap must not be recorded");
    }

    #[test]
    fn mprotect_narrows_permissions_and_they_take_effect() {
        let (mut g, mut s, mut f) = harness(256);
        let base = 0x1000_0000u64;

        // Start read/write/exec, then drop write. The page table is the thing
        // that enforces this, so translate() with WRITE must start failing.
        assert_eq!(g.space.table.perms_at(base), Some(Perms::RWX));
        let r = Registers::new(SYS_MPROTECT).with_args([base, 0x1000, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(g.space.table.perms_at(base), Some(Perms::READ));
        assert!(g.space.table.translate(base, Perms::READ).is_ok());
        assert_eq!(
            g.space.table.translate(base, Perms::WRITE),
            Err(crate::addr::AddrError::PermissionDenied)
        );
    }

    #[test]
    fn mprotect_can_also_restore_and_add_permissions() {
        let (mut g, mut s, mut f) = harness(256);
        let base = 0x1000_0000u64;

        let r = Registers::new(SYS_MPROTECT).with_args([base, 0x2000, PROT_NONE as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(g.space.table.perms_at(base), Some(Perms::NONE));
        assert_eq!(
            g.space.table.translate(base, Perms::READ),
            Err(crate::addr::AddrError::PermissionDenied)
        );

        // Re-granting read/write/exec makes the same pages usable again.
        let r = Registers::new(SYS_MPROTECT)
            .with_args([base, 0x2000, (PROT_READ | PROT_WRITE | PROT_EXEC) as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert!(g.space.table.translate(base, Perms::WRITE).is_ok());
        g.write(base, b"ok").unwrap();
        assert_eq!(g.read(base, 2).unwrap(), b"ok".to_vec());
    }

    #[test]
    fn mprotect_applies_to_every_page_in_the_range() {
        let (mut g, mut s, mut f) = harness(256);
        let base = 0x1000_0000u64;
        // Three pages, all of which must change.
        let r = Registers::new(SYS_MPROTECT).with_args([base, 0x3000, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        for i in 0..3u64 {
            assert_eq!(g.space.table.perms_at(base + i * 0x1000), Some(Perms::READ));
        }
        // A fourth page was never in range, so it keeps its permissions.
        assert_eq!(g.space.table.perms_at(base + 3 * 0x1000), Some(Perms::RWX));
    }

    #[test]
    fn mprotect_rejects_misaligned_zero_length_and_unknown_prot() {
        let (mut g, mut s, mut f) = harness(256);
        let base = 0x1000_0000u64;

        let misaligned = Registers::new(SYS_MPROTECT).with_args([base + 1, 0x1000, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(dispatch(&misaligned, &mut g, &mut s, &mut f), Err(Errno::Inval));

        let zero_len = Registers::new(SYS_MPROTECT).with_args([base, 0, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(dispatch(&zero_len, &mut g, &mut s, &mut f), Err(Errno::Inval));

        // Bit 8 is not a PROT_* bit; Linux would fail this rather than ignore it.
        let bogus = Registers::new(SYS_MPROTECT).with_args([base, 0x1000, 0x100, 0, 0, 0]);
        assert_eq!(dispatch(&bogus, &mut g, &mut s, &mut f), Err(Errno::Inval));

        // None of the rejected requests may have changed anything.
        assert_eq!(g.space.table.perms_at(base), Some(Perms::RWX));
    }

    #[test]
    fn mprotect_on_an_unmapped_range_is_nomem_and_changes_nothing() {
        let (mut g, mut s, mut f) = harness(256);
        let base = 0x1000_0000u64;
        // Four pages requested but the base region is only 16 pages, so the tail
        // runs off the end of what is mapped.
        let r = Registers::new(SYS_MPROTECT).with_args([base, 0x1000_0000, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoMem));
        // The in-range pages must be untouched by the failed request.
        assert_eq!(g.space.table.perms_at(base), Some(Perms::RWX));
    }

    #[test]
    fn brk_tracks_the_requested_break() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);

        let r = Registers::new(SYS_BRK).with_args([0x4000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0x4000_0000));
        assert_eq!(s.brk, 0x4000_0000);

        // A lower request does not shrink the break.
        let r = Registers::new(SYS_BRK).with_args([0x1000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0x4000_0000));
        assert_eq!(s.brk, 0x4000_0000);
    }

    #[test]
    fn unknown_syscalls_return_nosys() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        for nr in [999i64, 1000, 4000] {
            let r = Registers::new(nr);
            assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Nosys));
        }
    }

    #[test]
    fn fork_and_clone_are_not_yet_implemented() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        assert_eq!(
            dispatch(&Registers::new(SYS_FORK), &mut g, &mut s, &mut f),
            Err(Errno::Nosys)
        );
        assert_eq!(
            dispatch(&Registers::new(SYS_CLONE), &mut g, &mut s, &mut f),
            Err(Errno::Nosys)
        );
    }

    #[test]
    fn fd_table_allocates_sequentially_and_reuses_nothing() {
        let mut f = FdTable::new();
        // The standard streams are present from the start, backed by the host.
        assert_eq!(f.len(), 3);
        assert_eq!(f.get(Fd(0)), Ok(FdKind::Host(0)));
        let a = f.alloc(Ino(10));
        let b = f.alloc(Ino(11));
        assert_eq!(a, Fd(3));
        assert_eq!(b, Fd(4));
        assert_eq!(f.get(Fd(3)), Ok(FdKind::File(Ino(10))));
        assert_eq!(f.get_file(Fd(3)), Ok(Ino(10)));
        assert_eq!(f.len(), 5);
        assert_eq!(f.close(Fd(3)), Ok(FdKind::File(Ino(10))));
        assert_eq!(f.close(Fd(3)), Err(Errno::Badf));
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn ioctl_tty_probe_is_rejected() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(64);
        let r = Registers::new(SYS_IOCTL).with_args([1, 0x5401, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
    }

    #[test]
    fn errno_values_match_linux() {
        assert_eq!(Errno::NoEnt as i32, 2);
        assert_eq!(Errno::Io as i32, 5);
        assert_eq!(Errno::Badf as i32, 9);
        assert_eq!(Errno::Acces as i32, 13);
        assert_eq!(Errno::Exist as i32, 17);
        assert_eq!(Errno::NotDir as i32, 20);
        assert_eq!(Errno::IsDir as i32, 21);
        assert_eq!(Errno::Inval as i32, 22);
        assert_eq!(Errno::Nosys as i32, 38);
    }

    #[test]
    fn display_and_window_syscalls_round_trip() {
        let (mut g, mut s, mut f) = harness(512);
        s.display = crate::gfx::Display::new(8, 4);
        let info_at = 0x1000_0000u64;

        let r = Registers::new(SYS_DISPLAY_INFO).with_args([info_at, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let info = g.read(info_at, 16).unwrap();
        assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(info[8..12].try_into().unwrap()), 32);

        let r = Registers::new(SYS_WINDOW_CREATE).with_args([2, 2, 0, 0, 0, 0]);
        let id = dispatch(&r, &mut g, &mut s, &mut f).unwrap() as u32;

        let r = Registers::new(SYS_WINDOW_MAP).with_args([id as u64, info_at, 0, 0, 0, 0]);
        let base = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert!(base > 0);
        let mapinfo = g.read(info_at, 24).unwrap();
        assert_eq!(u64::from_le_bytes(mapinfo[0..8].try_into().unwrap()), base);
        assert_eq!(u32::from_le_bytes(mapinfo[8..12].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(mapinfo[16..20].try_into().unwrap()), 8);

        let red = 0x00ff_0000u32.to_le_bytes();
        let px: Vec<u8> = std::iter::repeat(red).take(4).flatten().collect();
        g.write(base, &px).unwrap();

        let r = Registers::new(SYS_WINDOW_PRESENT).with_args([id as u64, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let r = Registers::new(SYS_DISPLAY_PRESENT).with_args([0, 0, 0, 0, 0, 0]);
        let n = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert!(n > 0);
        let header = b"P6\n8 4\n255\n";
        assert_eq!(&s.frame[..header.len()], header);
        assert_eq!(&s.frame[header.len()..header.len() + 3], &[255, 0, 0]);
    }

    #[test]
    fn window_operations_on_unknown_ids_fail() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_WINDOW_PRESENT).with_args([99, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
        let r = Registers::new(SYS_WINDOW_MAP).with_args([99, 0x1000_0000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
        let r = Registers::new(SYS_WINDOW_DESTROY).with_args([99, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
    }
}
