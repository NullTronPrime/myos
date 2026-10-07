//! Syscall ABI: decoding guest registers, dispatch, and errno mapping.
//!
//! The dispatcher is a pure function from `(nr, args, &mut Guest)` to a return
//! value. Nothing here touches the host, so every syscall's logic is testable
//! by constructing a guest state and calling it directly. The `osplat` layer
//! only has to move registers in and out.

use crate::addr::{Perms, PAGE_SIZE};
use crate::vfs::{Errno, Fd, Ino, Vfs};
use std::collections::BTreeMap;

/// x86-64 Linux syscall numbers used by this kernel.
pub const SYS_READ: i64 = 0;
pub const SYS_WRITE: i64 = 1;
pub const SYS_OPEN: i64 = 2;
pub const SYS_CLOSE: i64 = 3;
pub const SYS_STAT: i64 = 4;
pub const SYS_FSTAT: i64 = 5;
pub const SYS_LSTAT: i64 = 6;
pub const SYS_LSEEK: i64 = 8;
pub const SYS_MMAP: i64 = 9;
pub const SYS_MPROTECT: i64 = 10;
pub const SYS_MUNMAP: i64 = 11;
pub const SYS_BRK: i64 = 12;
pub const SYS_RT_SIGACTION: i64 = 13;
pub const SYS_RT_SIGPROCMASK: i64 = 14;
pub const SYS_RT_SIGRETURN: i64 = 15;
pub const SYS_IOCTL: i64 = 16;
pub const SYS_PREAD64: i64 = 17;
pub const SYS_PWRITE64: i64 = 18;
pub const SYS_WRITEV: i64 = 20;
pub const SYS_PIPE: i64 = 22;
pub const SYS_SELECT: i64 = 23;
pub const SYS_DUP: i64 = 32;
pub const SYS_DUP2: i64 = 33;
pub const SYS_NANOSLEEP: i64 = 35;
pub const SYS_GETPID: i64 = 39;
pub const SYS_CLONE: i64 = 56;
pub const SYS_FORK: i64 = 57;
pub const SYS_EXECVE: i64 = 59;
pub const SYS_EXIT: i64 = 60;
pub const SYS_WAIT4: i64 = 61;
pub const SYS_KILL: i64 = 62;
pub const SYS_UNAME: i64 = 63;
pub const SYS_FCNTL: i64 = 72;
pub const SYS_FTRUNCATE: i64 = 77;
pub const SYS_GETDENTS: i64 = 78;
pub const SYS_GETCWD: i64 = 79;
pub const SYS_CHDIR: i64 = 80;
pub const SYS_MKDIR: i64 = 83;
pub const SYS_RMDIR: i64 = 84;
pub const SYS_UNLINK: i64 = 87;
pub const SYS_READLINK: i64 = 89;
pub const SYS_CHMOD: i64 = 90;
pub const SYS_UMASK: i64 = 95;
pub const SYS_GETTIMEOFDAY: i64 = 96;
pub const SYS_GETUID: i64 = 102;
pub const SYS_GETGID: i64 = 104;
pub const SYS_GETEUID: i64 = 107;
pub const SYS_GETEGID: i64 = 108;
pub const SYS_GETPPID: i64 = 110;
pub const SYS_ARCH_PRCTL: i64 = 158;
pub const SYS_SET_TID_ADDRESS: i64 = 218;
pub const SYS_CLOCK_GETTIME: i64 = 228;
pub const SYS_CLOCK_GETRES: i64 = 229;
pub const SYS_CLOCK_NANOSLEEP: i64 = 230;
pub const SYS_EXIT_GROUP: i64 = 231;
pub const SYS_TGKILL: i64 = 234;
pub const SYS_TGKILL3: i64 = 234;
pub const SYS_OPENAT: i64 = 257;
pub const SYS_MKDIRAT: i64 = 258;
pub const SYS_NEWFSTATAT: i64 = 262;
pub const SYS_UNLINKAT: i64 = 263;
pub const SYS_RENAMEAT: i64 = 264;
pub const SYS_READLINKAT: i64 = 267;
pub const SYS_FACCESSAT: i64 = 269;
pub const SYS_PSELECT6: i64 = 270;
pub const SYS_POLL: i64 = 271;
pub const SYS_SET_ROBUST_LIST: i64 = 273;
pub const SYS_UTIMENSAT: i64 = 280;
pub const SYS_FALLOCATE: i64 = 285;
pub const SYS_PPOLL: i64 = 288;
pub const SYS_DUP3: i64 = 292;
pub const SYS_PIPE2: i64 = 293;
pub const SYS_PRLIMIT64: i64 = 302;
pub const SYS_GETRANDOM: i64 = 318;
pub const SYS_MEMFD_CREATE: i64 = 319;
pub const SYS_EXECVEAT: i64 = 322;
pub const SYS_STATX: i64 = 332;
pub const SYS_RSEQ: i64 = 334;

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
/// Reads a window's current position, focus flag and z-order into a guest
/// structure. Read-only counterpart to `window_move`/`window_raise`.
pub const SYS_WINDOW_QUERY: i64 = 0x1009;
/// Resizes a window and remaps its buffer, reporting the new geometry.
pub const SYS_WINDOW_RESIZE: i64 = 0x100a;
/// Which window is topmost at a point, for hit testing and focus.
pub const SYS_DISPLAY_WINDOW_AT: i64 = 0x100b;
/// Blocks until an input event is queued, or until a timeout expires.
pub const SYS_INPUT_WAIT: i64 = 0x100c;
/// The guest's pending input events, read as fixed-size records.
pub const SYS_INPUT_READ: i64 = 0x100d;
/// Renames a window and sets its title, which the host draws in its decoration.
pub const SYS_WINDOW_SET_TITLE: i64 = 0x100e;
/// Asks the compositor for the next frame; a no-op that returns the frame
/// counter, so a guest loop can pace itself without a wall clock.
pub const SYS_DISPLAY_FRAME: i64 = 0x100f;
/// Writes the whole guest filesystem back to the host root, on demand.
pub const SYS_SYNC_FS: i64 = 0x1010;
/// Which window has input focus.
pub const SYS_WINDOW_FOCUS: i64 = 0x1011;
/// The descriptor to read input events from, allocated on first call.
///
/// Input is a stream rather than a global so that a guest which loses interest
/// simply stops reading it, and so two consumers cannot steal events from each
/// other. `input_read` and `input_wait` both need it, and there is no constant
/// a guest could guess.
pub const SYS_INPUT_FD: i64 = 0x1012;

/// `arch_prctl` sub-functions for the thread-pointer (`%fs`) base.
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

/// `lseek` whence values.
pub const SEEK_SET: i64 = 0;
pub const SEEK_CUR: i64 = 1;
pub const SEEK_END: i64 = 2;
/// `S_IFMT`, used when masking a mode.
pub const S_IFMT: u32 = 0o170000;
/// `getdents64` buffer header size: `d_ino` plus `d_off`.
pub const DIRENT_HDR: usize = 16;
/// `getdents64` record header size: the header plus `d_reclen` and `d_type`.
pub const DIRENT_REC: usize = 24;
/// `AT_FDCWD`, the "relative to the current directory" sentinel.
pub const AT_FDCWD: i64 = -100;
/// `AT_REMOVEDIR`, for `unlinkat`.
pub const AT_REMOVEDIR: i32 = 0x200;
/// `d_type` for a regular file.
pub const DT_FILE: u8 = 8;
/// `d_type` for a directory.
pub const DT_DIR: u8 = 4;

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
        Registers {
            nr,
            args: [0; MAX_ARGS],
            rip: 0,
            rsp: 0,
        }
    }

    pub fn with_args(mut self, args: [u64; MAX_ARGS]) -> Self {
        self.args = args;
        self
    }

    pub fn arg(&self, i: usize) -> u64 {
        self.args.get(i).copied().unwrap_or(0)
    }

    /// Reads argument `i` as a C `int`.
    ///
    /// A guest that declares an argument `int` writes only the low 32 bits of
    /// the register, so `AT_FDCWD` arrives as `0x0000_0000_ffff_ff9c` rather
    /// than sign-extended. Reading such an argument as a 64-bit integer would
    /// turn every negative sentinel into a large positive number, so 32-bit
    /// signed arguments must go through here.
    pub fn arg_i32(&self, i: usize) -> i32 {
        self.arg(i) as u32 as i32
    }

    /// Reads argument `i` as a C `long`, sign-extended from the low 32 bits
    /// when the guest left the high half clear.
    pub fn arg_i64(&self, i: usize) -> i64 {
        self.arg(i) as i64
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
    /// Thread-pointer (`%fs`) base the guest asked for via `arch_prctl`.
    pub fs_base: u64,
    /// Whether the guest has set `%fs` itself. Static glibc does this during
    /// startup; until then the host's own thread pointer must be left in place.
    pub fs_set: bool,
    /// The guest's display and window model.
    pub display: crate::gfx::Display,
    /// A PPM of the last `display_present`, for the platform layer to write out.
    pub frame: Vec<u8>,
    /// Wall and monotonic time, refreshed by the platform before each trap.
    pub clock: crate::clock::Clock,
    /// Signal dispositions, the blocked mask and the pending queue.
    pub signals: crate::signal::SignalTable,
    /// Keyboard and mouse events waiting for the guest.
    pub input: crate::input::InputQueue,
    /// The guest's current working directory. Every path resolves against it,
    /// which is what makes a relative `open` work the way a program expects.
    pub cwd: String,
    /// The guest's file mode creation mask.
    pub umask: u32,
    /// Frames composited so far, so a guest loop can pace itself.
    pub frame_counter: u64,
    /// A sleep the platform must perform, as `(deadline, to_return)`.
    pub pending_sleep: Option<Sleep>,
    /// Set when `input_wait` parked the guest, so the platform retries it.
    pub pending_input_wait: bool,
    /// The descriptor input events are read from, allocated on first request.
    pub input_fd: Option<u32>,
    /// Statistics the platform should report after a `sync`.
    pub sync: Option<crate::persist::SyncStats>,
}

/// A sleep request produced by `nanosleep`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sleep {
    /// Monotonic nanoseconds the sleep ends at.
    pub deadline_ns: u64,
    /// Whether to return the unslept remainder through `rem`.
    pub want_remaining: bool,
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
    /// An endpoint of the input event queue, which guests read like a file.
    Input,
}

/// An open file description.
///
/// Linux keeps the offset and the flags on the description rather than on the
/// descriptor, so two descriptors from one `dup` share a position. Keyed by an
/// id the `FdTable` hands out, which is what makes that sharing expressible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenFile {
    pub ino: crate::vfs::Ino,
    pub offset: u64,
    /// `O_APPEND` forces every write to the end, whatever the offset is.
    pub append: bool,
    /// Descriptors sharing this description.
    pub refs: u32,
}

/// Owned open file descriptors.
#[derive(Default)]
pub struct FdTable {
    next: u32,
    open: BTreeMap<u32, FdKind>,
    /// Open file descriptions, keyed by their own id.
    files: BTreeMap<u32, OpenFile>,
    /// Which description each descriptor refers to.
    pins: BTreeMap<u32, u32>,
    next_file: u32,
}

impl FdTable {
    pub fn new() -> Self {
        // The standard streams are the host's 0, 1 and 2.
        let mut open = BTreeMap::new();
        open.insert(0, FdKind::Host(0));
        open.insert(1, FdKind::Host(1));
        open.insert(2, FdKind::Host(2));
        FdTable {
            next: 3,
            open,
            files: BTreeMap::new(),
            pins: BTreeMap::new(),
            next_file: 1,
        }
    }

    pub fn alloc(&mut self, ino: crate::vfs::Ino) -> Fd {
        self.alloc_kind(FdKind::File(ino))
    }

    /// Allocates a descriptor together with a fresh open file description, so
    /// the new descriptor starts at offset zero regardless of any other.
    pub fn alloc_file(&mut self, ino: crate::vfs::Ino, flags: u32) -> Fd {
        let id = self.take_file_id();
        self.files.insert(
            id,
            OpenFile {
                ino,
                offset: 0,
                append: flags & crate::vfs::O_APPEND != 0,
                refs: 1,
            },
        );
        let fd = Fd(self.next);
        self.next += 1;
        self.open.insert(fd.0, FdKind::File(ino));
        self.pins.insert(fd.0, id);
        fd
    }

    fn take_file_id(&mut self) -> u32 {
        let id = self.next_file;
        self.next_file += 1;
        id
    }

    /// The open file description behind a descriptor.
    pub fn file(&self, fd: Fd) -> Option<&OpenFile> {
        self.files.get(self.pins.get(&fd.0)?)
    }

    pub fn file_mut(&mut self, fd: Fd) -> Option<&mut OpenFile> {
        let id = *self.pins.get(&fd.0)?;
        self.files.get_mut(&id)
    }

    /// Current offset of a descriptor, or `None` for one with no description.
    pub fn offset(&self, fd: Fd) -> Option<u64> {
        self.file(fd).map(|f| f.offset)
    }

    /// Sets the offset, as `lseek` does.
    pub fn set_offset(&mut self, fd: Fd, offset: u64) -> bool {
        match self.file_mut(fd) {
            Some(f) => {
                f.offset = offset;
                true
            }
            None => false,
        }
    }

    /// Allocates the next free descriptor for an already-open host fd.
    pub fn alloc_host(&mut self, host: i32) -> Fd {
        self.alloc_kind(FdKind::Host(host))
    }

    pub fn alloc_kind(&mut self, kind: FdKind) -> Fd {
        let n = self.next;
        self.next += 1;
        self.open.insert(n, kind);
        Fd(n)
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
        let kind = self.open.remove(&fd.0).ok_or(Errno::Badf)?;
        self.drop_pin(fd);
        Ok(kind)
    }

    /// Forgets the description a descriptor refers to, freeing the description
    /// once nothing else points at it.
    fn drop_pin(&mut self, fd: Fd) {
        if let Some(id) = self.pins.remove(&fd.0) {
            if let Some(f) = self.files.get_mut(&id) {
                f.refs -= 1;
                if f.refs == 0 {
                    self.files.remove(&id);
                }
            }
        }
    }

    /// Replaces the descriptor `fd`, as `dup2` does. Any description the old
    /// descriptor held is released.
    pub fn set(&mut self, fd: Fd, kind: FdKind) {
        self.open.insert(fd.0, kind);
        self.drop_pin(fd);
    }

    /// Points `fd` at the same description as `src`, so the two share an offset.
    /// Points `fd` at the same open file description as `src`.
    ///
    /// Sharing the description is what makes the two descriptors share an
    /// offset, which is the whole point of `dup`. Host and input descriptors
    /// have no description to share, so those are simply aliased.
    pub fn share(&mut self, fd: Fd, src: Fd) {
        let Some(kind) = self.open.get(&src.0).copied() else {
            return;
        };
        if !matches!(kind, FdKind::File(_)) {
            self.drop_pin(fd);
            self.open.insert(fd.0, kind);
            if fd.0 >= self.next {
                self.next = fd.0 + 1;
            }
            return;
        }
        let Some(id) = self.pins.get(&src.0).copied() else {
            return;
        };
        let Some(ino) = self.files.get(&id).map(|f| f.ino) else {
            return;
        };
        // Replacing an existing descriptor releases whatever it held first.
        self.drop_pin(fd);
        if let Some(f) = self.files.get_mut(&id) {
            f.refs += 1;
        }
        self.pins.insert(fd.0, id);
        self.open.insert(fd.0, FdKind::File(ino));
        if fd.0 >= self.next {
            self.next = fd.0 + 1;
        }
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

/// Executes one syscall against guest state.
/// Writes a `struct stat` for `ino` to `p`.
///
/// The guest ABI is fixed at the Linux x86-64 layout, which is 144 bytes with
/// the timestamp fields widened to 64 bits. `stat` and friends all share it, so
/// one helper serves all of them.
pub fn write_stat<M: GuestMemory>(
    mem: &mut M,
    state: &GuestState<'_>,
    ino: Ino,
    p: u64,
) -> SysResult {
    let st = state.vfs.stat(ino, state.now())?;
    mem.write(p, &st.to_bytes())?;
    Ok(0)
}

/// Encodes a `struct sigaction` the way the guest expects to read it back.
///
/// `SA_SIGINFO` is forced on in the reported flags: the kernel always fills
/// `siginfo`, and a guest that installed a plain handler still gets the
/// three-argument frame we build.
pub fn encode_action(act: crate::signal::SigAction) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&act.handler.to_le_bytes());
    out[8..16].copy_from_slice(&(act.flags | crate::signal::SA_SIGINFO).to_le_bytes());
    out[16..24].copy_from_slice(&act.restorer.to_le_bytes());
    out[24..32].copy_from_slice(&act.mask.to_le_bytes());
    out
}

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
            // The offset lives on the open file description, so a `dup`ed
            // descriptor continues from where the original left off.
            let (pos, append) = {
                let f = fds.file(fd).ok_or(Errno::Badf)?;
                (f.offset, f.append)
            };
            let size = state.vfs.read(ino, 0, usize::MAX)?;
            let at = if append { size.len() as u64 } else { pos };
            state.vfs.write(ino, at, &data)?;
            if let Some(f) = fds.file_mut(fd) {
                f.offset = at + data.len() as u64;
            }
            Ok(data.len() as u64)
        }
        SYS_READ => {
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            let ino = fds.get_file(fd)?;
            let pos = fds.offset(fd).ok_or(Errno::Badf)?;
            let data = state.vfs.read(ino, pos, len)?;
            if !data.is_empty() {
                mem.write(buf, &data)?;
                fds.set_offset(fd, pos + data.len() as u64);
            }
            Ok(data.len() as u64)
        }
        SYS_PREAD64 => {
            // Positional read: moves no descriptor offset.
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            let pos = regs.arg(3);
            let ino = fds.get_file(fd)?;
            let data = state.vfs.read(ino, pos, len)?;
            if !data.is_empty() {
                mem.write(buf, &data)?;
            }
            Ok(data.len() as u64)
        }
        SYS_PWRITE64 => {
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            let pos = regs.arg(3);
            let ino = fds.get_file(fd)?;
            let data = mem.read(buf, len)?;
            state.vfs.write(ino, pos, &data)?;
            Ok(data.len() as u64)
        }
        SYS_LSEEK => {
            let fd = Fd(regs.arg(0) as u32);
            let offset = regs.arg(1) as i64;
            let whence = regs.arg(2) as i64;
            let ino = fds.get_file(fd)?;
            let cur = fds.offset(fd).ok_or(Errno::Badf)?;
            let size = state.vfs.read(ino, 0, usize::MAX)?.len() as i64;
            let base = match whence {
                SEEK_SET => 0,
                SEEK_CUR => cur as i64,
                SEEK_END => size,
                _ => return Err(Errno::Inval),
            };
            // A negative resulting position is `EINVAL`, not a wrap.
            let next = base.checked_add(offset).ok_or(Errno::Inval)?;
            if next < 0 {
                return Err(Errno::Inval);
            }
            fds.set_offset(fd, next as u64);
            Ok(next as u64)
        }
        SYS_OPEN => {
            let path_ptr = regs.ptr(0)?;
            let flags = regs.arg(1) as u32;
            let raw = mem.read_cstr(path_ptr)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.open(&path, flags)?;
            Ok(fds.alloc_file(ino, flags).0 as u64)
        }
        SYS_OPENAT => {
            // A `dirfd` other than `AT_FDCWD` names an open directory. Only the
            // current directory is modelled, so anything else is refused rather
            // than silently resolved against the root.
            let dirfd = regs.arg_i32(0) as i64;
            if dirfd != AT_FDCWD {
                let d = Fd(dirfd as u32);
                let Some(ino) = fds.get(d).ok().and_then(|k| match k {
                    FdKind::File(i) => Some(i),
                    _ => None,
                }) else {
                    return Err(Errno::Badf);
                };
                if !state.vfs.get(ino).map(|n| n.kind.is_dir()).unwrap_or(false) {
                    return Err(Errno::NotDir);
                }
            }
            let path_ptr = regs.ptr(1)?;
            let flags = regs.arg(2) as u32;
            let raw = mem.read_cstr(path_ptr)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.open(&path, flags)?;
            Ok(fds.alloc_file(ino, flags).0 as u64)
        }
        SYS_CLOSE => {
            let fd = Fd(regs.arg(0) as u32);
            fds.close(fd)?;
            Ok(0)
        }
        SYS_DUP => {
            let src = Fd(regs.arg(0) as u32);
            // A `dup` of a closed descriptor fails rather than quietly handing
            // back a descriptor that can never be read.
            fds.get(src)?;
            let new = Fd(fds.next);
            fds.share(new, src);
            Ok(new.0 as u64)
        }
        SYS_DUP2 | SYS_DUP3 => {
            let src = Fd(regs.arg(0) as u32);
            let new = Fd(regs.arg(1) as u32);
            fds.get(src)?;
            // Closing the target first means `dup2(fd, fd)` releases the old
            // description and re-shares it, exactly once.
            if regs.arg(2) != 0 {
                fds.close(new)?;
            }
            fds.share(new, src);
            Ok(new.0 as u64)
        }
        SYS_FSTAT => {
            let fd = Fd(regs.arg(0) as u32);
            let p = regs.ptr(1)?;
            let ino = fds.get_file(fd)?;
            write_stat(mem, state, ino, p)?;
            Ok(0)
        }
        SYS_STAT | SYS_LSTAT => {
            // There are no symlinks, so `stat` and `lstat` agree.
            let p = regs.ptr(0)?;
            let out = regs.ptr(1)?;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.lookup(&path)?;
            write_stat(mem, state, ino, out)?;
            Ok(0)
        }
        SYS_NEWFSTATAT => {
            let dirfd = regs.arg_i32(0) as i64;
            if dirfd != AT_FDCWD {
                return Err(Errno::Badf);
            }
            let p = regs.ptr(1)?;
            let out = regs.ptr(2)?;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.lookup(&path)?;
            write_stat(mem, state, ino, out)?;
            Ok(0)
        }
        SYS_STATX => {
            // `struct statx` is 256 bytes with the fields this OS fills at the
            // front. Callers are told which ones are valid through `stx_mask`,
            // and anything not claimed there is left zero.
            let dirfd = regs.arg_i32(0) as i64;
            if dirfd != AT_FDCWD {
                return Err(Errno::Badf);
            }
            let p = regs.ptr(1)?;
            let out = regs.ptr(2)?;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.lookup(&path)?;
            let st = state.vfs.stat(ino, state.now())?;
            let mut buf = vec![0u8; 256];
            let mut put =
                |at: usize, bytes: &[u8]| buf[at..at + bytes.len()].copy_from_slice(bytes);
            // STATX_BASIC_STATS: everything a `stat` would have reported.
            let mask: u32 = 0x0000_07ff;
            put(0, &mask.to_le_bytes());
            put(4, &(st.blksize as u32).to_le_bytes());
            put(16, &(st.nlink as u32).to_le_bytes());
            put(28, &(st.mode as u16).to_le_bytes());
            put(32, &st.ino.to_le_bytes());
            put(40, &st.size.to_le_bytes());
            put(48, &(st.blocks * 8).to_le_bytes());
            // atime, btime, ctime, mtime: seconds then nanoseconds.
            put(64, &st.atime_sec.to_le_bytes());
            put(72, &st.atime_nsec.to_le_bytes());
            put(80, &st.ctime_sec.to_le_bytes());
            put(88, &st.ctime_nsec.to_le_bytes());
            put(96, &st.mtime_sec.to_le_bytes());
            put(104, &st.mtime_nsec.to_le_bytes());
            mem.write(out, &buf)?;
            Ok(0)
        }
        SYS_GETDENTS => {
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            let ino = fds.get_file(fd)?;
            if !state.vfs.get(ino).map(|n| n.kind.is_dir()).unwrap_or(false) {
                return Err(Errno::NotDir);
            }
            // The offset is a 1-based index into the sorted entry list, which
            // makes a repeat call resume where the last one stopped.
            let idx = fds.offset(fd).ok_or(Errno::Badf)? as usize;
            let names = state.vfs.readdir(ino)?;
            let mut out: Vec<u8> = Vec::new();
            let mut i = idx;
            while i < names.len() {
                let name = &names[i];
                // One record: header, then the name and its NUL.
                let reclen = (DIRENT_REC + name.len() + 1).div_ceil(8) * 8;
                if out.len() + reclen > len {
                    // Linux reports a short buffer rather than an error.
                    break;
                }
                let start = out.len();
                out.resize(start + reclen, 0);
                let ino_val = state
                    .vfs
                    .lookup(&format!("{}/{}", state.vfs.path_of(ino), name))
                    .map(|n| n.0)
                    .unwrap_or(0);
                out[start..start + 8].copy_from_slice(&ino_val.to_le_bytes());
                // `d_off` is the next index, so a zero-length buffer terminates.
                out[start + 8..start + 16].copy_from_slice(&((i + 1) as u64).to_le_bytes());
                out[start + 16..start + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
                let d_type = match state
                    .vfs
                    .lookup(&format!("{}/{}", state.vfs.path_of(ino), name))
                {
                    Ok(n) if state.vfs.get(n).map(|x| x.kind.is_dir()).unwrap_or(false) => DT_DIR,
                    _ => DT_FILE,
                };
                out[start + 18] = d_type;
                let nstart = start + DIRENT_REC;
                out[nstart..nstart + name.len()].copy_from_slice(name.as_bytes());
                i += 1;
            }
            fds.set_offset(fd, i as u64);
            mem.write(buf, &out)?;
            Ok(out.len() as u64)
        }
        SYS_GETCWD => {
            let p = regs.ptr(0)?;
            let len = regs.len(1)?;
            let mut c = state.cwd.clone().into_bytes();
            c.push(0);
            if len < c.len() {
                return Err(Errno::Range);
            }
            mem.write(p, &c)?;
            Ok(c.len() as u64)
        }
        SYS_CHDIR => {
            let p = regs.ptr(0)?;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.lookup(&path)?;
            if !state.vfs.get(ino)?.kind.is_dir() {
                return Err(Errno::NotDir);
            }
            state.cwd = state.vfs.path_of(ino);
            Ok(0)
        }
        SYS_MKDIR => {
            let p = regs.ptr(0)?;
            let mode = regs.arg(1) as u32;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.mkdir(&path)?;
            if let Ok(node) = state.vfs.get_mut(ino) {
                node.mode = mode & !state.umask & 0o7777;
            }
            Ok(0)
        }
        SYS_MKDIRAT => {
            let dirfd = regs.arg_i32(0) as i64;
            if dirfd != AT_FDCWD {
                return Err(Errno::Badf);
            }
            let p = regs.ptr(1)?;
            let mode = regs.arg(2) as u32;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.mkdir(&path)?;
            if let Ok(node) = state.vfs.get_mut(ino) {
                node.mode = mode & !state.umask & 0o7777;
            }
            Ok(0)
        }
        SYS_RMDIR => {
            let p = regs.ptr(0)?;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            state.vfs.rmdir(&path)?;
            Ok(0)
        }
        SYS_UNLINK => {
            let p = regs.ptr(0)?;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            state.vfs.unlink(&path)?;
            Ok(0)
        }
        SYS_UNLINKAT => {
            let dirfd = regs.arg_i32(0) as i64;
            if dirfd != AT_FDCWD {
                return Err(Errno::Badf);
            }
            let p = regs.ptr(1)?;
            let flags = regs.arg(2) as i32;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            if flags & AT_REMOVEDIR != 0 {
                state.vfs.rmdir(&path)?;
            } else {
                state.vfs.unlink(&path)?;
            }
            Ok(0)
        }
        SYS_FTRUNCATE => {
            let fd = Fd(regs.arg(0) as u32);
            let len = regs.arg(1);
            let ino = fds.get_file(fd)?;
            state.vfs.truncate(ino, len)?;
            Ok(0)
        }
        SYS_CHMOD => {
            let p = regs.ptr(0)?;
            let mode = regs.arg(1) as u32;
            let raw = mem.read_cstr(p)?;
            let path = String::from_utf8_lossy(&raw).into_owned();
            let path = state.abs_path(&path);
            let ino = state.vfs.lookup(&path)?;
            let node = state.vfs.get_mut(ino)?;
            node.mode = mode & 0o7777;
            Ok(0)
        }
        SYS_UMASK => {
            let old = state.umask;
            state.umask = regs.arg(0) as u32 & 0o777;
            Ok(old as u64)
        }
        SYS_UNAME => {
            let p = regs.ptr(0)?;
            // `struct utsname`: five 65-byte fields.
            let mut buf = vec![0u8; 5 * 65];
            let mut put = |field: usize, text: &str| {
                let start = field * 65;
                let n = text.len().min(64);
                buf[start..start + n].copy_from_slice(&text.as_bytes()[..n]);
            };
            put(0, "Linux");
            put(1, crate::NAME);
            put(2, crate::VERSION);
            put(3, crate::NAME);
            mem.write(p, &buf)?;
            Ok(0)
        }
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => Ok(0),
        SYS_GETPPID => Ok(1),
        SYS_CLOCK_GETTIME => {
            let id = regs.arg(0) as i64;
            let p = regs.ptr(1)?;
            let ts = state.clock.now(id).ok_or(Errno::Inval)?;
            mem.write(p, &ts.to_le_bytes())?;
            Ok(0)
        }
        SYS_CLOCK_GETRES => {
            let id = regs.arg(0) as i64;
            let p = regs.ptr(1)?;
            let ts = state.clock.resolution(id).ok_or(Errno::Inval)?;
            mem.write(p, &ts.to_le_bytes())?;
            Ok(0)
        }
        SYS_GETTIMEOFDAY => {
            // `struct timeval` and an unused `struct timezone`, both passed by
            // pointer and both optional.
            let tv = regs.arg(0);
            if tv != 0 {
                let ts = state
                    .clock
                    .now(crate::clock::CLOCK_REALTIME)
                    .ok_or(Errno::Inval)?;
                mem.write(tv, &crate::clock::Timeval::from_timespec(ts).to_le_bytes())?;
            }
            let tz = regs.arg(1);
            if tz != 0 {
                mem.write(tz, &[0u8; 8])?;
            }
            Ok(0)
        }
        SYS_NANOSLEEP | SYS_CLOCK_NANOSLEEP => {
            // `clock_nanosleep` puts the clock id first.
            let (req, rem) = if regs.nr == SYS_CLOCK_NANOSLEEP {
                (regs.ptr(1)?, regs.arg(2))
            } else {
                (regs.ptr(0)?, regs.arg(1))
            };
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&mem.read(req, 16)?);
            let deadline = crate::clock::Timespec::from_le_bytes(&raw).ok_or(Errno::Inval)?;
            state.pending_sleep = Some(Sleep {
                deadline_ns: deadline.to_nanos() as u64,
                want_remaining: rem != 0,
            });
            Ok(0)
        }
        SYS_RT_SIGACTION => {
            let signum = regs.arg(0) as i32;
            if signum < 1 || signum > 64 {
                return Err(Errno::Inval);
            }
            let act_ptr = regs.arg(1);
            let old_ptr = regs.arg(2);
            if old_ptr != 0 {
                let old = state.signals.action(signum);
                mem.write(old_ptr, &encode_action(old))?;
            }
            if act_ptr != 0 {
                let raw = mem.read(act_ptr, 32)?;
                let act = crate::signal::decode_action(&raw);
                // A real handler returns to `sa_restorer`, so one with no
                // restorer could never get back to where it was interrupted.
                // A real kernel refuses such an install rather than building a
                // frame the guest cannot leave.
                if act.handler != crate::signal::SIG_DFL
                    && act.handler != crate::signal::SIG_IGN
                    && act.restorer == 0
                {
                    return Err(Errno::Inval);
                }
                state.signals.set_action(signum, act);
            }
            Ok(0)
        }
        SYS_RT_SIGPROCMASK => {
            let how = regs.arg(0);
            let set_ptr = regs.arg(1);
            let old_ptr = regs.arg(2);
            let mut set = 0u64;
            if set_ptr != 0 {
                let raw = mem.read(set_ptr, 8)?;
                set = u64::from_ne_bytes(raw[..8].try_into().unwrap());
            }
            let old = state.signals.change_mask(how, set);
            if old_ptr != 0 {
                mem.write(old_ptr, &old.to_ne_bytes())?;
            }
            Ok(0)
        }
        SYS_RT_SIGRETURN => {
            // The platform layer restores registers from the frame; all this has
            // to do is stop the trap handler treating it as a failure.
            Ok(0)
        }
        SYS_INPUT_FD => {
            // The stream is created once and reused, so a guest that asks on
            // every frame does not leak a descriptor per frame.
            match state.input_fd {
                Some(fd) => Ok(fd as u64),
                None => {
                    let fd = fds.alloc_kind(FdKind::Input).0;
                    state.input_fd = Some(fd);
                    Ok(fd as u64)
                }
            }
        }
        SYS_INPUT_READ => {
            let fd = Fd(regs.arg(0) as u32);
            let buf = regs.ptr(1)?;
            let len = regs.len(2)?;
            match fds.get(fd)? {
                FdKind::Input => {}
                _ => return Err(Errno::Badf),
            }
            let mut tmp = vec![0u8; len];
            let n = state.input.read_into(&mut tmp);
            if n > 0 {
                mem.write(buf, &tmp[..n])?;
            }
            Ok(n as u64)
        }
        SYS_INPUT_WAIT => {
            let timeout_ns = regs.arg(0);
            // Reaching this syscall at all means the guest is running again, so
            // any previous park is over.
            state.pending_input_wait = false;
            if state.input.is_empty() {
                // The platform parks the guest and rewinds the instruction
                // pointer, so this syscall runs again once the wait is over.
                // Until then the honest answer is "nothing yet", not "here is an
                // event".
                state.pending_input_wait = true;
                state.pending_sleep = Some(Sleep {
                    deadline_ns: timeout_ns,
                    want_remaining: false,
                });
                return Ok(0);
            }
            Ok(1)
        }
        SYS_SYNC_FS => {
            // The platform performs the write-out and records what it did.
            state.sync = Some(crate::persist::SyncStats::default());
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
            state.pending_mmap.push(MmapRequest {
                addr: got,
                len,
                prot,
                flags,
            });
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
                    // Same open-file description as `write`, so a vectored
                    // write continues from the same place.
                    let pos = fds.offset(fd).ok_or(Errno::Badf)?;
                    state.vfs.write(ino, pos, &data)?;
                    fds.set_offset(fd, pos + data.len() as u64);
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
        SYS_GETRANDOM => {
            let p = regs.ptr(0)?;
            let len = regs.len(1)?;
            let mut out = Vec::with_capacity(len);
            let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
            for _ in 0..len {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
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
            let id = state
                .display
                .create(regs.arg(0) as u32, regs.arg(1) as u32)?;
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
            state
                .display
                .move_to(regs.arg(0) as u32, regs.arg(1) as i32, regs.arg(2) as i32)?;
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
            fb.draw_text(
                regs.arg(1) as i32,
                regs.arg(2) as i32,
                &text,
                regs.arg(3) as u32,
                bg,
            );
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
            fs_base: 0,
            fs_set: false,
            display: crate::gfx::Display::default(),
            frame: Vec::new(),
            clock: crate::clock::Clock::default(),
            signals: crate::signal::SignalTable::new(),
            input: crate::input::InputQueue::new(),
            cwd: "/".to_string(),
            umask: 0o022,
            frame_counter: 0,
            pending_sleep: None,
            pending_input_wait: false,
            input_fd: None,
            sync: None,
        }
    }

    /// Current time as a `timespec`, used for `stat` timestamps.
    pub fn now(&self) -> crate::clock::Timespec {
        self.clock
            .now(crate::clock::CLOCK_REALTIME)
            .unwrap_or_default()
    }

    /// Resolves a guest path against the current working directory.
    ///
    /// An absolute path is used as given; a relative one is joined onto `cwd`.
    /// `.` and `..` are left for `Vfs::normalize` to resolve, so this cannot be
    /// tricked into escaping the root.
    pub fn abs_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            return path.to_string();
        }
        if self.cwd == "/" {
            return format!("/{path}");
        }
        format!("{}/{path}", self.cwd.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::SimMem;
    use crate::space::AddressSpace;
    use crate::vfs::{Ino, Stat};

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
                .map_anon(
                    0x1000_0000,
                    region_pages * crate::PAGE_SIZE as u64,
                    crate::addr::Perms::RWX,
                )
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
                self.space
                    .unmap_range(target, len)
                    .map_err(|_| Errno::Inval)?;
            }
            self.space
                .map_anon(target, len, perms)
                .map_err(|_| Errno::NoMem)?;
            Ok(target)
        }

        fn unmap(&mut self, addr: u64, len: u64) -> Result<(), Errno> {
            self.space
                .unmap_range(addr, len)
                .map_err(|_| Errno::Inval)?;
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
                self.space
                    .table
                    .protect(vpage, perms)
                    .map_err(|_| Errno::Inval)?;
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

    /// The register a real guest leaves behind for `dirfd = AT_FDCWD`.
    ///
    /// `minic` declares `dirfd` as a C `int`, so only the low 32 bits of the
    /// argument register are written and the sentinel arrives zero-extended.
    /// Tests must use this form rather than a sign-extended literal, or they
    /// pass while every real guest gets `EBADF`.
    fn at_fdcwd() -> u64 {
        AT_FDCWD as i32 as u32 as u64
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

        // Rewind with lseek and read.
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let r = Registers::new(SYS_READ).with_args([fd, 0x1000_0200, 3, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));
        assert_eq!(g.read(0x1000_0200, 3).unwrap(), b"abc".to_vec());

        let r = Registers::new(SYS_CLOSE).with_args([fd, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        // Second close fails.
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Badf));
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
        let r = Registers::new(SYS_OPENAT).with_args([at_fdcwd(), 0x1000_0000, 0, 0, 0, 0]);
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
        let r = Registers::new(SYS_OPENAT).with_args([at_fdcwd(), 0x1000_0000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
    }

    #[test]
    fn a_32_bit_signed_argument_is_read_as_an_int() {
        // Regression: `dirfd` is a C `int`, so a guest leaves `AT_FDCWD` in the
        // low half of the register with the high half clear. Reading it as a
        // 64-bit integer compared against a sign-extended sentinel misses, the
        // call is taken to be relative to a descriptor that does not exist, and
        // every `open`/`stat`/`unlink` in the guest fails with `EBADF`.
        assert_eq!(0x0000_0000_ffff_ff9cu64 as i32, AT_FDCWD as i32);
        let regs = Registers::new(SYS_OPENAT).with_args([at_fdcwd(), 0, 0, 0, 0, 0]);
        assert_eq!(regs.arg_i32(0), AT_FDCWD as i32);
        // The raw register still looks like a large positive number, which is
        // exactly why the raw accessor must not be used for signed arguments.
        assert!(regs.arg(0) > 0);
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
        assert_eq!(
            g.read(0x1000_0000, 8).unwrap(),
            0x5000u64.to_ne_bytes().to_vec()
        );
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

        let r = Registers::new(SYS_MMAP).with_args([
            0,
            0x10000,
            (PROT_READ | PROT_WRITE) as u64,
            MAP_ANONYMOUS as u64,
            0,
            0,
        ]);
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
        let r = Registers::new(SYS_MMAP).with_args([
            0,
            0,
            PROT_READ as u64,
            MAP_ANONYMOUS as u64,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
    }

    #[test]
    fn munmap_removes_the_mapping() {
        let vfs: &'static mut Vfs = Box::leak(Box::new(Vfs::new()));
        let mut s = GuestState::new(vfs);
        let mut f = FdTable::new();
        let mut g = SimGuest::new(256);

        let r = Registers::new(SYS_MMAP).with_args([
            0,
            0x1000,
            (PROT_READ | PROT_WRITE) as u64,
            MAP_ANONYMOUS as u64,
            0,
            0,
        ]);
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
            target,
            0x2000,
            (PROT_READ | PROT_WRITE) as u64,
            (MAP_ANONYMOUS | MAP_FIXED) as u64,
            0,
            0,
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
        let r = Registers::new(SYS_MMAP).with_args([
            0,
            0x1000,
            PROT_READ as u64,
            (MAP_ANONYMOUS | MAP_FIXED) as u64,
            0,
            0,
        ]);
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
        let r = Registers::new(SYS_MMAP).with_args([
            0,
            0x10_00000,
            (PROT_READ | PROT_WRITE) as u64,
            MAP_ANONYMOUS as u64,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoMem));
        assert!(
            s.pending_mmap.is_empty(),
            "a failed mmap must not be recorded"
        );
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
        let r = Registers::new(SYS_MPROTECT).with_args([
            base,
            0x2000,
            (PROT_READ | PROT_WRITE | PROT_EXEC) as u64,
            0,
            0,
            0,
        ]);
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

        let misaligned =
            Registers::new(SYS_MPROTECT).with_args([base + 1, 0x1000, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(
            dispatch(&misaligned, &mut g, &mut s, &mut f),
            Err(Errno::Inval)
        );

        let zero_len = Registers::new(SYS_MPROTECT).with_args([base, 0, PROT_READ as u64, 0, 0, 0]);
        assert_eq!(
            dispatch(&zero_len, &mut g, &mut s, &mut f),
            Err(Errno::Inval)
        );

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
        let r =
            Registers::new(SYS_MPROTECT).with_args([base, 0x1000_0000, PROT_READ as u64, 0, 0, 0]);
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

    // ---- Offsets, sharing and positioning ---------------------------------

    /// Opens `/f` with `O_RDWR|O_CREAT` and returns the descriptor.
    fn open_file(g: &mut SimGuest, s: &mut GuestState<'_>, f: &mut FdTable, path: &str) -> u64 {
        put_str(g, 0x1000_0000, path);
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0o102, 0, 0, 0, 0]);
        dispatch(&r, g, s, f).unwrap()
    }

    #[test]
    fn lseek_moves_the_offset_and_rejects_a_negative_result() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"hello").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 5, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(5));

        // SEEK_SET is absolute.
        let r = Registers::new(SYS_LSEEK).with_args([fd, 2, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(2));

        // SEEK_CUR is relative to where we just landed.
        let r = Registers::new(SYS_LSEEK).with_args([fd, 1, SEEK_CUR as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));

        // SEEK_END is relative to the file size.
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_END as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(5));

        // Seeking before the start is invalid, and leaves the offset alone.
        let r = Registers::new(SYS_LSEEK).with_args([fd, (-1i64) as u64, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));

        // An unknown `whence` is rejected.
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, 9, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
    }

    #[test]
    fn dup_shares_one_offset_so_reads_continue_across_both_descriptors() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"abcdef").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 6, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(6));

        let r = Registers::new(SYS_DUP).with_args([fd, 0, 0, 0, 0, 0]);
        let fd2 = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert_ne!(fd, fd2);

        // Rewind once; both descriptors follow it because they share.
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));

        // Two bytes through the original, the rest through the copy.
        let r = Registers::new(SYS_READ).with_args([fd, 0x1000_0200, 2, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(2));
        assert_eq!(g.read(0x1000_0200, 2).unwrap(), b"ab".to_vec());
        let r = Registers::new(SYS_READ).with_args([fd2, 0x1000_0300, 4, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(4));
        assert_eq!(g.read(0x1000_0300, 4).unwrap(), b"cdef".to_vec());

        // Closing one descriptor does not disturb the other.
        let r = Registers::new(SYS_CLOSE).with_args([fd, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let r = Registers::new(SYS_READ).with_args([fd2, 0x1000_0400, 4, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
    }

    #[test]
    fn pread_and_pwrite_do_not_move_the_offset() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"abcdef").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 6, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(6));
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        g.write(0x1000_0100, b"bcd").unwrap();
        let r = Registers::new(SYS_PWRITE64).with_args([fd, 0x1000_0100, 3, 1, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));

        // The descriptor offset is still zero, so this reads from the start.
        let r = Registers::new(SYS_PREAD64).with_args([fd, 0x1000_0200, 3, 1, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));
        assert_eq!(g.read(0x1000_0200, 3).unwrap(), b"bcd".to_vec());
        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_CUR as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
    }

    #[test]
    fn append_writes_always_land_at_the_end() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"one").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 3, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));

        // Reopen with O_APPEND and write from offset zero: the bytes must be
        // added after the existing content rather than replacing it.
        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0o2001, 0, 0, 0, 0]);
        let app = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        g.write(0x1000_0100, b"two").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([app, 0x1000_0100, 3, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(3));

        let r = Registers::new(SYS_LSEEK).with_args([fd, 0, SEEK_SET as u64, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let r = Registers::new(SYS_READ).with_args([fd, 0x1000_0200, 6, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(6));
        assert_eq!(g.read(0x1000_0200, 6).unwrap(), b"onetwo".to_vec());
    }

    #[test]
    fn ftruncate_shortens_and_zero_fills() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"abcdef").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 6, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(6));

        let r = Registers::new(SYS_FTRUNCATE).with_args([fd, 3, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(
            s.vfs
                .read(Ino(s.vfs.lookup("/f").unwrap().0), 0, 32)
                .unwrap(),
            b"abc".to_vec()
        );

        // Extending zero-fills rather than leaving stale bytes.
        let r = Registers::new(SYS_FTRUNCATE).with_args([fd, 5, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(
            s.vfs
                .read(Ino(s.vfs.lookup("/f").unwrap().0), 0, 32)
                .unwrap(),
            b"abc\0\0".to_vec()
        );
    }

    // ---- Metadata ----------------------------------------------------------

    #[test]
    fn stat_reports_the_size_and_type_of_a_file() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"hello").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 5, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(5));

        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_STAT).with_args([0x1000_0000, 0x1000_0500, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0500, Stat::BYTE_LEN).unwrap();
        let st = Stat::from_bytes(&buf).unwrap();
        assert_eq!(st.size, 5);
        assert!(
            st.mode & 0o170000 == 0o100000,
            "regular file bit must be set"
        );
        assert_eq!(st.nlink, 1);

        // fstat on the descriptor sees the same thing.
        let r = Registers::new(SYS_FSTAT).with_args([fd, 0x1000_0600, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0600, Stat::BYTE_LEN).unwrap();
        assert_eq!(Stat::from_bytes(&buf).unwrap().size, 5);

        // A missing path is still ENOENT.
        put_str(&mut g, 0x1000_0000, "/nope");
        let r = Registers::new(SYS_STAT).with_args([0x1000_0000, 0x1000_0700, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
    }

    #[test]
    fn newfstatat_requires_the_current_directory() {
        let (mut g, mut s, mut f) = harness(64);
        open_file(&mut g, &mut s, &mut f, "/f");
        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_NEWFSTATAT).with_args([
            at_fdcwd(),
            0x1000_0000,
            0x1000_0800,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        // Any other directory descriptor is refused rather than guessed at.
        let r = Registers::new(SYS_NEWFSTATAT).with_args([3, 0x1000_0000, 0x1000_0800, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Badf));
    }

    #[test]
    fn statx_reports_the_same_size_in_the_statx_layout() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        g.write(0x1000_0100, b"hello").unwrap();
        let r = Registers::new(SYS_WRITE).with_args([fd, 0x1000_0100, 5, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(5));

        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_STATX).with_args([
            at_fdcwd(),
            0x1000_0000,
            0x1000_0900,
            0,
            0x7ff,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0900, 112).unwrap();
        let mask = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_ne!(mask & 0x200, 0, "stx_size must be reported");
        // stx_size lives at offset 40, not in the early header fields.
        assert_eq!(u64::from_le_bytes(buf[40..48].try_into().unwrap()), 5);
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64,
            s.vfs
                .stat(Ino(s.vfs.lookup("/f").unwrap().0), s.now())
                .unwrap()
                .blksize
        );
    }

    #[test]
    fn getdents_walks_a_directory_then_stops() {
        let (mut g, mut s, mut f) = harness(64);
        for n in ["/a", "/b", "/c"] {
            open_file(&mut g, &mut s, &mut f, n);
        }
        put_str(&mut g, 0x1000_0000, "/");
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0o200000, 0, 0, 0, 0]);
        let dir = dispatch(&r, &mut g, &mut s, &mut f).unwrap();

        let mut names = Vec::new();
        for _ in 0..4 {
            let r = Registers::new(SYS_GETDENTS).with_args([dir, 0x1000_0a00, 512, 0, 0, 0]);
            let n = dispatch(&r, &mut g, &mut s, &mut f).unwrap() as usize;
            if n == 0 {
                break;
            }
            let buf = g.read(0x1000_0a00, n).unwrap();
            let mut off = 0usize;
            while off + DIRENT_REC <= buf.len() {
                let reclen =
                    u16::from_le_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                if reclen == 0 {
                    break;
                }
                let nstart = off + DIRENT_REC;
                let nend = buf[nstart..off + reclen]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap();
                names.push(String::from_utf8_lossy(&buf[nstart..nstart + nend]).into_owned());
                off += reclen;
            }
        }
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn getdents_on_a_file_is_notdir() {
        let (mut g, mut s, mut f) = harness(64);
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        let r = Registers::new(SYS_GETDENTS).with_args([fd, 0x1000_0a00, 512, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NotDir));
    }

    // ---- Directories and the working directory ----------------------------

    #[test]
    fn relative_paths_resolve_against_the_working_directory() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_MKDIR).with_args([0x1000_0000, 0o755, 0, 0, 0, 0]);
        put_str(&mut g, 0x1000_0000, "/dir");
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));

        put_str(&mut g, 0x1000_0000, "/dir");
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Exist));

        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_CHDIR).with_args([0x1000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.cwd, "/dir");

        // A relative create now lands inside the directory.
        put_str(&mut g, 0x1000_0000, "rel");
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0o102, 0, 0, 0, 0]);
        assert!(dispatch(&r, &mut g, &mut s, &mut f).unwrap() >= 3);
        assert!(s.vfs.lookup("/dir/rel").is_ok());

        // getcwd reports it back with a NUL.
        let r = Registers::new(SYS_GETCWD).with_args([0x1000_0b00, 64, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(5));
        assert_eq!(g.read(0x1000_0b00, 5).unwrap(), b"/dir\0".to_vec());

        // Too small a buffer is a range error, not a truncation.
        let r = Registers::new(SYS_GETCWD).with_args([0x1000_0b00, 2, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Range));
    }

    #[test]
    fn chdir_to_a_file_is_notdir_and_to_nothing_is_noent() {
        let (mut g, mut s, mut f) = harness(64);
        open_file(&mut g, &mut s, &mut f, "/f");
        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_CHDIR).with_args([0x1000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NotDir));
        put_str(&mut g, 0x1000_0000, "/missing");
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NoEnt));
    }

    #[test]
    fn unlink_and_rmdir_remove_the_right_thing() {
        let (mut g, mut s, mut f) = harness(64);
        open_file(&mut g, &mut s, &mut f, "/f");
        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_MKDIR).with_args([0x1000_0000, 0o755, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));

        // A directory cannot be unlinked, only removed with rmdir.
        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_UNLINK).with_args([0x1000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::IsDir));

        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_UNLINK).with_args([0x1000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert!(s.vfs.lookup("/f").is_err());

        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_RMDIR).with_args([0x1000_0000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert!(s.vfs.lookup("/dir").is_err());
    }

    #[test]
    fn unlinkat_honours_the_removedir_flag() {
        let (mut g, mut s, mut f) = harness(64);
        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_MKDIR).with_args([0x1000_0000, 0o755, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_UNLINKAT).with_args([
            at_fdcwd(),
            0x1000_0000,
            AT_REMOVEDIR as u64,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert!(s.vfs.lookup("/dir").is_err());
    }

    #[test]
    fn openat_with_a_directory_descriptor_needs_a_directory() {
        let (mut g, mut s, mut f) = harness(64);
        open_file(&mut g, &mut s, &mut f, "/f");
        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_MKDIR).with_args([0x1000_0000, 0o755, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        put_str(&mut g, 0x1000_0000, "/dir");
        let r = Registers::new(SYS_OPEN).with_args([0x1000_0000, 0o200000, 0, 0, 0, 0]);
        let dir = dispatch(&r, &mut g, &mut s, &mut f).unwrap();

        // A real directory descriptor is accepted.
        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_OPENAT).with_args([dir, 0x1000_0000, 0o110, 0, 0, 0]);
        assert!(dispatch(&r, &mut g, &mut s, &mut f).unwrap() >= 3);

        // A regular file is not.
        let r = Registers::new(SYS_OPENAT).with_args([3, 0x1000_0000, 0o110, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::NotDir));
        // Neither is a closed descriptor.
        let r = Registers::new(SYS_OPENAT).with_args([999, 0x1000_0000, 0o110, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Badf));
    }

    #[test]
    fn umask_masks_new_file_modes_and_returns_the_previous_value() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_UMASK).with_args([0o077, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0o022));

        put_str(&mut g, 0x1000_0000, "/m");
        let r = Registers::new(SYS_MKDIR).with_args([0x1000_0000, 0o777, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let ino = s.vfs.lookup("/m").unwrap();
        assert_eq!(s.vfs.get(ino).unwrap().mode, 0o700);

        // Setting it again reports the old mask.
        let r = Registers::new(SYS_UMASK).with_args([0o022, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0o077));
    }

    #[test]
    fn chmod_sets_the_mode_explicitly() {
        let (mut g, mut s, mut f) = harness(64);
        open_file(&mut g, &mut s, &mut f, "/f");
        put_str(&mut g, 0x1000_0000, "/f");
        let r = Registers::new(SYS_CHMOD).with_args([0x1000_0000, 0o644, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.vfs.get(s.vfs.lookup("/f").unwrap()).unwrap().mode, 0o644);
    }

    #[test]
    fn uname_reports_five_nul_terminated_fields() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_UNAME).with_args([0x1000_0c00, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0c00, 5 * 65).unwrap();
        assert_eq!(&buf[0..5], b"Linux");
        assert_eq!(&buf[65..69], b"myos");
        // Every field must terminate inside its own 65 bytes.
        for i in 0..5 {
            let field = &buf[i * 65..(i + 1) * 65];
            assert!(field.iter().any(|&b| b == 0), "field {i} is not terminated");
        }
    }

    // ---- Clock -------------------------------------------------------------

    #[test]
    fn clock_gettime_tracks_the_monotonic_clock() {
        let (mut g, mut s, mut f) = harness(64);
        s.clock = crate::clock::Clock::new(1_000_000_000, 0);
        s.clock.advance_to(1_500_000_000);

        let r = Registers::new(SYS_CLOCK_GETTIME).with_args([
            crate::clock::CLOCK_MONOTONIC as u64,
            0x1000_0d00,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0d00, 16).unwrap();
        let ts = crate::clock::Timespec::from_le_bytes(&buf).unwrap();
        assert_eq!(ts.to_nanos(), 1_500_000_000);

        // Wall time is independent of the monotonic base.
        let r = Registers::new(SYS_CLOCK_GETTIME).with_args([
            crate::clock::CLOCK_REALTIME as u64,
            0x1000_0d00,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0d00, 16).unwrap();
        assert_eq!(
            crate::clock::Timespec::from_le_bytes(&buf)
                .unwrap()
                .to_nanos(),
            2_500_000_000
        );

        // An unknown clock id is rejected.
        let r = Registers::new(SYS_CLOCK_GETTIME).with_args([999, 0x1000_0d00, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
    }

    #[test]
    fn clock_getres_reports_the_resolution_and_gettimeofday_the_wall_clock() {
        let (mut g, mut s, mut f) = harness(64);
        s.clock = crate::clock::Clock::new(3_250_000_000, 0);
        let r = Registers::new(SYS_CLOCK_GETRES).with_args([
            crate::clock::CLOCK_MONOTONIC as u64,
            0x1000_0e00,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0e00, 16).unwrap();
        assert_eq!(
            crate::clock::Timespec::from_le_bytes(&buf)
                .unwrap()
                .to_nanos(),
            crate::clock::CLOCK_RESOLUTION_NS
        );

        let r = Registers::new(SYS_GETTIMEOFDAY).with_args([0x1000_0e00, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let buf = g.read(0x1000_0e00, 16).unwrap();
        let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(sec * 1_000_000 + usec, 3_250_000);

        // Both pointers are optional.
        let r = Registers::new(SYS_GETTIMEOFDAY).with_args([0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
    }

    #[test]
    fn nanosleep_records_a_deadline_for_the_platform() {
        let (mut g, mut s, mut f) = harness(64);
        let want = crate::clock::Timespec::new(0, 5_000_000);
        g.write(0x1000_0f00, &want.to_le_bytes()).unwrap();
        let r = Registers::new(SYS_NANOSLEEP).with_args([0x1000_0f00, 0x1000_0f40, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let sleep = s
            .pending_sleep
            .expect("the platform was not asked to sleep");
        assert_eq!(sleep.deadline_ns, 5_000_000);
        assert!(sleep.want_remaining);

        // `clock_nanosleep` shifts the arguments by one and is absolute on the
        // clock it names.
        let r = Registers::new(SYS_CLOCK_NANOSLEEP).with_args([
            crate::clock::CLOCK_REALTIME as u64,
            0x1000_0f00,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let sleep = s.pending_sleep.unwrap();
        assert_eq!(sleep.deadline_ns, 5_000_000);
        assert!(!sleep.want_remaining);
    }

    // ---- Signals -----------------------------------------------------------

    #[test]
    fn rt_sigaction_installs_and_reports_a_handler() {
        let (mut g, mut s, mut f) = harness(64);
        let mut act = [0u8; 32];
        act[0..8].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        act[8..16].copy_from_slice(&crate::signal::SA_RESTART.to_le_bytes());
        act[16..24].copy_from_slice(&0x4000_200u64.to_le_bytes());
        act[24..32].copy_from_slice(&0x0000_000f_0000_0000u64.to_le_bytes());
        g.write(0x1000_1000, &act).unwrap();

        let r = Registers::new(SYS_RT_SIGACTION).with_args([
            crate::signal::SIGINT as u64,
            0x1000_1000,
            0x1000_1100,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        let installed = s.signals.action(crate::signal::SIGINT);
        assert_eq!(installed.handler, 0xdead_beef);
        assert!(installed.flags & crate::signal::SA_RESTART != 0);
        assert_eq!(installed.mask, 0x0000_000f_0000_0000);

        // Reading it back reports the default first, since nothing was there.
        let r = Registers::new(SYS_RT_SIGACTION).with_args([
            crate::signal::SIGINT as u64,
            0,
            0x1000_1100,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.signals.action(crate::signal::SIGINT).handler, 0xdead_beef);

        // Out-of-range signal numbers are rejected.
        let r = Registers::new(SYS_RT_SIGACTION).with_args([0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
        let r = Registers::new(SYS_RT_SIGACTION).with_args([65, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));

        // A handler with no restorer is refused: it would return to nothing.
        // Ignoring the default disposition needs no restorer, so it stays legal.
        let mut act = [0u8; 32];
        act[0..8].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        g.write(0x1000_1000, &act).unwrap();
        let r = Registers::new(SYS_RT_SIGACTION).with_args([
            crate::signal::SIGINT as u64,
            0x1000_1000,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Inval));
        assert_eq!(
            s.signals.action(crate::signal::SIGINT).handler,
            0xdead_beef,
            "the refused install left the previous handler alone"
        );
        let mut act = [0u8; 32];
        act[0..8].copy_from_slice(&1u64.to_le_bytes());
        g.write(0x1000_1000, &act).unwrap();
        let r = Registers::new(SYS_RT_SIGACTION).with_args([
            crate::signal::SIGINT as u64,
            0x1000_1000,
            0,
            0,
            0,
            0,
        ]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.signals.action(crate::signal::SIGINT).handler, 1);
    }

    #[test]
    fn rt_sigprocmask_reports_the_old_mask_and_applies_the_new_one() {
        let (mut g, mut s, mut f) = harness(64);
        let set = 0x0000_0000_0000_0003u64;
        g.write(0x1000_1200, &set.to_ne_bytes()).unwrap();
        // SIG_BLOCK is 0.
        let r =
            Registers::new(SYS_RT_SIGPROCMASK).with_args([0, 0x1000_1200, 0x1000_1300, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.signals.blocked(), set);
        let old = g.read(0x1000_1300, 8).unwrap();
        assert_eq!(u64::from_ne_bytes(old.try_into().unwrap()), 0);

        // SIG_UNBLOCK is 1 and clears exactly those bits.
        let r = Registers::new(SYS_RT_SIGPROCMASK).with_args([1, 0x1000_1200, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert_eq!(s.signals.blocked(), 0);
    }

    // ---- Input -------------------------------------------------------------

    #[test]
    fn input_read_drains_the_queue_one_event_at_a_time() {
        let (mut g, mut s, mut f) = harness(64);
        f.alloc_kind(FdKind::Input);
        s.input.push(crate::input::Event::key_down(
            1,
            0x41,
            crate::input::Mods::default(),
            false,
        ));
        s.input.push(crate::input::Event::key_up(
            1,
            0x41,
            crate::input::Mods::default(),
        ));

        let r = Registers::new(SYS_INPUT_READ).with_args([3, 0x1000_1400, 512, 0, 0, 0]);
        let n = dispatch(&r, &mut g, &mut s, &mut f).unwrap() as usize;
        assert_eq!(n, 2 * crate::input::EVENT_SIZE);
        let buf = g.read(0x1000_1400, n).unwrap();
        assert_eq!(
            &buf[0..4],
            &1u32.to_le_bytes(),
            "first event is the key press"
        );

        // A read on an empty queue reports zero rather than blocking.
        let r = Registers::new(SYS_INPUT_READ).with_args([3, 0x1000_1400, 512, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));

        // A regular file is not an input stream.
        let fd = open_file(&mut g, &mut s, &mut f, "/f");
        let r = Registers::new(SYS_INPUT_READ).with_args([fd, 0x1000_1400, 512, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Err(Errno::Badf));
    }

    #[test]
    fn input_fd_is_allocated_once_and_reused() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_INPUT_FD).with_args([0, 0, 0, 0, 0, 0]);
        let fd = dispatch(&r, &mut g, &mut s, &mut f).unwrap();
        assert!(fd >= 3, "stdio must be reserved");
        assert_eq!(s.input_fd, Some(fd as u32));
        assert!(matches!(f.get(Fd(fd as u32)).unwrap(), FdKind::Input));

        // Asking again returns the same descriptor rather than a new one.
        let r = Registers::new(SYS_INPUT_FD).with_args([0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(fd));
        assert_eq!(f.len(), 4, "stdin, stdout, stderr and one input stream");
    }

    #[test]
    fn sync_asks_the_platform_to_write_the_filesystem_out() {
        let (mut g, mut s, mut f) = harness(64);
        let r = Registers::new(SYS_SYNC_FS).with_args([0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        // The core cannot touch a disk, so it records the request and lets the
        // platform carry it out.
        assert_eq!(s.sync, Some(crate::persist::SyncStats::default()));
    }

    #[test]
    fn input_wait_parks_the_guest_only_when_nothing_is_queued() {
        let (mut g, mut s, mut f) = harness(64);
        f.alloc_kind(FdKind::Input);

        // Nothing queued: the guest is parked and told there is nothing yet.
        let r = Registers::new(SYS_INPUT_WAIT).with_args([0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(0));
        assert!(s.pending_input_wait);
        assert_eq!(s.pending_sleep.unwrap().deadline_ns, 0);

        // An event makes the wait unnecessary.
        s.input.push(crate::input::Event::simple(
            crate::input::EventKind::Expose,
            1,
        ));
        let r = Registers::new(SYS_INPUT_WAIT).with_args([16_000_000, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&r, &mut g, &mut s, &mut f), Ok(1));
        assert!(!s.pending_input_wait);
    }
}
