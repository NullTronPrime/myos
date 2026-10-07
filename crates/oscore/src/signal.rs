//! Guest signal disposition, masking, and the `rt_sigframe` the kernel builds.
//!
//! Everything here is pure: it computes the bytes of a signal frame and the
//! register state the guest should resume with, but never touches memory. The
//! platform layer writes the frame and sets the registers.

use std::collections::BTreeMap;

/// Signal numbers this kernel knows about.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;

/// `siginfo_t::si_code` for a signal the kernel raised itself.
pub const SI_KERNEL: i32 = 0x80;
/// `siginfo_t::si_code` for a signal sent by `kill`.
pub const SI_USER: i32 = 0;
/// `si_code` for an invalid memory reference.
pub const SEGV_MAPERR: i32 = 0;
/// `si_code` for a write to a read-only mapping.
pub const SEGV_ACCERR: i32 = 2;

/// `sa_handler`/`sa_sigaction` offset: 1.
pub const SA_SIGINFO: u64 = 0x0000_0004;
/// Set `SA_RESTART` so interrupted syscalls restart.
pub const SA_RESTART: u64 = 0x1000_0000;
/// Signal number shifted into `sa_flags`.
pub const SA_SIGINFO_SHIFT: u32 = 8;

/// Offset of the `ucontext_t` inside an `rt_sigframe` (past `pretcode`).
pub const UC_OFFSET: u64 = 8;
/// Offset of `uc_mcontext` inside a glibc `ucontext_t` on x86-64.
pub const UC_MCONTEXT_OFFSET: u64 = 40;
/// Byte size of glibc's `ucontext_t` on x86-64.
pub const UC_SIZE: u64 = 968;
/// Byte size of `siginfo_t` on x86-64.
pub const SIGINFO_SIZE: u64 = 128;
/// Offset of the `siginfo_t` inside an `rt_sigframe`.
pub const INFO_OFFSET: u64 = UC_OFFSET + UC_SIZE;

/// Total size of the frame the kernel pushes onto the guest stack.
pub const FRAME_SIZE: u64 = INFO_OFFSET + SIGINFO_SIZE;
/// Alignment the frame starts on.
pub const FRAME_ALIGN: u64 = 16;

/// Indices into `mcontext_t::gregs`, matching glibc's `REG_*`.
pub const GREG_R8: usize = 0;
pub const GREG_R9: usize = 1;
pub const GREG_R10: usize = 2;
pub const GREG_R11: usize = 3;
pub const GREG_R12: usize = 4;
pub const GREG_R13: usize = 5;
pub const GREG_R14: usize = 6;
pub const GREG_R15: usize = 7;
pub const GREG_RDI: usize = 8;
pub const GREG_RSI: usize = 9;
pub const GREG_RBP: usize = 10;
pub const GREG_RBX: usize = 11;
pub const GREG_RDX: usize = 12;
pub const GREG_RAX: usize = 13;
pub const GREG_RCX: usize = 14;
pub const GREG_RSP: usize = 15;
pub const GREG_RIP: usize = 16;
pub const GREG_EFL: usize = 17;
/// Packs the `cs`, `gs` and `fs` *selectors* (not their bases). A real kernel
/// saves this and restores it on `sigreturn`; leaving it zero makes the return
/// pop to a null code selector and fault.
pub const GREG_CSGSFS: usize = 18;
pub const GREG_OLDMASK: usize = 21;
pub const GREG_CR2: usize = 22;

/// `uc_flags` a real x86-64 kernel sets: extended state present, and the signal
/// context carries the segment selectors.
pub const UC_SIGCONTEXT_XSTATE: u64 = 0x1;
pub const UC_SIGCONTEXT_SS: u64 = 0x2;
pub const UC_FP_XSTATE: u64 = 0x4;
pub const UC_DEFAULTS: u64 = UC_SIGCONTEXT_XSTATE | UC_SIGCONTEXT_SS | UC_FP_XSTATE;

/// Number of general registers saved in an `mcontext_t`.
pub const NGREG: usize = 23;

/// The general registers a signal frame saves and restores.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FrameRegs {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub rbx: u64,
    pub csgsfs: u64,
    pub oldmask: u64,
    pub cr2: u64,
}

impl FrameRegs {
    /// Reads register `index` from a `gregs` array of 23 little-endian u64s.
    pub fn from_gregs(gregs: &[u64; NGREG]) -> Self {
        let g = |i: usize| gregs.get(i).copied().unwrap_or(0);
        FrameRegs {
            r8: g(GREG_R8),
            r9: g(GREG_R9),
            r10: g(GREG_R10),
            r11: g(GREG_R11),
            r12: g(GREG_R12),
            r13: g(GREG_R13),
            r14: g(GREG_R14),
            r15: g(GREG_R15),
            rdi: g(GREG_RDI),
            rsi: g(GREG_RSI),
            rdx: g(GREG_RDX),
            rax: g(GREG_RAX),
            rcx: g(GREG_RCX),
            rbp: g(GREG_RBP),
            rsp: g(GREG_RSP),
            rip: g(GREG_RIP),
            eflags: g(GREG_EFL),
            rbx: g(GREG_RBX),
            csgsfs: g(GREG_CSGSFS),
            oldmask: g(GREG_OLDMASK),
            cr2: g(GREG_CR2),
        }
    }

    /// Writes every register into a `gregs` array.
    pub fn to_gregs(&self, gregs: &mut [u64; NGREG]) {
        gregs[0] = self.r8;
        gregs[1] = self.r9;
        gregs[2] = self.r10;
        gregs[3] = self.r11;
        gregs[4] = self.r12;
        gregs[5] = self.r13;
        gregs[6] = self.r14;
        gregs[7] = self.r15;
        gregs[8] = self.rdi;
        gregs[9] = self.rsi;
        gregs[10] = self.rbp;
        gregs[11] = self.rbx;
        gregs[12] = self.rdx;
        gregs[13] = self.rax;
        gregs[14] = self.rcx;
        gregs[15] = self.rsp;
        gregs[16] = self.rip;
        gregs[17] = self.eflags;
        gregs[18] = self.csgsfs;
        gregs[21] = self.oldmask;
        gregs[22] = self.cr2;
    }
}

/// A guest's installed handler for one signal.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SigAction {
    /// Handler address, or 0/`SIG_DFL`.
    pub handler: u64,
    /// `SA_*` flags.
    pub flags: u64,
    /// Address of the trampoline that issues `rt_sigreturn`.
    pub restorer: u64,
    /// Signals to block while this one runs.
    pub mask: u64,
}

impl SigAction {
    pub const DEFAULT: SigAction = SigAction {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };

    /// True when this action restores the default on delivery.
    pub fn is_reset(&self) -> bool {
        self.flags & 0x8000_0000 != 0
    }

    /// True when the action asks for a `siginfo_t*` argument.
    pub fn wants_siginfo(&self) -> bool {
        self.flags & SA_SIGINFO != 0
    }

    /// True when the action blocks the signal itself during delivery.
    pub fn no_defer(&self) -> bool {
        self.flags & 0x4000_0000 != 0
    }
}

/// `SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// A signal waiting to be delivered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pending {
    pub signum: i32,
    pub code: i32,
    /// `si_addr`, or the sender's pid for `SI_USER`.
    pub addr: u64,
}

impl Pending {
    pub fn kernel(signum: i32, code: i32, addr: u64) -> Self {
        Pending { signum, code, addr }
    }
}

/// Register set a signal is delivered with, plus what to restore.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Delivery {
    /// Stack pointer to resume the guest at.
    pub rsp: u64,
    /// Address the guest's next instruction should be, normally the handler or
    /// its restorer trampoline.
    pub rip: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    /// `rax` on entry to the handler.
    pub rax: u64,
}

/// Signal dispositions, the blocked mask, and the pending queue.
#[derive(Clone, Debug, Default)]
pub struct SignalTable {
    actions: BTreeMap<i32, SigAction>,
    blocked: u64,
    pending: Vec<Pending>,
}

impl SignalTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn action(&self, signum: i32) -> SigAction {
        self.actions
            .get(&signum)
            .copied()
            .unwrap_or(SigAction::DEFAULT)
    }

    pub fn set_action(&mut self, signum: i32, action: SigAction) {
        if action == SigAction::DEFAULT {
            self.actions.remove(&signum);
        } else {
            self.actions.insert(signum, action);
        }
    }

    pub fn blocked(&self) -> u64 {
        self.blocked
    }

    /// Applies a `rt_sigprocmask` change. Returns the previous mask.
    pub fn change_mask(&mut self, how: u64, set: u64) -> u64 {
        let old = self.blocked;
        // `SIG_BLOCK` = 0, `SIG_UNBLOCK` = 1, `SIG_SETMASK` = 2.
        self.blocked = match how {
            0 => old | set,
            1 => old & !set,
            _ => set,
        };
        old
    }

    pub fn queue(&mut self, p: Pending) {
        // A standard signal is not queued twice; it stays pending once.
        if !is_real_time(p.signum) && self.pending.iter().any(|q| q.signum == p.signum) {
            return;
        }
        self.pending.push(p);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// True when a signal is queued, whether or not it is currently blocked.
    pub fn is_pending(&self, signum: i32) -> bool {
        self.pending.iter().any(|p| p.signum == signum)
    }

    /// Removes and returns the lowest-numbered deliverable signal.
    ///
    /// Linux picks the lowest signal number rather than the oldest, so a
    /// flood of one signal cannot starve another.
    pub fn take_next(&mut self) -> Option<Pending> {
        let blocked = self.blocked;
        let idx = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, p)| blocked & bit(p.signum) == 0)
            .min_by_key(|(_, p)| p.signum)
            .map(|(i, _)| i)?;
        Some(self.pending.remove(idx))
    }

    /// Drops every disposition and the blocked mask, as `execve` does.
    pub fn reset(&mut self) {
        self.actions.clear();
        self.blocked = 0;
        self.pending.clear();
    }
}

/// True for the real-time signals, which queue rather than coalesce.
pub fn is_real_time(signum: i32) -> bool {
    (34..=64).contains(&signum)
}

/// The mask bit for a signal number.
pub fn bit(signum: i32) -> u64 {
    if (1..=64).contains(&signum) {
        1u64 << (signum - 1)
    } else {
        0
    }
}

/// Decodes a glibc `struct sigaction`.
pub fn decode_action(bytes: &[u8]) -> SigAction {
    if bytes.len() < 32 {
        return SigAction::DEFAULT;
    }
    let word = |i: usize| u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    SigAction {
        handler: word(0),
        flags: word(1),
        restorer: word(2),
        mask: word(3),
    }
}

/// Builds the byte image of an `rt_sigframe` and the registers to run the
/// handler with.
///
/// `stack` is the current guest stack pointer. The frame is placed below it, and
/// `sp` is the aligned address the handler starts on.
///
/// A guest handler must supply an `sa_restorer`, exactly as on a real kernel:
/// the handler returns to it, and it issues `rt_sigreturn`. Without one the
/// handler would have no way back, so `rt_sigaction` rejects the install rather
/// than building a frame the guest could never leave.
///
/// `rt_syscall_number` is the number that restorer uses for `rt_sigreturn`, and
/// is also recorded in the frame so the return path can be recognised.
pub fn build_frame(
    stack: u64,
    act: &SigAction,
    regs: &FrameRegs,
    sig: Pending,
    rt_syscall_number: u64,
) -> (Vec<u8>, Delivery) {
    let top = align_down(stack) - FRAME_SIZE;
    let sp = top;

    let mut frame = vec![0u8; FRAME_SIZE as usize];

    // `pretcode` holds the restorer address, as the kernel writes it.
    frame[0..8].copy_from_slice(&act.restorer.to_ne_bytes());

    let uc = UC_OFFSET as usize;
    // uc_flags, uc_link. The flags tell the guest's libc that the segment
    // selectors and extended state are in this context.
    frame[uc + 8..uc + 16].copy_from_slice(&UC_DEFAULTS.to_ne_bytes());

    // stack_t at uc+16: the guest stack the frame was pushed on.
    // `ss_flags` is `SS_DISABLE` (2) when the stack is not the one that was
    // interrupted, and 0 when it is. We always report the live stack, so the
    // saved `ss_sp`/`ss_size` describe it and the flag is clear.
    frame[uc + 16..uc + 24].copy_from_slice(&stack.to_ne_bytes());
    frame[uc + 24..uc + 28].copy_from_slice(&0u32.to_ne_bytes());
    frame[uc + 28..uc + 32].copy_from_slice(&0u32.to_ne_bytes());
    frame[uc + 32..uc + 40].copy_from_slice(&(FRAME_SIZE).to_ne_bytes());

    // mcontext_t: save every register, plus the mask to restore on return.
    let mc = (UC_OFFSET + UC_MCONTEXT_OFFSET) as usize;
    let mut gregs = [0u64; NGREG];
    regs.to_gregs(&mut gregs);
    // The signal being handled is blocked unless SA_NODEFER.
    let mask = if act.no_defer() {
        regs.oldmask
    } else {
        regs.oldmask | bit(sig.signum)
    };
    gregs[GREG_OLDMASK] = mask;
    gregs[GREG_CR2] = sig.addr;
    for (i, &v) in gregs.iter().enumerate() {
        frame[mc + i * 8..mc + i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
    }

    // siginfo_t.
    let info = INFO_OFFSET as usize;
    frame[info..info + 4].copy_from_slice(&(sig.signum as u32).to_ne_bytes());
    frame[info + 4..info + 8].copy_from_slice(&0u32.to_ne_bytes());
    frame[info + 8..info + 12].copy_from_slice(&(sig.code as i32).to_ne_bytes());
    frame[info + 16..info + 24].copy_from_slice(&sig.addr.to_ne_bytes());

    // Entry state: rdi = signum, rsi = &siginfo, rdx = &ucontext. `rax` is
    // cleared because a real handler starts there with no syscall result in it.
    let real_handler = act.handler != SIG_DFL && act.handler != SIG_IGN;
    let (rip, rax) = if real_handler {
        (act.handler, 0)
    } else {
        // Nothing is installed, so there is no handler to enter.
        (act.restorer, rt_syscall_number)
    };

    let delivery = Delivery {
        rsp: sp,
        rip,
        rdi: sig.signum as u64,
        rsi: sp + INFO_OFFSET,
        rdx: sp + UC_OFFSET,
        rax,
    };
    (frame, delivery)
}

fn align_down(v: u64) -> u64 {
    v & !(FRAME_ALIGN - 1)
}

/// Offsets of each saved register inside a frame, for the platform layer to
/// read the real bytes back out of guest memory.
pub fn reg_offsets() -> BTreeMap<usize, u64> {
    let mut out = BTreeMap::new();
    for i in 0..NGREG {
        out.insert(i, UC_OFFSET + UC_MCONTEXT_OFFSET + (i as u64) * 8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs() -> FrameRegs {
        FrameRegs {
            rip: 0x4000_10,
            rsp: 0x5000_0000,
            rax: 7,
            rdi: 1,
            rsi: 2,
            rdx: 3,
            rbp: 4,
            rbx: 5,
            ..Default::default()
        }
    }

    #[test]
    fn mask_bit_matches_signal_number() {
        assert_eq!(bit(1), 1);
        assert_eq!(bit(9), 1 << 8);
        assert_eq!(bit(64), 1 << 63);
        assert_eq!(bit(0), 0);
        assert_eq!(bit(65), 0);
    }

    #[test]
    fn real_time_signals_queue_but_standard_ones_coalesce() {
        let mut t = SignalTable::new();
        t.queue(Pending::kernel(SIGSEGV, SEGV_MAPERR, 0x10));
        t.queue(Pending::kernel(SIGSEGV, SEGV_MAPERR, 0x20));
        assert_eq!(t.pending_len(), 1, "a standard signal stays pending once");

        t.queue(Pending::kernel(35, SI_USER, 0));
        t.queue(Pending::kernel(35, SI_USER, 0));
        assert_eq!(t.pending_len(), 3, "real-time signals queue separately");
    }

    #[test]
    fn blocked_signals_are_not_taken_until_unblocked() {
        let mut t = SignalTable::new();
        t.queue(Pending::kernel(SIGINT, SI_KERNEL, 0));
        t.change_mask(0, bit(SIGINT));
        assert!(t.take_next().is_none());
        assert!(t.is_pending(SIGINT), "still pending, just not deliverable");
        t.change_mask(1, bit(SIGINT));
        assert_eq!(t.take_next().unwrap().signum, SIGINT);
    }

    #[test]
    fn lowest_signal_is_delivered_first() {
        let mut t = SignalTable::new();
        t.queue(Pending::kernel(SIGTERM, SI_KERNEL, 0));
        t.queue(Pending::kernel(SIGHUP, SI_KERNEL, 0));
        t.queue(Pending::kernel(SIGINT, SI_KERNEL, 0));
        let order: Vec<i32> = (0..3).map(|_| t.take_next().unwrap().signum).collect();
        assert_eq!(order, vec![SIGHUP, SIGINT, SIGTERM]);
    }

    #[test]
    fn mask_changes_follow_linux_semantics() {
        let mut t = SignalTable::new();
        assert_eq!(t.change_mask(0, bit(SIGINT)), 0);
        assert_eq!(t.blocked(), bit(SIGINT));
        assert_eq!(t.change_mask(2, bit(SIGUSR1)), bit(SIGINT));
        assert_eq!(t.change_mask(1, bit(SIGINT)), bit(SIGUSR1));
        assert_eq!(t.blocked(), bit(SIGUSR1));
    }

    #[test]
    fn execve_resets_dispositions_and_mask() {
        let mut t = SignalTable::new();
        t.set_action(
            SIGINT,
            SigAction {
                handler: 0x1234,
                ..SigAction::DEFAULT
            },
        );
        t.change_mask(0, bit(SIGUSR1));
        t.queue(Pending::kernel(SIGUSR2, SI_KERNEL, 0));
        t.reset();
        assert_eq!(t.action(SIGINT).handler, 0);
        assert_eq!(t.blocked(), 0);
        assert_eq!(t.pending_len(), 0);
    }

    #[test]
    fn set_and_get_round_trip_an_action() {
        let mut t = SignalTable::new();
        let act = SigAction {
            handler: 0xdead_beef,
            flags: SA_SIGINFO | SA_RESTART,
            restorer: 0x4000_50,
            mask: bit(SIGUSR1),
        };
        t.set_action(SIGILL, act);
        assert_eq!(t.action(SIGILL), act);
        t.set_action(SIGILL, SigAction::DEFAULT);
        assert_eq!(t.action(SIGILL), SigAction::DEFAULT);
    }

    #[test]
    fn decode_action_reads_a_glibc_sigaction() {
        let act = SigAction {
            handler: 0x40_1234,
            flags: SA_SIGINFO,
            restorer: 0x40_2000,
            mask: bit(SIGINT) | bit(SIGQUIT),
        };
        let mut bytes = Vec::new();
        for w in [act.handler, act.flags, act.restorer, act.mask] {
            bytes.extend_from_slice(&w.to_ne_bytes());
        }
        assert_eq!(decode_action(&bytes), act);
        assert_eq!(decode_action(&bytes[..8]), SigAction::DEFAULT);
    }

    #[test]
    fn frame_saves_every_register_the_guest_can_see() {
        let act = SigAction {
            handler: 0x4000_100,
            flags: SA_SIGINFO,
            restorer: 0x4000_200,
            mask: 0,
        };
        let r = regs();
        let (frame, _) = build_frame(
            r.rsp,
            &act,
            &r,
            Pending::kernel(SIGSEGV, SEGV_MAPERR, 0xbeef),
            15,
        );
        let mc = (UC_OFFSET + UC_MCONTEXT_OFFSET) as usize;
        let mut gregs = [0u64; NGREG];
        for i in 0..NGREG {
            gregs[i] = u64::from_ne_bytes(frame[mc + i * 8..mc + i * 8 + 8].try_into().unwrap());
        }
        let back = FrameRegs::from_gregs(&gregs);
        assert_eq!(back.rip, r.rip);
        assert_eq!(back.rsp, r.rsp);
        assert_eq!(back.rax, r.rax);
        assert_eq!(back.rdi, r.rdi);
    }

    #[test]
    fn frame_blocks_the_signal_being_delivered() {
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (frame, _) = build_frame(
            0x5000_0000,
            &act,
            &regs(),
            Pending::kernel(SIGSEGV, SEGV_MAPERR, 0),
            15,
        );
        let mc = (UC_OFFSET + UC_MCONTEXT_OFFSET) as usize;
        let old = u64::from_ne_bytes(
            frame[mc + GREG_OLDMASK * 8..mc + GREG_OLDMASK * 8 + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(old, bit(SIGSEGV));
    }

    #[test]
    fn nodefer_leaves_the_signal_unblocked_in_the_saved_mask() {
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            flags: 0x4000_0000,
            mask: 0,
        };
        let (frame, _) = build_frame(
            0x5000_0000,
            &act,
            &regs(),
            Pending::kernel(SIGSEGV, 0, 0),
            15,
        );
        let mc = (UC_OFFSET + UC_MCONTEXT_OFFSET) as usize;
        let old = u64::from_ne_bytes(
            frame[mc + GREG_OLDMASK * 8..mc + GREG_OLDMASK * 8 + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(old, 0);
    }

    #[test]
    fn handler_arguments_point_into_the_frame() {
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (_, d) = build_frame(
            0x5000_0000,
            &act,
            &regs(),
            Pending::kernel(SIGINT, 0, 0),
            15,
        );
        assert_eq!(d.rdi, SIGINT as u64);
        assert_eq!(d.rsi, d.rsp + INFO_OFFSET);
        assert_eq!(d.rdx, d.rsp + UC_OFFSET);
        assert_eq!(d.rax, 0, "the restorer runs, so rax is cleared");
    }

    #[test]
    fn frame_sits_below_the_guest_stack_and_stays_aligned() {
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (frame, d) = build_frame(
            0x5000_0000,
            &act,
            &regs(),
            Pending::kernel(SIGINT, 0, 0),
            15,
        );
        assert_eq!(d.rsp % FRAME_ALIGN, 0);
        assert!(d.rsp + FRAME_SIZE <= 0x5000_0000);
        assert_eq!(frame.len() as u64, FRAME_SIZE);
    }

    #[test]
    fn siginfo_carries_the_number_code_and_fault_address() {
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (frame, _) = build_frame(
            0x5000_0000,
            &act,
            &regs(),
            Pending::kernel(SIGSEGV, SEGV_ACCERR, 0xdead_beef),
            15,
        );
        let info = INFO_OFFSET as usize;
        let signo = i32::from_ne_bytes(frame[info..info + 4].try_into().unwrap());
        let code = i32::from_ne_bytes(frame[info + 8..info + 12].try_into().unwrap());
        let addr = u64::from_ne_bytes(frame[info + 16..info + 24].try_into().unwrap());
        assert_eq!(signo, SIGSEGV);
        assert_eq!(code, SEGV_ACCERR);
        assert_eq!(addr, 0xdead_beef);
    }

    #[test]
    fn a_real_handler_enters_with_rax_clear_and_a_null_one_at_the_restorer() {
        // A real handler starts with no syscall result in `rax`; the default
        // disposition has no handler to enter, so it starts at the restorer with
        // the return syscall's number in `rax`, which is what a guest resuming
        // from a default disposition expects to find.
        let real = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (_, d) = build_frame(
            0x5000_0000,
            &real,
            &regs(),
            Pending::kernel(SIGINT, 0, 0),
            15,
        );
        assert_eq!(d.rip, 0x4000_100, "a real handler is entered directly");
        assert_eq!(d.rax, 0);

        let default = SigAction {
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (_, d) = build_frame(
            0x5000_0000,
            &default,
            &regs(),
            Pending::kernel(SIGINT, 0, 0),
            15,
        );
        assert_eq!(d.rip, 0x4000_200, "nothing to enter, so the restorer runs");
        assert_eq!(d.rax, 15);
    }

    #[test]
    fn the_frame_carries_the_segment_selectors_and_flags() {
        // Without the selectors the return path pops to a null code selector and
        // faults, and `uc_flags` is what tells a guest's libc the context has
        // them.
        let mut r = regs();
        r.csgsfs = 0x2b00_0000_0000_0033;
        r.eflags = 0x246;
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (frame, _) = build_frame(0x5000_0000, &act, &r, Pending::kernel(SIGINT, 0, 0), 15);
        let word = |at: usize| u64::from_ne_bytes(frame[at..at + 8].try_into().unwrap());
        let mc = (UC_OFFSET + UC_MCONTEXT_OFFSET) as usize;
        assert_eq!(word(mc + GREG_CSGSFS * 8), 0x2b00_0000_0000_0033);
        assert_eq!(word(mc + GREG_EFL * 8), 0x246, "eflags survives the frame");
        assert_eq!(word(UC_OFFSET as usize + 8), UC_DEFAULTS);
    }

    #[test]
    fn saved_cr2_holds_the_faulting_address() {
        let act = SigAction {
            handler: 0x4000_100,
            restorer: 0x4000_200,
            ..SigAction::DEFAULT
        };
        let (frame, _) = build_frame(
            0x5000_0000,
            &act,
            &regs(),
            Pending::kernel(SIGSEGV, 0, 0xabc),
            15,
        );
        let mc = (UC_OFFSET + UC_MCONTEXT_OFFSET) as usize;
        let cr2 = u64::from_ne_bytes(
            frame[mc + GREG_CR2 * 8..mc + GREG_CR2 * 8 + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(cr2, 0xabc);
    }

    #[test]
    fn greg_round_trip_preserves_every_field() {
        let r = FrameRegs {
            r8: 1,
            r9: 2,
            r10: 3,
            r11: 4,
            r12: 5,
            r13: 6,
            r14: 7,
            r15: 8,
            rdi: 9,
            rsi: 10,
            rdx: 11,
            rax: 12,
            rcx: 13,
            rbp: 16,
            rbx: 17,
            rsp: 18,
            rip: 19,
            eflags: 0x246,
            csgsfs: 0x2b0000_0000_0033,
            oldmask: 0x30,
            cr2: 0x40,
        };
        let mut g = [0u64; NGREG];
        r.to_gregs(&mut g);
        assert_eq!(FrameRegs::from_gregs(&g), r);
    }

    #[test]
    fn reg_offsets_match_the_frame_layout() {
        let offs = reg_offsets();
        assert_eq!(offs[&GREG_RIP], UC_OFFSET + UC_MCONTEXT_OFFSET + 16 * 8);
        assert_eq!(offs[&GREG_RSP], UC_OFFSET + UC_MCONTEXT_OFFSET + 15 * 8);
    }
}
