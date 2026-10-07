//! Turning the pure [`oscore::signal`] model into a running guest handler.
//!
//! The signal rules — dispositions, the blocked mask, the pending queue, and
//! the layout of the frame handed to a handler — all live in `oscore`, where
//! they can be tested without a host. This module is the part that cannot be:
//! it reads a real `ucontext`, pushes a frame onto the guest's own stack, and
//! rewrites that context so the guest resumes *inside* its handler.
//!
//! Every guest address here is untrusted, so each is checked or written
//! through a helper that reports failure instead of faulting in turn.

use libc::{c_int, ucontext_t};

use oscore::signal::{
    build_frame, Delivery, FrameRegs, Pending, SigAction, SignalTable, FRAME_ALIGN, FRAME_SIZE,
    NGREG, SIG_DFL, SIG_IGN,
};
use oscore::syscall::SYS_RT_SIGRETURN;

/// `SIG_BLOCK`, as `rt_sigprocmask` spells it.
const SIG_BLOCK: u64 = 0;

/// `SIG_SETMASK`, as `rt_sigprocmask` spells it.
const SIG_SETMASK: u64 = 2;

/// Reads the guest's general registers out of a signal context.
///
/// On x86-64 the host's `gregs` order and the frame's `mcontext_t` order are
/// the same, which is why the pure model's numbering describes both and no
/// translation table is needed.
fn frame_regs(uc: &ucontext_t) -> FrameRegs {
    let mut gregs = [0u64; NGREG];
    for (slot, value) in gregs.iter_mut().zip(uc.uc_mcontext.gregs.iter()) {
        *slot = *value as u64;
    }
    FrameRegs::from_gregs(&gregs)
}

/// Sets one register by its index in the shared `gregs` order.
fn set_greg(uc: &mut ucontext_t, index: usize, value: u64) {
    if index >= NGREG {
        return;
    }
    unsafe {
        let base = &mut uc.uc_mcontext.gregs as *mut libc::greg_t as *mut u64;
        *base.add(index) = value;
    }
}

/// What became of a delivery attempt.
pub enum Delivered {
    /// The guest now resumes inside its handler at these registers.
    Went(Delivery),
    /// The signal was ignored, or nothing was deliverable.
    Dropped,
    /// Nothing is installed for this signal, so the guest dies of it.
    Fatal(i32),
    /// The frame could not be placed, so there was nowhere to deliver to.
    Undeliverable,
}

/// Signals that end the guest when nothing is installed for them.
///
/// The set follows a real system. `SIGCHLD`, `SIGCONT` and `SIGURG` are
/// absent because their default disposition is to be ignored, but a fault with
/// no handler installed is fatal.
const FATAL_BY_DEFAULT: &[i32] = &[
    oscore::signal::SIGHUP,
    oscore::signal::SIGINT,
    oscore::signal::SIGQUIT,
    oscore::signal::SIGILL,
    oscore::signal::SIGTRAP,
    oscore::signal::SIGABRT,
    oscore::signal::SIGBUS,
    oscore::signal::SIGFPE,
    oscore::signal::SIGKILL,
    oscore::signal::SIGSEGV,
    oscore::signal::SIGPIPE,
    oscore::signal::SIGALRM,
    oscore::signal::SIGTERM,
];

/// True when a default disposition for `signum` ends the process.
pub fn action_is_fatal(act: &SigAction, signum: i32) -> bool {
    act.handler == SIG_DFL && FATAL_BY_DEFAULT.contains(&signum)
}

/// Builds the kernel-raised signal for a host fault.
///
/// `si_addr` carries the address that faulted, which is what a `SIGSEGV`
/// handler reads to tell a bad pointer from a bad access.
pub fn fault_pending(sig: c_int, addr: u64) -> Option<Pending> {
    let signum = match sig {
        libc::SIGSEGV => oscore::signal::SIGSEGV,
        libc::SIGBUS => oscore::signal::SIGBUS,
        libc::SIGILL => oscore::signal::SIGILL,
        libc::SIGFPE => oscore::signal::SIGFPE,
        libc::SIGTRAP => oscore::signal::SIGTRAP,
        _ => return None,
    };
    Some(Pending::kernel(signum, oscore::signal::SI_KERNEL, addr))
}

/// Delivers the next queued signal to the guest, if one can be delivered.
///
/// `uc` is the interrupted guest context; on a successful delivery it is
/// rewritten so the guest resumes in its handler. A queued signal that is
/// currently blocked stays queued, so unblocking it later still delivers.
pub fn deliver(table: &mut SignalTable, uc: &mut ucontext_t) -> Delivered {
    // The lowest-numbered deliverable signal, so one kind cannot starve another.
    let Some(sig) = table.take_next() else {
        return Delivered::Dropped;
    };
    let action = table.action(sig.signum);

    if action.handler == SIG_IGN {
        return Delivered::Dropped;
    }
    if action_is_fatal(&action, sig.signum) {
        return Delivered::Fatal(sig.signum);
    }

    let regs = frame_regs(uc);
    // The frame goes below the current stack pointer, as the kernel would.
    // Anything near the bottom of the address space has no room for one.
    if regs.rsp < FRAME_SIZE + 0x1000 {
        return Delivered::Undeliverable;
    }
    let (frame, delivery) = build_frame(regs.rsp, &action, &regs, sig, SYS_RT_SIGRETURN as u64);
    if !unsafe { crate::regs::write_guest(delivery.rsp, &frame) } {
        return Delivered::Undeliverable;
    }

    set_greg(uc, oscore::signal::GREG_RDI, delivery.rdi);
    set_greg(uc, oscore::signal::GREG_RSI, delivery.rsi);
    set_greg(uc, oscore::signal::GREG_RDX, delivery.rdx);
    set_greg(uc, oscore::signal::GREG_RAX, delivery.rax);
    set_greg(uc, oscore::signal::GREG_RSP, delivery.rsp);
    set_greg(uc, oscore::signal::GREG_RIP, delivery.rip);

    // The signal stays blocked while its own handler runs, so a second one
    // cannot nest inside it. `SA_NODEFER` asks for exactly that, and
    // `sigreturn` puts the saved mask back either way.
    if !action.no_defer() {
        table.change_mask(SIG_BLOCK, oscore::signal::bit(sig.signum));
    }
    Delivered::Went(delivery)
}

/// Restores the guest from the frame its handler was given, for `rt_sigreturn`.
///
/// `sp` is the frame pointer on entry. The saved registers describe where the
/// guest was interrupted, so putting them back is what makes the interrupted
/// instruction resume; the mask recorded in the frame becomes current again.
pub fn sigreturn(uc: &mut ucontext_t, sp: u64, table: &mut SignalTable) -> bool {
    if sp < FRAME_SIZE + 0x1000 || sp % FRAME_ALIGN != 0 {
        return false;
    }
    let Some(frame) = (unsafe { crate::regs::read_guest(sp, FRAME_SIZE as usize) }) else {
        return false;
    };
    // ucontext_t sits inside the frame, and its mcontext is at a fixed offset.
    let mc = oscore::signal::UC_OFFSET as usize + oscore::signal::UC_MCONTEXT_OFFSET as usize;
    if mc + NGREG * 8 > frame.len() {
        return false;
    }
    let mut gregs = [0u64; NGREG];
    for (i, slot) in gregs.iter_mut().enumerate() {
        let at = mc + i * 8;
        *slot = u64::from_ne_bytes(frame[at..at + 8].try_into().unwrap());
    }
    let regs = FrameRegs::from_gregs(&gregs);
    if regs.rsp == 0 || regs.rip == 0 {
        return false;
    }

    // The blocked set the signal was delivered with is recorded in the frame,
    // so returning reinstates exactly that rather than whatever the handler
    // happened to leave behind.
    table.change_mask(SIG_SETMASK, gregs[oscore::signal::GREG_OLDMASK]);
    for (i, value) in gregs.iter().enumerate() {
        if i == oscore::signal::GREG_OLDMASK || i == oscore::signal::GREG_CR2 {
            continue; // frame bookkeeping, not a register to hand back
        }
        set_greg(uc, i, *value);
    }
    true
}
