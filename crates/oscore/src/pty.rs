//! Pure pseudo-terminal model for Phase 2.1.
//!
//! Host `openpt`/`grantpt`/`ptsname` live in `osplat` and cannot run under
//! `cargo test` on Windows. This module is the testable half: allocation,
//! line discipline, window size and foreground process group, expressed over
//! plain byte queues so `guest/terminal.c` behaviour can be asserted without
//! a host pty.
//!
//! The trap layer already delegates `SYS_OPENPT` et al to the host when its
//! hooks are installed (`osplat::trap`). When they are absent (tests, or a
//! headless build), this table is the in-memory fallback the dispatcher can
//! drive directly.

use std::collections::{BTreeMap, VecDeque};

/// `lflag` bits honoured by the line discipline.
pub const ICANON: u32 = 0x0002;
/// Echo input characters.
pub const ECHO: u32 = 0x0008;
/// Enable `ERASE`/`KILL` handling.
pub const ECHOE: u32 = 0x0010;

/// Control characters that terminate a canonical line.
pub const VINTR: usize = 0;
/// End-of-file character.
pub const VEOF: usize = 4;

/// Job-control signals from Phase 2.1.
pub const SIGTSTP: i32 = 20;
/// Background read from controlling terminal.
pub const SIGTTIN: i32 = 21;
/// Background write to controlling terminal.
pub const SIGTTOU: i32 = 22;

/// Terminal window size, matching `struct winsize` layout (rows/cols/x/y).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Winsize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsize {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.rows.to_le_bytes());
        out[2..4].copy_from_slice(&self.cols.to_le_bytes());
        out[4..6].copy_from_slice(&self.xpixel.to_le_bytes());
        out[6..8].copy_from_slice(&self.ypixel.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        Some(Winsize {
            rows: u16::from_le_bytes([b[0], b[1]]),
            cols: u16::from_le_bytes([b[2], b[3]]),
            xpixel: u16::from_le_bytes([b[4], b[5]]),
            ypixel: u16::from_le_bytes([b[6], b[7]]),
        })
    }
}

/// Simplified `termios`: only the fields the line discipline reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub cc: [u8; 8],
}

impl Default for Termios {
    fn default() -> Self {
        Termios {
            iflag: 0,
            oflag: 0,
            cflag: 0,
            lflag: ICANON | ECHO | ECHOE,
            cc: [0x03, 0x1c, 0x7f, 0x15, 0x04, 0, 0, 0],
        }
    }
}

/// One pty: two byte queues plus discipline state.
#[derive(Clone, Debug, Default)]
pub struct Pty {
    /// Bytes the slave wrote, waiting for the master to read.
    pub to_master: VecDeque<u8>,
    /// Bytes the master wrote, waiting for the slave to read.
    pub to_slave: VecDeque<u8>,
    /// Canonical input staging (slave side, before newline).
    line: Vec<u8>,
    /// Echoed output staging, drained into `to_master`.
    echo: VecDeque<u8>,
    pub termios: Termios,
    pub winsize: Winsize,
    /// Foreground process group for `tcsetpgrp` job control.
    pub foreground: u32,
    /// Whether `grantpt`/`unlockpt` have run.
    pub granted: bool,
    pub unlocked: bool,
    /// Whether this pty is the controlling terminal (`TIOCSCTTY`).
    pub controlling: bool,
}

impl Pty {
    pub fn new() -> Self {
        Self::default()
    }

    fn canonical(&self) -> bool {
        self.termios.lflag & ICANON != 0
    }

    fn echo_on(&self) -> bool {
        self.termios.lflag & ECHO != 0
    }

    /// Slave writes a chunk (a shell printing output, or typed input echoed).
    ///
    /// In canonical mode input accumulates until newline and only complete
    /// lines become readable by the master; output bytes pass through
    /// directly. Returns bytes accepted.
    pub fn slave_write(&mut self, data: &[u8]) -> usize {
        if !self.canonical() {
            self.to_master.extend(data.iter());
            return data.len();
        }
        for &b in data {
            if b == b'\n' {
                self.line.push(b);
                // Flush the whole line at once, preserving order.
                let line = std::mem::take(&mut self.line);
                self.to_master.extend(line);
            } else if (b == 0x7f || b == 0x08) && self.termios.lflag & ECHOE != 0 {
                self.line.pop();
                if self.echo_on() {
                    // Erase one echoed char: backspace-space-backspace.
                    self.to_master.extend([0x08, b' ', 0x08]);
                }
            } else if b == self.termios.cc[VINTR] && b != 0 {
                // INTR discards the staged line; the signal itself is
                // delivered by the caller via kill, not here.
                self.line.clear();
            } else {
                self.line.push(b);
                if self.echo_on() {
                    self.to_master.push_back(b);
                }
            }
        }
        // Drain any echo backlog into the readable queue.
        while let Some(b) = self.echo.pop_front() {
            self.to_master.push_back(b);
        }
        data.len()
    }

    /// Master reads output (what the terminal emulator renders).
    pub fn master_read(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.to_master.len());
        self.to_master.drain(..n).collect()
    }

    /// Master writes input (keystrokes forwarded to the shell).
    pub fn master_write(&mut self, data: &[u8]) -> usize {
        self.to_slave.extend(data.iter());
        data.len()
    }

    /// Slave reads input (what a shell on the slave side observes).
    pub fn slave_read(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.to_slave.len());
        self.to_slave.drain(..n).collect()
    }

    /// Bytes waiting for the master.
    pub fn master_pending(&self) -> usize {
        self.to_master.len()
    }

    /// Bytes waiting for the slave.
    pub fn slave_pending(&self) -> usize {
        self.to_slave.len()
    }

    /// Sets the foreground process group (`SYS_TCSETPGRP`).
    pub fn set_foreground(&mut self, pgid: u32) {
        self.foreground = pgid;
    }

    /// Reads the foreground process group (`SYS_TCGETPGRP`).
    pub fn get_foreground(&self) -> u32 {
        self.foreground
    }

    /// Job-control decision for a process group touching this terminal.
    ///
    /// Returns the signal a background group earns: `SIGTTIN` for a read,
    /// `SIGTTOU` for a write, or `None` when `pgid` is the foreground group
    /// (or no foreground group is set, in which case nothing is stopped).
    /// A real kernel only sends `SIGTTOU` when `TOSTOP` is set; this model
    /// always stops background writes, which is documented so callers are
    /// not surprised.
    pub fn job_signal(&self, pgid: u32, want_write: bool) -> Option<i32> {
        if self.foreground == 0 || pgid == self.foreground {
            return None;
        }
        Some(if want_write { SIGTTOU } else { SIGTTIN })
    }
}

/// Table of allocated ptys, keyed by master id.
#[derive(Clone, Debug, Default)]
pub struct PtyTable {
    next: u32,
    ptys: BTreeMap<u32, Pty>,
}

impl PtyTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a master, mirroring `openpt`.
    pub fn open(&mut self) -> u32 {
        let id = self.next;
        self.next += 1;
        self.ptys.insert(id, Pty::new());
        id
    }

    pub fn get(&self, id: u32) -> Option<&Pty> {
        self.ptys.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Pty> {
        self.ptys.get_mut(&id)
    }

    /// Mirrors `grantpt`: marks the slave accessible.
    pub fn grant(&mut self, id: u32) -> bool {
        match self.ptys.get_mut(&id) {
            Some(p) => {
                p.granted = true;
                true
            }
            None => false,
        }
    }

    /// Mirrors `unlockpt`.
    pub fn unlock(&mut self, id: u32) -> bool {
        match self.ptys.get_mut(&id) {
            Some(p) if p.granted => {
                p.unlocked = true;
                true
            }
            _ => false,
        }
    }

    /// Slave device name, mirroring `ptsname`.
    pub fn name(&self, id: u32) -> Option<String> {
        self.ptys
            .get(&id)
            .filter(|p| p.granted && p.unlocked)
            .map(|_| format!("/dev/pts/{id}"))
    }

    pub fn len(&self) -> usize {
        self.ptys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ptys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_grant_unlock_then_name() {
        let mut t = PtyTable::new();
        let id = t.open();
        assert_eq!(t.name(id), None, "ungranted pty has no name");
        assert!(t.grant(id));
        assert_eq!(t.name(id), None, "locked pty has no name");
        assert!(t.unlock(id));
        assert_eq!(t.name(id), Some(format!("/dev/pts/{id}")));
    }

    #[test]
    fn canonical_lines_flush_on_newline() {
        let mut p = Pty::new();
        p.slave_write(b"hel");
        assert_eq!(p.master_pending(), 3, "echo is readable immediately");
        let mut p2 = Pty::new();
        // Disable echo to isolate line buffering.
        p2.termios.lflag &= !ECHO;
        p2.slave_write(b"hel");
        assert_eq!(p2.master_pending(), 0, "partial line not yet readable");
        p2.slave_write(b"lo\n");
        assert_eq!(p2.master_read(99), b"hello\n");
    }

    #[test]
    fn erase_removes_a_staged_char() {
        let mut p = Pty::new();
        p.termios.lflag &= !ECHO;
        p.slave_write(b"ab");
        p.slave_write(&[0x7f]);
        p.slave_write(b"c\n");
        assert_eq!(p.master_read(99), b"ac\n");
    }

    #[test]
    fn master_to_slave_round_trips_keystrokes() {
        let mut p = Pty::new();
        p.master_write(b"ls\n");
        assert_eq!(p.slave_pending(), 3);
        assert_eq!(p.slave_read(99), b"ls\n");
    }

    #[test]
    fn winsize_round_trips_through_bytes() {
        let w = Winsize {
            rows: 24,
            cols: 80,
            xpixel: 640,
            ypixel: 480,
        };
        assert_eq!(Winsize::from_bytes(&w.to_bytes()), Some(w));
        assert_eq!(Winsize::from_bytes(&[0u8; 3]), None);
    }

    #[test]
    fn job_control_foreground_group_is_tracked() {
        let mut p = Pty::new();
        assert_eq!(p.foreground, 0);
        p.foreground = 42;
        p.controlling = true;
        assert!(p.controlling);
        assert_eq!(p.foreground, 42);
    }

    #[test]
    fn set_and_get_foreground_round_trip() {
        let mut p = Pty::new();
        p.set_foreground(7);
        assert_eq!(p.get_foreground(), 7);
    }

    #[test]
    fn background_groups_earn_ttin_ttou_foreground_passes() {
        let mut p = Pty::new();
        // No foreground set: nothing is stopped.
        assert_eq!(p.job_signal(99, false), None);
        p.set_foreground(42);
        assert_eq!(p.job_signal(42, false), None);
        assert_eq!(p.job_signal(42, true), None);
        assert_eq!(p.job_signal(7, false), Some(SIGTTIN));
        assert_eq!(p.job_signal(7, true), Some(SIGTTOU));
    }
}
