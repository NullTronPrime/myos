//! oscore: the pure, host-testable core of the parasitic OS.
//!
//! Every module here compiles for Windows, Linux and macOS and is exercised by
//! `cargo test` without a VM, without a bootloader and without root. The host
//! bindings live in `osplat` and are the only code that cannot be tested this
//! way, which is the whole point of the split.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod addr;
pub mod clock;
pub mod elf;
pub mod frame;
pub mod gfx;
pub mod input;
pub mod link;
pub mod mem;
pub mod persist;
pub mod signal;
pub mod space;
pub mod syscall;
pub mod vfs;
pub mod widget;

pub use addr::{Frame, Perms, PAGE_SIZE};
pub use clock::{Clock, Timespec};
pub use mem::{MemBackend, MemError, SimMem};
pub use vfs::{Errno, Vfs};

/// Version string reported by the `uname`-style command.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Kernel name reported to the guest.
pub const NAME: &str = "myos";

/// Builds a `<name> <version>` string for `uname`.
pub fn banner() -> String {
    format!("{NAME} {VERSION}")
}
