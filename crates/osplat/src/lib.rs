//! osplat: the thin, Linux-only adapter between the pure core and the host.
//!
//! Everything here is `unsafe` and host-facing. Everything else in the project
//! lives in `oscore` where it is covered by `cargo test`. Keep this crate
//! small: every line added here is a line that cannot be unit-tested.

#![deny(missing_docs)]

#[cfg(target_os = "linux")]
pub mod trap;

#[cfg(target_os = "linux")]
pub mod regs;

#[cfg(target_os = "linux")]
pub mod loader;

#[cfg(not(target_os = "linux"))]
compile_error!(
    "osplat requires Linux: the parasitic OS traps syscalls with seccomp-bpf, \
     which exists only on Linux. WSL2 is fine."
);
