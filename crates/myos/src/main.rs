//! `myos`: a kernel that runs as an ordinary Linux process.
//!
//! The launcher loads a guest ELF *into its own address space* (no `execve`,
//! which would discard the `SIGSYS` handler) and jumps to its entry point in a
//! forked child. Every syscall the guest makes is trapped by a seccomp-bpf
//! filter, serviced by `oscore`'s pure dispatcher, and returned in `rax`.
//! Nothing is emulated and nothing is booted.

use oscore::elf::ElfImage;
use osplat::{loader, trap};
use std::ffi::CString;

/// Files the guest filesystem starts with.
const INITRD: &[(&str, &[u8])] = &[
    (
        "/motd",
        b"myos: parasitic kernel, running inside a process.\n",
    ),
    ("/version", NAME_VERSION.as_bytes()),
];

const NAME_VERSION: &str = concat!("myos ", env!("CARGO_PKG_VERSION"), "\n");

fn usage() -> ! {
    eprintln!(
        "usage: myos [--allow <nr>]... <program> [args...]\n\n\
         Runs <program> as a guest under the myos kernel. Every syscall the\n\
         guest issues is trapped with seccomp-bpf and serviced by oscore.\n\n\
         options:\n  \
           --allow <nr>   let guest syscall <nr> reach the host (default: none)\n  \
           --list          print allowed guest syscalls and exit\n  \
           -h, --help      this text\n"
    );
    std::process::exit(2);
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("myos: {msg}");
    std::process::exit(1);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let mut allow: Vec<i64> = Vec::new();
    let mut exec_mode = false;
    while let Some(a) = args.first() {
        match a.as_str() {
            "-h" | "--help" => usage(),
            "--exec" => {
                // Internal: a guest's `execve` re-exec'd us. The seccomp filter
                // is already installed and inherited; only the handler needs
                // re-arming. Load the new image into this process directly.
                args.remove(0);
                exec_mode = true;
                break;
            }
            "--list" => {
                println!("guest syscalls trapped: all");
                println!("guest syscalls allowed to reach the host:");
                if trap::ALLOWED_SYSCALLS.is_empty() {
                    println!("  (none)");
                }
                for nr in trap::ALLOWED_SYSCALLS {
                    println!("  {nr}");
                }
                std::process::exit(0);
            }
            "--allow" => {
                args.remove(0);
                let nr = match args.first().and_then(|s| s.parse::<i64>().ok()) {
                    Some(n) => n,
                    None => usage(),
                };
                args.remove(0);
                allow.push(nr);
            }
            _ => break,
        }
    }

    if args.is_empty() {
        usage();
    }
    if exec_mode && args.len() < 2 {
        fail("--exec needs <argv0> <program>");
    }

    // An optional host directory backs the guest's `/`. When set, program paths
    // and file opens resolve inside it; the re-exec'd launcher gets the same
    // root through `MYOS_ROOT` in its environment.
    let has_root = std::env::var_os("MYOS_ROOT").is_some();
    if has_root {
        let root = std::path::PathBuf::from(std::env::var_os("MYOS_ROOT").unwrap());
        trap::set_root(root.clone());
        match trap::preload_root(&root) {
            Ok(n) if !exec_mode => eprintln!("myos: rootfs {} ({n} nodes)", root.display()),
            Ok(_) => {}
            Err(e) => fail(format_args!("cannot preload rootfs: {e}")),
        }
    } else {
        // Seed the guest filesystem before any guest code runs.
        for (path, data) in INITRD {
            if let Err(e) = trap::provide_file(path, data) {
                fail(format_args!("cannot create {path}: {e:?}"));
            }
        }
    }

    // Open a real window if there is a display server. This is optional: with no
    // `DISPLAY`, a refused connection, no socket or a server that never answers,
    // the OS keeps running against its in-memory framebuffer and the guest
    // simply receives no input events.
    match osplat::display::connect() {
        Some(()) => eprintln!("myos: display connected"),
        None => eprintln!("myos: no display server; running headless"),
    }

    // In `--exec` mode the first argument is the guest-visible `argv[0]` and the
    // second is the host path to load; they differ when a rootfs translated it.
    let (program, guest_args): (String, Vec<String>) = if exec_mode {
        (
            args[1].clone(),
            std::iter::once(args[0].clone())
                .chain(args[2..].iter().cloned())
                .collect(),
        )
    } else {
        (args[0].clone(), args.clone())
    };

    let bytes = match std::fs::read(&program) {
        Ok(b) => b,
        Err(e) => fail(format_args!("cannot read {program}: {e}")),
    };
    let image = match ElfImage::parse(&bytes) {
        Ok(i) => i,
        Err(e) => fail(format_args!(
            "{program} is not a runnable ELF: {}",
            e.as_str()
        )),
    };

    let c_args: Vec<CString> = guest_args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_default())
        .collect();
    // The guest gets an empty environment. Its dynamic linker walks `envp`
    // looking for `LD_*` overrides, and a large or unexpected environment
    // changes the initial stack layout enough to change how far it gets before
    // touching an unset field. A guest that runs must not depend on whatever
    // happens to be in our environment.
    let envp: Vec<CString> = Vec::new();

    let root_path = if has_root {
        Some(std::path::PathBuf::from(std::env::var_os("MYOS_ROOT").unwrap()))
    } else {
        None
    };
    let loaded = match loader::prepare(&image, &bytes, &c_args, &envp, root_path.as_deref()) {
        Ok(l) => l,
        Err(e) => fail(e),
    };

    if !exec_mode {
        eprintln!(
            "myos: {} loading {program} at {:#x}",
            oscore::banner(),
            loaded.entry
        );
    }

    // The guest's program break starts at the end of its image, so `brk` growth
    // claims fresh pages rather than starting at zero.
    trap::set_initial_brk(loaded.brk);

    unsafe {
        if exec_mode {
            // A filter is already in force; re-arm only the trap handler, which
            // `execve` reset, then hand this process to the new guest.
            if let Err(e) = trap::install_handler_only() {
                eprintln!("myos: cannot re-arm syscall trap: {e}");
                libc::_exit(120);
            }
            if let Some(script) = std::env::var_os("MYOS_INJECT") {
                match trap::inject_file(std::path::Path::new(&script)) {
                    Ok(n) => eprintln!("myos: injected {n} input events"),
                    Err(e) => {
                        eprintln!("myos: inject failed: {e}");
                        libc::_exit(121);
                    }
                }
            }
            loader::enter(loaded.entry, loaded.stack_top);
        }

        // The guest runs in a forked child so a crash cannot take the launcher
        // with it, and so the filter is installed only in the process it
        // applies to.
        //
        // Note: presentation happens inside the child's trap handler when the
        // guest calls `display_present` (see `osplat::trap`). A compositor
        // thread here in the parent would read a *copy* of the kernel state
        // (fork duplicates the process), so it could never see guest windows.
        let pid = libc::fork();
        if pid < 0 {
            fail("fork failed");
        }
        if pid == 0 {
            if let Err(e) = trap::install(&allow) {
                eprintln!("myos: cannot install syscall trap: {e}");
                eprintln!("myos: this needs Linux with CONFIG_SECCOMP_FILTER.");
                libc::_exit(120);
            }
            // Headless interaction tests: queue scripted input before the
            // guest runs. Only the initial guest is injected; `execve`'d
            // children start clean because the re-exec environment does
            // not propagate `MYOS_INJECT` (see `exec_trampoline`).
            if let Some(script) = std::env::var_os("MYOS_INJECT") {
                match trap::inject_file(std::path::Path::new(&script)) {
                    Ok(n) => eprintln!("myos: injected {n} input events"),
                    Err(e) => {
                        eprintln!("myos: inject failed: {e}");
                        libc::_exit(121);
                    }
                }
            }
            // Never returns; the guest owns the thread from here.
            loader::enter(loaded.entry, loaded.stack_top);
        }

        let mut status: libc::c_int = 0;
        if libc::waitpid(pid, &mut status, 0) < 0 {
            fail("waitpid failed");
        }
        if libc::WIFEXITED(status) {
            std::process::exit(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            eprintln!("myos: guest killed by signal {sig}");
            std::process::exit(128 + sig);
        }
        std::process::exit(1);
    }
}
