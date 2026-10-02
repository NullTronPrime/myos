# Roadmap: from library OS to a usable windowed OS

This is a working checklist. It is based on an audit of every module in the
repo. The short version: the architecture is a real hosted library OS, but the
windowing is offscreen-only and several core modules are tested-but-unwired.

## Where it is today

- **Real and wired:** `addr`, `vfs`, `elf`, `link`, `gfx`, `syscall`, the
  `osplat` loader/trap layer, the process model (`fork` / `execve` / `wait4` /
  pipes) and the minic self-hosted libc.
- **Tested but NOT wired at runtime:** `frame`, `mem`, `space`, `sched`. All
  four exist, pass unit tests, and are referenced only from each other. Real
  memory is host `mmap`; real scheduling is the host's `fork`/`wait`; guest page
  faults are not served (a fault prints a dump and `_exit`s).
- **Window system:** a window model (`gfx`) with z-order and a compositor, an
  8x8 ASCII font, and a syscall ABI (`0x1000`-`0x1008`). Output is a **PPM file**
  written only when the guest asks to present. There is **no on-screen output**
  and **no input at all**.
- **Missing for real programs:** signals, threads, futex, a clock, timers,
  poll/select/epoll, sockets, stat/getdents, most file mutation, cwd, a shared
  library (`libc.so`), and any persistence.

## Definition of done

A person launches myos, gets a desktop, opens a terminal window, types, moves and
resizes windows, runs real programs, and their files survive a restart.

## Decision to make first

Pick the model, because it changes everything below:

- **A. Hosted compositor library OS (recommended).** Keep the "OS is a host
  process" design. Add a real display/input host (X11/Wayland on Linux, Win32 on
  Windows), a host-backed filesystem, and run the desktop as the root guest. Low
  risk, builds on what works.
- **B. Self-hosted kernel.** Implement address spaces, a scheduler and timer
  interrupts in `osplat`. This means either moving `oscore`'s hardware-free
  modules into `osplat` (they cannot stay under `#![forbid(unsafe_code)]`) or
  deleting the simulated `frame`/`mem`/`space`/`sched`. Much larger, but is what
  "real OS" usually means.

The rest assumes **A**, with the simulation core flagged for removal or reuse.

## Phase 0 - Run real programs

- [ ] Decide the fate of `frame`/`mem`/`space`/`sched`: wire them or delete them.
      Dead "kernel" code is worse than none.
- [ ] Give the OS a real clock:
      `clock_gettime` (229) currently returns the zero epoch; add `nanosleep`,
      `clock_getres`, `gettimeofday`. Nothing that waits can work without this.
- [ ] File metadata: `stat` / `fstat` / `newfstatat` / `statx`, `access`.
      Dynamic linkers and every shell builtin ask for these.
- [ ] Directory iteration: `getdents64` (the VFS already has `Dir` + `lookup`).
- [ ] File positioning: `lseek`; and fix `dup` so a dup'd fd shares its offset
      (offsets are keyed by guest fd, not open-file description, today).
- [ ] File mutation: `unlink`, `rename`, `mkdir`/`rmdir`, `truncate`/`ftruncate`.
- [ ] CWD: `getcwd`, `chdir`, and honour `dirfd` in `openat` (currently ignored).
- [ ] Identity: `uname`, `getuid`/`geteuid`/`getgid`/`getegid`, `getppid`,
      `umask`, `fcntl` (for `FD_CLOEXEC`, `F_DUPFD`, `O_NONBLOCK`).
- [ ] Signals: guest `rt_sigaction` / `rt_sigprocmask` / `rt_sigreturn` +
      delivery, and route `SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE` to the guest's
      handler instead of killing the process. Needed for Ctrl-C and for any
      program that recovers from a fault.
- [ ] Readiness: `poll` / `select` / `epoll` / `eventfd`. This is the backbone of
      every event loop, including the window server.
- [ ] Threads: `clone` with a real stack + per-thread TLS (only one `%fs` exists
      today), `futex`. Required by most runtimes.
- [ ] Persistence: back the VFS with a real filesystem (host directory,
      virtiofs-style, or an on-disk image). Today `preload_root` is one-way and
      writes are lost at exit; each `fork` gets a private copy.
- [ ] Shared library: build our own `libc.so` and resolve it in the loader
      (`DT_NEEDED`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`). Today dynamic
      guests require the *host's* `ld.so` + glibc.
- [ ] An `init` process and a real `/bin` (a shell that does PATH lookup,
      redirection, job control) replacing the minimal `guest/sh.c`.

## Phase 1 - Real display and input (the actual "window OS")

- [ ] Presentation sink: replace the PPM dump with a real surface. X11/Wayland
      (Linux) or a Win32 window. All of it belongs in `osplat`; `oscore::gfx`
      keeps the pure compositor.
- [ ] A frame loop: drive presentation from a compositor loop (timer + input),
      not only when a guest calls `display_present`.
- [ ] Back buffer + damage tracking: composite only dirty rects; stop
      reallocating a full framebuffer per present.
- [ ] Input subsystem: keyboard + mouse events, an event queue, and a syscall
      (or a device + `poll`) to read them. **This is the single biggest missing
      piece.** Add `WINDOW_*` / input syscalls and iterate them in the ABI.
- [ ] Cursor rendering, focus, activation, and hit-testing
      ("which window is at x,y?").
- [ ] Window manager: decorations (title bar, close/resize), drag-to-move,
      drag-to-resize, minimize/maximize, and a real z-order API
      (`lower`, `set_z`, stable indices) instead of move-to-top only.
- [ ] Resize path: `WINDOW_RESIZE` + buffer remap. Sizes are immutable today.
- [ ] Alpha: add `ARGB8888`, blending in `blit`, and stop discarding the top
      byte in `to_ppm`.
- [ ] Clip rectangles per window instead of emergent per-pixel bounds tests.
- [ ] Text: Unicode, proportional/scalable fonts, wrapping, and a text cursor.
      Today: fixed 8x8 ASCII, no wrapping.

## Phase 2 - A usable desktop

- [ ] Window server as the root guest: owns the display, spawns clients, routes
      input, composites.
- [ ] Terminal emulator as a window: pty (needs a real tty + job control) and
      scrolling text.
- [ ] A widget toolkit: event dispatch, buttons, text fields, layout, so apps
      can be written instead of painting pixels by hand.
- [ ] Desktop shell: panel/taskbar, launcher, wallpaper.
- [ ] Shared-memory surfaces + IPC so clients and the server can exchange pixel
      buffers and events without being the same process.

## Phase 3 - Robustness and isolation

- [ ] Give each guest its own address space (or at least a real boundary). Today
      guest and kernel share one address space, and a guest can jump into host
      code.
- [ ] Deliver faults to guests; stop treating every fault as fatal.
- [ ] Enforce memory limits (`prlimit64` reports infinity for everything now)
      and cap window memory (only a per-window 64 MiB bound exists).
- [ ] Credentials/permissions: the VFS stores a `mode` but never checks it.
- [ ] Persistence and recovery for the filesystem.

## Cross-cutting risks

- `oscore` is `#![forbid(unsafe_code)]`: any real hardware work must live in
  `osplat`, which is explicitly the untestable layer. Keep new logic pure and in
  `oscore` where possible.
- The seccomp IP gate keys on "below 4 GiB = guest". Any move to multiple
  address spaces must revisit this rule.
- There is no `TODO`/`FIXME` in the tree; gaps are only in prose. Keep this file
  current as the single source of truth.
