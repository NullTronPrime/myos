# myos

A library OS that runs as an ordinary Linux process. There is no bootloader, no
hypervisor and no emulation: the launcher loads a guest ELF *into its own address
space*, installs a seccomp-bpf filter, and services every syscall the guest makes
from Rust. It is parasitic by design — it borrows a Linux process the way a
library OS borrows its host.

```
crates/oscore   host-testable core :implements address space, frames,
                memory, VFS, ELF, relocation, graphics, syscall dispatcher
crates/osplat   Linux specific layer:implements ELF loader, SIGSYS trap handler,
                host process/pipe/fd plumbing
crates/myos     the launcher binary
guest/          guest programs and the self-hosted C library (`minic`)
scripts/        build and run helpers
```

## How it works

- **Hosted kernel.** `myos` maps the guest image (optionally followed by the
  host's own `ld.so` for dynamic guests), builds a SysV initial stack, and transfers
  to the entry point in a forked child.
- **Seccomp + SIGSYS.** A seccomp filter traps syscalls. Calls issued from guest
  code (below 4 GiB) are serviced by `oscore`; calls issued by host libraries
  (above 4 GiB) pass straight through, so the kernel can still use real syscalls.
- **In-process `execve`.** `execve` resets caught signal handlers, so the
  launcher re-execs itself in `--exec` mode and re-arms only the trap handler.
- **Self-hosting.** Guests can be built with no host libc at all, against
  `guest/lib/minic.c` + `guest/lib/crt0.S`. Static PIE images are relocated by
  the kernel side of the loader (`oscore::link`).

## Requirements

- x86-64 Linux with `CONFIG_SECCOMP_FILTER` (WSL2 works).
- A Rust toolchain and `cargo`.
- `gcc` to build the guest programs.
- `readelf` is optional (used by the contract tests).
- For sound: `ffmpeg` and `pulseaudio-utils` (`paplay`), or set
  `MYOS_AUDIO_CMD` to redirect playback.
- For the local-TLS and network contract tests: `python3`, `openssl`.
- For live windows: an X server (WSLg on Windows, X11 on Linux).

## Build and run

```sh
scripts/build.sh      # builds the kernel + guests + assembles target/rootfs
scripts/run.sh        # opens the myos shell
scripts/live.sh desktop_shell            # full desktop in a live window (WSLg/X11)
scripts/live.sh browser <url>            # browser alone, live
scripts/shot.sh browser <url>            # headless screenshot to target/shots/
scripts/snd.sh song.mp3 song.u8          # convert audio to 8-bit for /dev/audio
```

`scripts/run.sh` sets `MYOS_ROOT=target/rootfs`, which backs the guest's `/`.
Type commands at the prompt, or pipe them in:

```sh
printf '/bin/catfile /etc/motd\nexit\n' | scripts/run.sh
```

Run a single program without a rootfs:

```sh
target/release/myos target/guest/hello
target/release/myos target/guest/pie_guest
```

With no `MYOS_ROOT`, the guest filesystem starts from a built-in initrd
(`/motd`, `/version`).

### Display

Guests can draw into an offscreen window system. `MYOS_DISPLAY` sets the screen
size and `MYOS_FB_OUT` writes a PPM of the final frame:

```sh
MYOS_DISPLAY=64x48 MYOS_FB_OUT=frame.ppm \
  target/release/myos target/guest/fb_paint text
```

## Writing a guest

Any static ELF works. For a guest with no host libc, include `minic.h` and link
`guest/lib/crt0.S` + `guest/lib/minic.c`:

```c
#include "minic.h"

int main(void) {
    printf("hello from myos\n");
    return 0;
}
```

```sh
gcc -nostdlib -static -no-pie -fno-stack-protector -fno-builtin \
    -Iguest/lib -O2 -o hello guest/lib/crt0.S guest/lib/minic.c hello.c
```

## Tests

`guest/contracts.sh` is the contract suite (49 checks and counting): seccomp
trap behavior, syscalls, processes, display, input, sockets, `poll` waits,
local TLS for both cipher suites, P-256/GCM self-checks, the HTML parser,
and the DOM bindings — all runnable headless under WSL2.

```sh
bash guest/contracts.sh
cargo test -p oscore --lib   # 337 kernel unit tests
cargo test -p osplat --lib   # platform tests (keymap, loader, …)
```

## Capabilities

**Processes.** `fork`/`execve`/`wait4`, `clone` (fork-like and thread-like),
`futex`, signals with real handlers (`rt_sigreturn`, blocking, fault routing),
ptys (`/dev/ptmx`, `grantpt`, job control), pipes, shared memory (`memfd`,
`shm_open`), and environment inheritance rules that keep the dynamic linker
hermetic (empty guest env by design; the re-exec trampoline forwards only
`DISPLAY`/`MYOS_*`).

**Display.** A real X11 client (hand-rolled protocol, no toolkit): live windows
at ~60fps with damage tracking, plus headless PPM snapshots. Windows support
create/map/present/move/resize/destroy/raise/focus, 8x8 text, and 32-bit color.
Input arrives as key/mouse/resize/close events; `poll` with a timeout genuinely
waits (blocking host-side, then re-running the call). Keyboard covers the full
PC/XT map including Shift symbols and both Enters.

**Desktop.** Wallpaper, dock-style taskbar (launcher pill, per-app icon tiles,
live window census with running indicators, clock), Alt+Tab, and window
drag/resize/close. Apps embed *inside* the one desktop window: their outer X
windows reparent into it (rendezvous via `/winserv/desktop/xid`), follow
resizes through `/winserv/desktop/geom`, and keep their own input. Resizing the
OS window rebuilds every buffer and re-lays out.

**Terminal & shell.** Multi-tab terminal over ptys; `sh2` with PATH lookup,
redirection, pipes, background jobs, env expansion, and builtins.

**Networking.** Full socket delegation (stream/datagram, socketpair, options,
nonblocking `connect` with timeout), a static-friendly resolver (numeric,
`/etc/hosts`, hand-built DNS over UDP with TCP fallback across every
nameserver), HTTP/1.1 with chunked decoding, and redirect following.
`fetch <host> [port] [path] [--body]` proves any of it in one line.

**TLS 1.2.** Hand-rolled: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` preferred
(P-256 ECDH with on-curve validation, AES-GCM, SNI/groups/ALPN/sigalgs,
`ServerKeyExchange` RSA/SHA-256 verification) with `TLS_RSA_WITH_AES_128_CBC_SHA`
fallback. RSA certificates only, hostname checking with a real DER walk of
SAN lists, expiry sanity — but no chain-of-trust validation (toy-grade, and it
says so). Verified against real sites, not just localhost.

**Browser.** One window: title strip (drag + close), nav row (back/forward/
reload/home, dimmed when useless), blurple URL pill, bookmarks bar with a
working star, page viewport, status line. Renders tag-stripped HTML with blue
clickable links, scrollback, and history; downloads binaries to `/downloads`
and runs them on click (explicit consent model). Bare hostnames gain `https://`,
single words search, 301/302/303/307/308 followed, truncated closes tolerated.

**JavaScript.** QuickJS linked straight into the browser (no daemon): pages
parse to a real node tree (`guest/lib/dom.c`), scripts run pre-render against
DOM bindings (`guest/lib/jsdom.c`) — `document`/`Element` queries and mutation,
`innerHTML`, timers firing from the main loop with re-layout, synchronous XHR
over our own sockets, `console.log`. One bad script never kills the rest.
What the engine can't do (layout-geometry APIs, full modern surface) fails
loudly per-script instead of silently.

**Sound.** 8-bit minimalist: write unsigned 8-bit mono 8000 Hz PCM to
`/dev/audio` and the kernel streams it to the host player (PulseAudio).
`scripts/snd.sh` converts anything ffmpeg reads; `beep [freq]` tests the path;
`MYOS_AUDIO_CMD` redirects playback (e.g. `tee /tmp/cap.u8`) for headless tests.

**Tools.** `js` runs scripts/files under the trap (`print`, real exit codes);
`beep` checks audio; `fetch` probes the network; `dom_test`/`jsdom_test`/
`poll_test`/`ec_test` pin their subsystems in contracts.
