# myos

A library OS that runs as an ordinary Linux process. There is no bootloader, no
hypervisor and no emulation: the launcher loads a guest ELF *into its own address
space*, installs a seccomp-bpf filter, and services every syscall the guest makes
from Rust. It is parasitic by design — it borrows a Linux process the way a
library OS borrows its host.

```
crates/oscore   pure, host-testable core (no unsafe): address space, frames,
                memory, VFS, ELF, relocation, graphics, syscall dispatcher
crates/osplat   the only Linux-specific layer: ELF loader, SIGSYS trap handler,
                host process/pipe/fd plumbing
crates/myos     the launcher binary (`myos`)
guest/          guest programs and the self-hosted C library (`minic`)
scripts/        build and run helpers
```

## How it works

- **Hosted kernel.** `myos` maps the guest image (optionally followed by the
  host's own `ld.so` for dynamic guests), builds a SysV initial stack, and jumps
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

## Build and run

```sh
scripts/build.sh      # builds the kernel + guests, assembles target/rootfs
scripts/run.sh        # opens the myos shell
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

`guest/contracts.sh` pins the kernel/host behaviours the OS depends on and runs
the end-to-end checks:

```sh
bash guest/contracts.sh
```
