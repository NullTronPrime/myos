#!/bin/bash
# Build the myos kernel and its guest programs, then assemble a rootfs.
#
# This is the "use it" path. Validation lives in guest/contracts.sh and is
# intentionally not run here.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

cargo build --release

out=target/guest
root=target/rootfs
cc=${CC:-gcc}

mkdir -p "$out" "$root/bin" "$root/etc" "$root/dev"

# Guests that link the host's static glibc: fixed-address, no interpreter.
for g in sh catfile catstdin proc_parent proc_child fb_paint; do
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/$g" "guest/$g.c"
done

# A dynamically linked guest: exercises PT_INTERP + host ld.so inside myos.
"$cc" -O2 -o "$out/dyn_hello" guest/dyn_hello.c

# Guests built only against our self-hosted C library (no host libc at all):
# a static ET_EXEC and a relocatable static PIE.
"$cc" -nostdlib -static -no-pie -fno-stack-protector -fno-builtin \
    -Iguest/lib -O2 -o "$out/selfhost" \
    guest/lib/crt0.S guest/lib/minic.c guest/selfhost.c
"$cc" -nostdlib -static-pie -fno-stack-protector -fno-builtin \
    -Iguest/lib -O2 -o "$out/pie_guest" \
    guest/lib/crt0.S guest/lib/minic.c guest/pie_guest.c

# Populate the directory the guest sees as /.
cp "$out/sh" "$out/dyn_hello" "$out/pie_guest" "$out/selfhost" \
   "$out/catfile" "$out/catstdin" "$root/bin/"
printf 'myos: parasitic kernel, running inside a process.\n' > "$root/etc/motd"
printf 'os-1.0\n' > "$root/etc/version"

echo
echo "kernel: target/release/myos"
echo "rootfs: $root"
echo "shell:  MYOS_ROOT=$root target/release/myos $out/sh"
