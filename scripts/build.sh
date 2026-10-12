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

mkdir -p "$out" "$root/bin" "$root/etc" "$root/dev" "$root/lib"

# Guests that link the host's static glibc: fixed-address, no interpreter.
for g in sh sh2 init window_server desktop_shell terminal input_test catfile catstdin proc_parent proc_child fb_paint beep; do
    "$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/$g" "guest/$g.c"
done

# fetch and browser are static but resolve names through guest/lib/resolve.c
# (numeric, /etc/hosts, hand-built DNS): glibc NSS needs shared modules that
# a static guest can neither see nor load. Both link the minimal TLS 1.2
# client (guest/lib/tls.c) for https:// URLs.
"$cc" -static -no-pie -O2 -fno-stack-protector -o "$out/fetch" guest/fetch.c guest/lib/resolve.c guest/lib/tls.c
"$cc" -static -no-pie -O2 -fno-stack-protector '-DCONFIG_VERSION="2026-06-04"' \
    -o "$out/browser" guest/browser.c guest/lib/resolve.c guest/lib/tls.c \
    guest/lib/dom.c guest/lib/jsdom.c third_party/quickjs/quickjs.c \
    third_party/quickjs/dtoa.c third_party/quickjs/libregexp.c \
    third_party/quickjs/libunicode.c third_party/quickjs/cutils.c -lm
# js: QuickJS linked into a static guest (core engine only: no libc
# helpers, no intl/temporal data; no host libc beyond what the other
# guests use). ~30s of compile for the engine.
"$cc" -static -no-pie -O2 -fno-stack-protector '-DCONFIG_VERSION="2026-06-04"' \
    -o "$out/js" guest/js.c third_party/quickjs/quickjs.c \
    third_party/quickjs/dtoa.c third_party/quickjs/libregexp.c \
    third_party/quickjs/libunicode.c third_party/quickjs/cutils.c -lm

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

# Our own libc.so: a shared library that guests can link against dynamically.
"$cc" -nostdlib -shared -fPIC -fno-stack-protector -fno-builtin \
    -Iguest/lib -O2 -o "$root/lib/libc.so" \
    guest/lib/minic.c -Wl,-soname,libc.so

# Populate the directory the guest sees as /.
cp "$out/sh" "$out/sh2" "$out/init" "$out/window_server" "$out/desktop_shell" "$out/terminal" \
   "$out/dyn_hello" "$out/pie_guest" "$out/selfhost" \
   "$out/catfile" "$out/catstdin" "$out/fetch" "$out/browser" "$out/beep" "$out/js" "$root/bin/"
printf 'myos: parasitic kernel, running inside a process.\n' > "$root/etc/motd"
printf 'os-1.0\n' > "$root/etc/version"

echo
echo "kernel: target/release/myos"
echo "rootfs: $root"
echo "shell:  MYOS_ROOT=$root target/release/myos $out/sh"
