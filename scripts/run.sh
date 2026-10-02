#!/bin/bash
# Launch the myos shell with the assembled rootfs as the guest's /.
#
# Reads commands from stdin, exactly like a login shell:
#   scripts/run.sh
#   printf '/bin/catfile /etc/motd\nexit\n' | scripts/run.sh
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

myos=target/release/myos
out=target/guest
root=target/rootfs

if [ ! -x "$myos" ] || [ ! -x "$out/sh" ]; then
    echo "not built yet; run scripts/build.sh first" >&2
    exit 1
fi

exec env MYOS_ROOT="$root" "$myos" "$out/sh" "$@"
