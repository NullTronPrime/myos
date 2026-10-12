#!/bin/bash
# Launch the parasyteos shell with the assembled rootfs as the guest's /.
#
# Reads commands from stdin, exactly like a login shell:
#   scripts/run.sh
#   printf '/bin/catfile /etc/motd\nexit\n' | scripts/run.sh
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

parasyteos=target/release/parasyteos
out=target/guest
root=target/rootfs

if [ ! -x "$parasyteos" ] || [ ! -x "$out/sh" ]; then
    echo "not built yet; run scripts/build.sh first" >&2
    exit 1
fi

exec env PARASYTEOS_ROOT="$root" "$parasyteos" "$out/sh" "$@"
