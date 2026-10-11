#!/bin/bash
# boot.sh: unified boot — shows progress, starts desktop with taskbar,
# wallpaper, and a terminal window.
set -euo pipefail
cd "$(dirname "$0")/.."

myos=target/release/myos
out=target/guest
root=target/rootfs

if [ ! -x "$myos" ] || [ ! -x "$out/desktop_shell" ]; then
    echo "not built yet; run scripts/build.sh first" >&2
    exit 1
fi

echo "myos: booting..."
echo "myos: rootfs $root"
echo "myos: display connected"
echo "myos: starting desktop shell"
echo ""

export DISPLAY="${DISPLAY:-:0}"
exec env MYOS_ROOT="$root" MYOS_DISPLAY=800x600 MYOS_FB_OUT=target/frame_latest.ppm DISPLAY="$DISPLAY" "$myos" "$out/desktop_shell"
