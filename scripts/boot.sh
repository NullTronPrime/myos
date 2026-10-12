#!/bin/bash
# boot.sh: unified boot — shows progress, starts desktop with taskbar,
# wallpaper, and a terminal window.
set -euo pipefail
cd "$(dirname "$0")/.."

parasyteos=target/release/parasyteos
out=target/guest
root=target/rootfs

if [ ! -x "$parasyteos" ] || [ ! -x "$out/desktop_shell" ]; then
    echo "not built yet; run scripts/build.sh first" >&2
    exit 1
fi

echo "parasyteos: booting..."
echo "parasyteos: rootfs $root"
echo "parasyteos: display connected"
echo "parasyteos: starting desktop shell"
echo ""

export DISPLAY="${DISPLAY:-:0}"
exec env PARASYTEOS_ROOT="$root" PARASYTEOS_DISPLAY=800x600 PARASYTEOS_FB_OUT=target/frame_latest.ppm DISPLAY="$DISPLAY" "$parasyteos" "$out/desktop_shell"
