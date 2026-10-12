#!/bin/bash
# Screenshot a parasyteos app without any display server.
#
#   scripts/shot.sh desktop_shell
#   scripts/shot.sh browser http://localhost:8000/
#
# Runs the guest headless for a few seconds, composites one frame and
# converts it to PNG. Prints the PNG path; open it in any image viewer.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

if [ $# -lt 1 ]; then
    echo "usage: scripts/shot.sh <guest> [args...]" >&2
    exit 2
fi

guest="$1"
shift
out="target/shots/$guest.png"
mkdir -p target/shots

PARASYTEOS_DISPLAY="${PARASYTEOS_DISPLAY:-640x480}" \
PARASYTEOS_FB_OUT="target/shots/$guest.ppm" \
PARASYTEOS_ROOT="${PARASYTEOS_ROOT:-target/rootfs}" \
    timeout "${SHOT_SECS:-8}" target/release/parasyteos "target/guest/$guest" "$@" \
    > /dev/null 2>&1 || true

python3 scripts/ppm2png.py "target/shots/$guest.ppm" "$out"
