#!/bin/bash
# Open a parasyteos app in a live window (WSLg on Windows, X11 on Linux).
#
#   scripts/live.sh terminal
#   scripts/live.sh browser http://localhost:8000/
#
# A window titled "parasyteos" appears on your desktop; keyboard and mouse in it
# reach the guest. Close it by exiting the app (or Ctrl-C here, which kills
# the launcher; the guest cannot outlive it).
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

if [ $# -lt 1 ]; then
    echo "usage: scripts/live.sh <guest> [args...]" >&2
    echo "guests: terminal desktop_shell browser window_server sh2" >&2
    exit 2
fi

# Screenshots and live display are exclusive: a file steals the frames.
unset PARASYTEOS_FB_OUT
export PARASYTEOS_ROOT="${PARASYTEOS_ROOT:-target/rootfs}"
export PARASYTEOS_DISPLAY="${PARASYTEOS_DISPLAY:-640x480}"

if [ -z "${DISPLAY:-}" ]; then
    echo "live.sh: no DISPLAY; is WSLg/X11 running?" >&2
    echo "live.sh: falling back to a screenshot; see scripts/shot.sh" >&2
    exec scripts/shot.sh "$@"
fi

guest="$1"
shift
exec target/release/parasyteos "target/guest/$guest" "$@"
