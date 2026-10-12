#!/bin/bash
# Convert any audio ffmpeg reads into the one format myos plays: unsigned
# 8-bit mono PCM at 8000 Hz (the whole of the OS sound card).
#
#   scripts/snd.sh song.mp3 song.u8
#   cat song.u8 > /dev/audio        # inside the OS (terminal, shell, beep)
#
# Playback is `paplay` over the host PulseAudio server; see
# MYOS_AUDIO_CMD in crates/osplat/src/trap.rs to redirect it.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: scripts/snd.sh <in.mp3|in.wav|...> <out.u8>" >&2
    exit 2
fi

command -v ffmpeg >/dev/null 2>&1 || {
    echo "snd.sh: need ffmpeg (apt-get install ffmpeg)" >&2
    exit 1
}

ffmpeg -y -v error -i "$1" -ar 8000 -ac 1 -f u8 "$2"
ls -la "$2"
