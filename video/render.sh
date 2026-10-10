#!/usr/bin/env bash
# Render the 30-second ScanMark launch film to ../artifacts/scanmark-launch-film.mp4
#
#   npm install                    # once
#   AUDIO_PYTHON=python3 bash render.sh
#
# AUDIO_PYTHON must have numpy, scipy and pillow (soundtrack + grain plate).
# REMOTION_BROWSER_EXECUTABLE may point at an existing Chromium; without it
# Remotion downloads its own headless shell.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
OUT="${1:-../artifacts/scanmark-launch-film.mp4}"

bash scripts/prepare-assets.sh
npx tsc -p tsconfig.json

BROWSER_FLAG=()
if [ -n "${REMOTION_BROWSER_EXECUTABLE:-}" ]; then
    BROWSER_FLAG=(--browser-executable="$REMOTION_BROWSER_EXECUTABLE")
fi

npx remotion render src/index.ts ScanMarkLaunch "$OUT" \
    --codec=h264 --crf=16 --x264-preset=slow --pixel-format=yuv420p --color-space=bt709 \
    --audio-codec=aac --audio-bitrate=256k \
    --concurrency="${RENDER_CONCURRENCY:-4}" --gl=swangle "${BROWSER_FLAG[@]}"

ffprobe -v error -show_entries stream=codec_type,codec_name,profile,width,height,r_frame_rate,pix_fmt,sample_rate,channels:format=duration,size,bit_rate -of compact "$OUT"
