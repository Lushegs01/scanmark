#!/usr/bin/env bash
# Stage the film's inputs in public/ (generated, git-ignored):
#   - the real ScanMark captures from ../artifacts/scanmark-demo
#   - the logo exactly as the app ships it (ScanMark/static/logo.png)
#   - Poppins (the app's own typeface) and Caveat, both SIL OFL, from npm
#   - the synthesized soundtrack (audio/make_soundtrack.py)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPTURES="$HERE/../artifacts/scanmark-demo"
PUBLIC="$HERE/public"
PYTHON="${AUDIO_PYTHON:-python3}"

mkdir -p "$PUBLIC/shots" "$PUBLIC/footage" "$PUBLIC/brand" "$PUBLIC/fonts" "$PUBLIC/audio"
for shot in 01-product-dashboard 02-lecturer-session-qr 02b-lecturer-live-checkins 03-student-checkin \
            04-attendance-confirmation 05-attendance-records 05b-attendance-records-full \
            06b-dashboard-analytics-full 07-mobile-experience; do
    cp "$CAPTURES/$shot.png" "$PUBLIC/shots/"
done
cp "$CAPTURES/editing-mezzanine/08-student-checkin-flow.mp4" "$PUBLIC/footage/"
cp "$CAPTURES/editing-mezzanine/09-lecturer-dashboard-flow.mp4" "$PUBLIC/footage/"
cp "$HERE/../ScanMark/static/logo.png" "$PUBLIC/brand/logo.png"
for weight in 300 400 500 600 700 800; do
    cp "$HERE/node_modules/@fontsource/poppins/files/poppins-latin-$weight-normal.woff2" "$PUBLIC/fonts/"
done
cp "$HERE/node_modules/@fontsource/caveat/files/caveat-latin-600-normal.woff2" "$PUBLIC/fonts/"
"$PYTHON" "$HERE/audio/make_soundtrack.py" "$PUBLIC/audio/soundtrack.wav"
# A fixed grain plate (seeded), overlaid at 4.5 % to dither the dark gradients.
"$PYTHON" - "$PUBLIC/brand/grain.png" <<'PY'
import sys
import numpy as np
from PIL import Image
noise = np.random.default_rng(7).normal(128, 42, (1080, 1920)).clip(0, 255).astype('uint8')
Image.fromarray(noise, 'L').save(sys.argv[1])
PY
echo "prepare-assets: staged $(find "$PUBLIC" -type f | wc -l) files in public/"
