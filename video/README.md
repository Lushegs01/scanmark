# ScanMark launch film (Remotion)

The 30-second launch film, built as a Remotion (React) composition around **real ScanMark captures**. The rendered film is [`../artifacts/scanmark-launch-film.mp4`](../artifacts/scanmark-launch-film.mp4): 1920×1080, 30 fps, H.264 (High) + AAC stereo.

## Re-render it

```bash
cd video
npm install
AUDIO_PYTHON=python3 bash render.sh          # stages assets, synthesizes audio, renders, probes
```

- `AUDIO_PYTHON` needs `numpy`, `scipy` and `pillow`.
- Set `REMOTION_BROWSER_EXECUTABLE` to use an existing Chromium. Without it, Remotion downloads its own headless shell.
- A render takes about 8 minutes on 4 CPU cores.
- `npm run studio` opens the composition in Remotion Studio for scrubbing and editing.
- `node scripts/stills.mjs <dir> <frame> …` renders single frames for review.

The camera captures come from `../artifacts/scanmark-demo/`. See its README for how they were made against an isolated, fictional dataset. `scripts/prepare-assets.sh` copies them into `public/`, which is generated and git-ignored.

## How it is built

| File | Role |
|---|---|
| `src/cues.json` | **The cue sheet.** Every timed event, in frames. The picture *and* the soundtrack read it, so they can't drift apart. |
| `src/Film.tsx` | Lighting (a lamp-lit room → ScanMark green), the six scenes on their windows, vignette, grain, audio |
| `src/scenes/Problem.tsx` | 0–4 s: a paper register filling up by hand while the lecture clock runs (concept, no product UI) |
| `src/scenes/Brand.tsx` | 4–8 s: the real logo assembles from its own pixels, then the camera dives into its QR |
| `src/scenes/Signature.tsx` | 8–15 s: the real projector QR, a scanning beam, the phone's real scan footage, the real confirmation, Tolu Adeyemi landing on the real roll call |
| `src/scenes/Credibility.tsx` | 15–22 s: the live roll call (real footage), the register, analytics and the CSV export button |
| `src/scenes/Impact.tsx` | 22–27 s: the four real screens as one workflow |
| `src/scenes/EndCard.tsx` | 27–30 s: logo, wordmark, supporting line |
| `src/components.tsx` | Crop-accurate windows onto stills (`Shot`) and footage (`Footage`), kinetic type, light sweeps, device frame, highlights |
| `audio/make_soundtrack.py` | Synthesizes the music and every sound effect from scratch, cue by cue |

## What is real and what is graphic

- **Real (unaltered captures, only cropped, scaled and placed in 3D):** every ScanMark screen, the projector QR, both screen recordings (`08` phone, `09` desktop), the logo (`ScanMark/static/logo.png`, on a white tile so it is never recoloured), and the names, matric numbers and figures on screen. All data is the fictional demo dataset.
- **Graphic (motion design):**
  - the paper register and clock in the opening
  - the scanning beam and lock-on brackets
  - the light sweeps and the gold highlights that point at real rows
  - the success ring
  - the three callouts in the scan beat ("Signed, rotating code", "Inside the classroom geofence", "Enrolled in CSC 201")
  - the workflow labels and connector

  The callouts name checks the server really performs on every scan: an HMAC-signed token that refreshes every 12 s, `GEOFENCE_REQUIRED` against the saved room, and enrolment.
- **Timing:** the phone footage keeps its real pace. The roll-call footage in the "Real-time attendance" beat plays at 1.5×, and the arrivals it shows are real. The projector really refreshes that list every second.

## Sound

Original, with no samples and no third-party music. `audio/make_soundtrack.py` builds it from:
- a pad from detuned additive voices
- a Karplus-Strong plucked arpeggio
- a synthesized kick, hats and snare
- bells, whooshes, risers, UI pops, clock ticks and pen scratches from filtered noise and oscillators

It's 120 BPM, starting on the brand reveal, so every scene boundary falls on a beat. The output is 48 kHz stereo, peaked at −1 dBFS, and fades to silence by 29.9 s.

## Licences

- Poppins (the app's own typeface) and Caveat are SIL Open Font License, installed from npm (`@fontsource`).
- Remotion is free for individuals and companies of up to three people; larger organisations need a company licence from remotion.pro before using this project commercially.
