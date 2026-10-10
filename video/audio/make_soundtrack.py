"""
Synthesize the ScanMark launch film's soundtrack: music bed and sound design.

Everything is generated here from oscillators, filtered noise and a
Karplus-Strong string: no samples, no loops, no third-party audio, so the
mix carries no licence beyond this repository's own. Every hit is placed
from ../src/cues.json, the same cue sheet the picture is cut to.

    python make_soundtrack.py ../public/audio/soundtrack.wav

Output: 30.000 s, 48 kHz, stereo, 16-bit PCM WAV, peak -1 dBFS.
"""
import json
import sys
from pathlib import Path

import numpy as np
from scipy.io import wavfile
from scipy.signal import butter, fftconvolve, lfilter, sosfilt

SR = 48_000
CUES = json.loads((Path(__file__).resolve().parent.parent / 'src' / 'cues.json').read_text())
FPS = CUES['fps']
LENGTH = CUES['durationInFrames'] / FPS
N = int(round(LENGTH * SR))
rng = np.random.default_rng(2026)

dry = np.zeros((N, 2))      # straight to the mix
wet = np.zeros((N, 2))      # also sent to the reverb


def sec(frame):
    return frame / FPS


def at(frame):
    return int(round(sec(frame) * SR))


def tvec(duration):
    return np.arange(int(duration * SR)) / SR


def place(bus, signal, start_frame, gain=1.0, pan=0.0):
    """Add a mono or stereo signal at a frame, with constant-power pan."""
    start = at(start_frame)                 # frames; fractional frames are fine
    if start >= N:
        return
    if signal.ndim == 1:
        angle = (pan + 1) * np.pi / 4
        signal = np.stack([signal * np.cos(angle), signal * np.sin(angle)], axis=1)
    end = min(N, start + len(signal))
    bus[start:end] += signal[:end - start] * gain


def db(value):
    return 10 ** (value / 20)


def bandpass(signal, low, high, order=2):
    sos = butter(order, [low, high], btype='bandpass', fs=SR, output='sos')
    return sosfilt(sos, signal)


def lowpass(signal, cutoff, order=2):
    return sosfilt(butter(order, cutoff, btype='lowpass', fs=SR, output='sos'), signal, axis=0)


def highpass(signal, cutoff, order=2):
    return sosfilt(butter(order, cutoff, btype='highpass', fs=SR, output='sos'), signal, axis=0)


def midi(note):
    return 440.0 * 2 ** ((note - 69) / 12)


def swept_band_noise(duration, f_start, f_end, q=3.0):
    """Noise through a band-pass whose centre glides, block by block."""
    noise = rng.standard_normal(int(duration * SR))
    out = np.zeros_like(noise)
    block = 1024
    for i in range(0, len(noise), block):
        frac = i / max(1, len(noise) - 1)
        centre = f_start * (f_end / f_start) ** frac
        low, high = centre / (1 + 1 / q), min(SR / 2 - 100, centre * (1 + 1 / q))
        segment = noise[max(0, i - 2048):i + block]
        filtered = bandpass(segment, max(30, low), high)
        out[i:i + block] = filtered[-len(noise[i:i + block]):]
    return out


# ---------------------------------------------------------------------------
# Instruments
# ---------------------------------------------------------------------------

CHORDS = {
    'Fmaj7': [53, 57, 60, 64], 'G6': [55, 59, 62, 64], 'Am9': [57, 60, 64, 67, 71],
    'Cadd9': [60, 64, 67, 74], 'Cmaj9': [60, 64, 67, 71, 74],
}
ROOTS = {'Fmaj7': 41, 'G6': 43, 'Am9': 45, 'Cadd9': 48, 'Cmaj9': 36}


def pad_note(freq, duration, attack=0.7, release=1.0):
    """A warm, slowly breathing pad voice: detuned soft-saw partials."""
    t = tvec(duration + release)
    voice = np.zeros((len(t), 2))
    for side, cents in ((0, -7), (1, 7), (0, 3), (1, -3)):
        f = freq * 2 ** (cents / 1200)
        tone = sum(np.sin(2 * np.pi * f * k * t + k) / k ** 1.6 for k in range(1, 7))
        voice[:, side] += tone
    env = np.minimum(1, t / attack)
    env *= np.where(t > duration, np.exp(-(t - duration) / (release / 3)), 1)
    env *= 1 + 0.06 * np.sin(2 * np.pi * 0.23 * t)          # slow swell
    return voice * env[:, None] * 0.25


def pluck(freq, decay=0.996, duration=1.4, brightness=0.5):
    """Karplus-Strong string: a comb filter excited by a short noise burst."""
    delay = max(2, int(round(SR / freq)))
    burst = np.zeros(int(duration * SR))
    burst[:delay] = lowpass(rng.uniform(-1, 1, delay), 1500 + 6000 * brightness)
    a = np.zeros(delay + 2)
    a[0], a[delay], a[delay + 1] = 1, -0.5 * decay, -0.5 * decay
    return lfilter([1.0], a, burst) * 0.6


def bell(freq, duration=2.2, partials=((1, 1), (2.76, 0.45), (5.4, 0.22), (8.93, 0.1))):
    t = tvec(duration)
    out = np.zeros_like(t)
    for ratio, amp in partials:
        out += amp * np.sin(2 * np.pi * freq * ratio * t) * np.exp(-t * (1.6 + ratio * 0.9))
    return out * np.minimum(1, t / 0.004)


def kick(gain=1.0):
    t = tvec(0.45)
    freq = 42 + 75 * np.exp(-t / 0.035)
    body = np.sin(2 * np.pi * np.cumsum(freq) / SR) * np.exp(-t / 0.16)
    click = rng.standard_normal(len(t)) * np.exp(-t / 0.002) * 0.15
    return (body + click) * gain


def hat():
    t = tvec(0.06)
    return highpass(rng.standard_normal(len(t)), 7000) * np.exp(-t / 0.012) * 0.35


def snare():
    t = tvec(0.25)
    tone = np.sin(2 * np.pi * 185 * t) * np.exp(-t / 0.05)
    noise = bandpass(rng.standard_normal(len(t)), 1500, 7000) * np.exp(-t / 0.07)
    return (0.5 * tone + 0.7 * noise) * 0.5


def click(freq=2400, length=0.03, noise=0.4):
    t = tvec(length)
    ping = np.sin(2 * np.pi * freq * t) * np.exp(-t / (length / 4))
    tick = highpass(rng.standard_normal(len(t)), 2500) * np.exp(-t / 0.0015) * noise
    return ping + tick


def ui_pop(f0=820, f1=1240, length=0.11):
    t = tvec(length)
    freq = f0 + (f1 - f0) * (1 - np.exp(-t / 0.02))
    return np.sin(2 * np.pi * np.cumsum(freq) / SR) * np.exp(-t / 0.035) * np.minimum(1, t / 0.002)


def whoosh(duration, f_start=250, f_end=3200, peak_at=0.55):
    sweep = swept_band_noise(duration, f_start, f_end, q=2.2)
    t = tvec(duration)[:len(sweep)]
    env = np.where(t < duration * peak_at, (t / (duration * peak_at)) ** 2,
                   np.exp(-(t - duration * peak_at) / (duration * 0.18)))
    return sweep * env


def riser(duration, f_start=300, f_end=5000):
    sweep = swept_band_noise(duration, f_start, f_end, q=4)
    t = tvec(duration)[:len(sweep)]
    tone = np.sin(2 * np.pi * np.cumsum(220 * (3.5 ** (t / duration))) / SR) * 0.25
    env = (t / duration) ** 2.5
    return (sweep + tone) * env


def boom(freq=50, length=1.3):
    t = tvec(length)
    sub = np.sin(2 * np.pi * freq * t) * np.exp(-t / 0.38)
    thump = lowpass(rng.standard_normal(len(t)), 220) * np.exp(-t / 0.07) * 1.6
    return (sub + thump) * np.minimum(1, t / 0.003)


# ---------------------------------------------------------------------------
# Music bed (from the brand reveal onwards)
# ---------------------------------------------------------------------------

music = CUES['music']
chord_frames = music['chordFrames'] + [CUES['durationInFrames']]
beat = FPS * 60 / music['bpm']                                # 15 frames


def section_gain(frame):
    """How present the bed is in each part of the film."""
    if frame < 240:
        return 0.55
    if frame < 450:
        return 0.8
    if frame < 660:
        return 1.0
    if frame < 810:
        return 0.75
    return 1.0


for index, name in enumerate(music['chords']):
    start, end = chord_frames[index], chord_frames[index + 1]
    held = sec(end - start) + (1.4 if name == 'Cmaj9' else 0.15)
    for note in CHORDS[name]:
        place(wet, pad_note(midi(note), held), start, gain=0.075 * section_gain(start))
    # Sub bass on the root from the signature moment onwards.
    if start >= 240:
        t = tvec(sec(end - start) + 0.3)
        root = midi(ROOTS[name])
        bass = (np.sin(2 * np.pi * root * t) + 0.25 * np.sin(4 * np.pi * root * t))
        bass *= np.minimum(1, t / 0.04) * np.where(t > sec(end - start), np.exp(-(t - sec(end - start)) / 0.1), 1)
        if name == 'Cmaj9':
            bass *= np.exp(-t / 1.1)
        place(dry, bass, start, gain=0.16 * section_gain(start))

# Plucked arpeggio: eighth notes through the signature and credibility
# sections, quarter notes while the impact composition breathes.
pattern = [0, 2, 1, 3, 2, 1, 3, 2]
for index, name in enumerate(music['chords'][:-1]):
    start, end = chord_frames[index], chord_frames[index + 1]
    if start < 240 or start >= 810:
        continue
    step = beat if start >= 660 else beat / 2
    tones = [n + 12 for n in CHORDS[name]]
    frame, i = float(start), 0
    while frame < end - 1 and frame < 792:
        note = tones[pattern[i % len(pattern)] % len(tones)]
        accent = 1.0 if i % 4 == 0 else 0.7
        place(wet, pluck(midi(note), brightness=0.35 + 0.3 * accent), frame,
              gain=0.10 * accent * section_gain(start), pan=0.35 * np.sin(i * 1.3))
        frame += step
        i += 1

# Rhythm: half-time through the signature, driving under the credibility
# section, half-time again for the impact composition.
frame = 240.0
while frame < 792:
    in_drive = 450 <= frame < 660
    in_half = (240 <= frame < 450) or (660 <= frame < 792)
    beat_index = int(round((frame - 120) / beat))
    if in_drive or (in_half and beat_index % 2 == 0):
        place(dry, kick(), frame, gain=0.32)
    if in_drive:
        place(dry, hat(), frame + beat / 2, gain=0.10, pan=0.25)
        if beat_index % 2 == 1:
            place(wet, snare(), frame, gain=0.12)
    frame += beat

# ---------------------------------------------------------------------------
# Sound design
# ---------------------------------------------------------------------------

p, b, s, c, im, e = (CUES[k] for k in ('problem', 'brand', 'signature', 'credibility', 'impact', 'endCard'))

# 0-4 s: a quiet room, a clock and pens.
room = lowpass(np.cumsum(rng.standard_normal(at(126))) * 0.002, 380)
room -= room.mean()
room_t = np.arange(len(room)) / SR
room *= np.minimum(1, room_t / 0.6) * np.clip((sec(126) - room_t) / 0.5, 0, 1)
place(dry, room / (np.abs(room).max() + 1e-9), 0, gain=db(-27))
# A low, unresolved drone under the problem: A2 and E3, swelling into the reveal.
drone_t = tvec(sec(124))
drone = sum(np.sin(2 * np.pi * midi(n) * drone_t + i) * (0.6 if i else 1.0) for i, n in enumerate((45, 52, 57)))
drone = lowpass(drone, 700) * np.minimum(1, drone_t / 1.2) * (0.75 + 0.25 * drone_t / drone_t[-1])
drone *= np.clip((sec(124) - drone_t) / 0.25, 0, 1)
place(wet, drone, 0, gain=db(-24))
for i, frame in enumerate(range(p['clockTicksFrom'], p['clockTicksTo'], p['clockTickEvery'])):
    place(wet, click(2600 if i % 2 == 0 else 2100, 0.025, 0.6), frame, gain=db(-20), pan=0.3)
for frame in p['rowsWrite']:
    duration = sec(p['rowWriteDuration'])
    t = tvec(duration)
    jitter = 0.55 + 0.45 * np.abs(np.sin(2 * np.pi * rng.uniform(18, 28) * t + rng.uniform(0, 3)))
    scratch = bandpass(rng.standard_normal(len(t)), 2200, 6500) * jitter
    scratch *= np.minimum(1, t / 0.03) * np.minimum(1, (duration - t) / 0.08)
    place(dry, scratch, frame, gain=db(-23), pan=0.45)
place(dry, riser(sec(p['riser'][1] - p['riser'][0])), p['riser'][0], gain=db(-14))

# 4-8 s: the logo assembles.
place(dry, boom(52), b['impact'], gain=db(-9))
for frame in np.sort(rng.uniform(b['modules'][0], b['modules'][1], 13)):
    place(wet, click(rng.uniform(2300, 4200), 0.05, 0.1), frame, gain=db(-27), pan=rng.uniform(-0.6, 0.6))
for i, note in enumerate((84, 88, 91)):                       # C6 E6 G6
    place(wet, bell(midi(note), 2.6), b['glassHit'] + i, gain=db(-17) * (1 - 0.15 * i), pan=(i - 1) * 0.3)
place(dry, whoosh(sec(b['zoomOut'][1] - b['zoomOut'][0]), 220, 3600, 0.75), b['zoomOut'][0], gain=db(-15))

# 8-15 s: the scan.
beam_t = tvec(sec(s['beam'][1] - s['beam'][0]))
beam_f = 520 * (1250 / 520) ** (beam_t / beam_t[-1])
beam = np.sin(2 * np.pi * np.cumsum(beam_f) / SR) * 0.6 + bandpass(rng.standard_normal(len(beam_t)), 900, 3000) * 0.25
beam *= np.sin(np.pi * beam_t / beam_t[-1]) ** 1.5
place(wet, beam, s['beam'][0], gain=db(-25), pan=-0.1)
place(wet, click(1760, 0.07, 0.05), s['lock'], gain=db(-17))
place(wet, click(2349, 0.09, 0.05), s['lock'] + 4, gain=db(-17))
place(dry, whoosh(0.8, 300, 2600), s['phoneIn'][0] - 4, gain=db(-17), pan=0.4)
for frame in s['chips']:
    place(wet, ui_pop(700, 980, 0.09), frame, gain=db(-24), pan=0.35)
place(wet, bell(midi(84), 2.4, ((1, 1), (2.0, 0.3), (3.0, 0.12))), s['success'], gain=db(-13))
place(wet, bell(midi(91), 2.4, ((1, 1), (2.0, 0.3), (3.0, 0.12))), s['success'] + 4, gain=db(-14))
place(dry, boom(60, 0.6), s['success'], gain=db(-17))
place(wet, ui_pop(900, 1300), s['highlight'], gain=db(-24), pan=-0.4)
place(dry, whoosh(0.7, 260, 2800), s['exit'][0], gain=db(-18), pan=-0.3)

# 15-22 s: records and analytics.
place(dry, whoosh(0.6, 300, 3000), c['whoosh'], gain=db(-18), pan=0.3)
for frame in c['rtArrivals']:
    place(wet, ui_pop(880, 1320, 0.1), frame, gain=db(-22), pan=0.45)
place(dry, whoosh(0.55, 400, 3200), c['records'][0] - 4, gain=db(-20), pan=0.3)
place(wet, ui_pop(760, 1140), c['recordsHighlight'], gain=db(-22))
place(dry, whoosh(0.55, 400, 3200), c['analytics'][0] - 2, gain=db(-20), pan=0.3)
shimmer_len = sec(c['chartReveal'][1] - c['chartReveal'][0])
place(wet, riser(shimmer_len, 1200, 7000) * 0.8, c['chartReveal'][0], gain=db(-24))
place(wet, ui_pop(1000, 1500), c['csvChip'], gain=db(-22), pan=0.3)
place(dry, whoosh(0.8, 250, 2500), c['exit'][0], gain=db(-17))

# 22-27 s: the workflow.
place(dry, boom(46, 1.0), im['softImpact'], gain=db(-16))
for i, frame in enumerate(im['cards']):
    place(wet, click(1900 + 220 * i, 0.04, 0.15), frame, gain=db(-24), pan=-0.6 + 0.4 * i)
connector_len = sec(im['connector'][1] - im['connector'][0])
glide = tvec(connector_len)
glide_tone = np.sin(2 * np.pi * np.cumsum(1500 + 900 * glide / connector_len) / SR)
glide_tone *= np.sin(np.pi * glide / connector_len) * 0.3
place(wet, glide_tone + riser(connector_len, 2500, 8000) * 0.4, im['connector'][0], gain=db(-29))
place(dry, riser(sec(im['riser'][1] - im['riser'][0]), 250, 4500), im['riser'][0], gain=db(-15))

# 27-30 s: the end card.
place(dry, boom(41, 2.5), e['hit'], gain=db(-8))
for i, note in enumerate((72, 76, 79, 83, 86)):                # C5 E5 G5 B5 D6
    place(wet, bell(midi(note), 3.2), e['hit'] + i * 1.5, gain=db(-17), pan=(i - 2) * 0.22)
place(wet, bell(midi(96), 2.0, ((1, 1), (2.76, 0.2))), e['sweep'][0], gain=db(-27), pan=0.2)

# ---------------------------------------------------------------------------
# Space and master
# ---------------------------------------------------------------------------

ir_t = tvec(2.2)
impulse = np.stack([rng.standard_normal(len(ir_t)), rng.standard_normal(len(ir_t))], axis=1)
impulse *= np.exp(-ir_t / 0.5)[:, None]
impulse = lowpass(impulse, 6500)
impulse /= np.sqrt((impulse ** 2).sum(axis=0))
reverb = np.stack([fftconvolve(wet[:, ch], impulse[:, ch])[:N] for ch in range(2)], axis=1)

mix = dry + wet + reverb * 0.55
mix = highpass(mix, 28)
fade = np.clip((LENGTH - 0.12 - np.arange(N) / SR) / 0.9, 0, 1)    # silent by the last frame
mix *= fade[:, None]
mix = np.tanh(mix * 1.4) / 1.4                                     # gentle ceiling
mix *= db(-1) / np.abs(mix).max()

out = Path(sys.argv[1] if len(sys.argv) > 1 else 'soundtrack.wav')
out.parent.mkdir(parents=True, exist_ok=True)
wavfile.write(out, SR, (mix * 32767).astype(np.int16))
rms = 20 * np.log10(np.sqrt((mix ** 2).mean()) + 1e-12)
print(f'make_soundtrack: {out} {LENGTH:.3f}s {SR} Hz stereo, peak -1.0 dBFS, rms {rms:.1f} dBFS')
