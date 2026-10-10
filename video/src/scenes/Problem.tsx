import React from 'react';
import { AbsoluteFill } from 'remotion';
import cues from '../cues.json';
import { Kinetic } from '../components';
import { C, FONT, HAND, ease, tween } from '../theme';

const P = cues.problem;

// Concept, not product: a paper register being filled in by hand while the
// lecture clock runs. The names are the fictional demo roster.
const ROWS = [
  ['Chiamaka Nwosu', 'DEMO230002'],
  ['Ibrahim Musa', 'DEMO230003'],
  ['Funke Adebayo', 'DEMO230004'],
  ['Emeka Eze', 'DEMO230005'],
  ['Aisha Bello', 'DEMO230006'],
  ['Daniel Okon', 'DEMO230007'],
];

const SIGNATURES = [
  'M4 30 C 18 4, 26 44, 40 18 S 62 8, 70 30 S 96 40, 112 14',
  'M4 26 C 14 8, 30 8, 34 30 C 38 46, 56 6, 70 24 C 80 36, 98 30, 116 18',
  'M4 34 C 20 0, 34 40, 50 20 C 60 8, 64 40, 84 24 S 104 10, 118 26',
  'M6 22 C 22 40, 30 0, 46 24 C 58 42, 70 6, 86 20 L 112 18',
  'M4 30 C 16 10, 24 10, 30 28 C 36 44, 52 2, 64 22 C 72 34, 96 34, 116 12',
  'M4 24 C 18 44, 34 2, 48 26 S 72 40, 86 16 S 108 22, 118 30',
];

const ROW_H = 74;

const Paper: React.FC<{ frame: number }> = ({ frame }) => (
  <div
    style={{
      position: 'relative',
      width: 820,
      height: 1080,
      borderRadius: 6,
      background: 'linear-gradient(160deg, #f6f1e6 0%, #ece5d6 60%, #e2dac8 100%)',
      boxShadow: '0 80px 140px rgba(0,0,0,0.65), 0 20px 40px rgba(0,0,0,0.4)',
      overflow: 'hidden',
    }}
  >
    {/* Ruled lines and the margin rule. */}
    <div
      style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: `repeating-linear-gradient(to bottom, transparent 0, transparent ${ROW_H - 2}px, rgba(70, 110, 160, 0.28) ${ROW_H - 2}px, rgba(70, 110, 160, 0.28) ${ROW_H}px)`,
        backgroundPosition: '0 196px',
      }}
    />
    <div style={{ position: 'absolute', left: 96, top: 0, bottom: 0, width: 2, background: 'rgba(200, 70, 70, 0.35)' }} />
    <div style={{ position: 'absolute', left: 120, top: 70, fontFamily: FONT, fontWeight: 600, fontSize: 26, letterSpacing: '0.16em', color: '#3a3833' }}>
      CSC 201 · ATTENDANCE SHEET
    </div>
    <div style={{ position: 'absolute', left: 120, right: 50, top: 150, display: 'flex', fontFamily: FONT, fontWeight: 600, fontSize: 15, letterSpacing: '0.14em', color: '#6b665c' }}>
      <span style={{ width: 300 }}>NAME</span>
      <span style={{ width: 200 }}>MATRIC NO.</span>
      <span>SIGNATURE</span>
    </div>
    {ROWS.map(([name, matric], i) => {
      const start = P.rowsWrite[i];
      const written = tween(frame, [start, start + P.rowWriteDuration], [0, 100], ease.soft);
      const signed = tween(frame, [start + 6, start + P.rowWriteDuration + 6], [1, 0], ease.soft);
      return (
        <div key={name} style={{ position: 'absolute', left: 120, right: 40, top: 200 + i * ROW_H, height: ROW_H, display: 'flex', alignItems: 'center' }}>
          <div style={{ display: 'flex', clipPath: `inset(-20px ${100 - written}% -20px 0)` }}>
            <span style={{ width: 300, fontFamily: HAND, fontWeight: 600, fontSize: 40, color: '#1e2d4a' }}>{name}</span>
            <span style={{ width: 200, fontFamily: HAND, fontWeight: 600, fontSize: 34, color: '#1e2d4a' }}>{matric}</span>
          </div>
          <svg width="124" height="48" viewBox="0 0 124 48" style={{ overflow: 'visible' }}>
            <path d={SIGNATURES[i]} fill="none" stroke="#1e2d4a" strokeWidth="2.6" strokeLinecap="round" pathLength={1} strokeDasharray="1" strokeDashoffset={signed} />
          </svg>
        </div>
      );
    })}
  </div>
);

export const Problem: React.FC<{ frame: number }> = ({ frame }) => {
  const exit = tween(frame, P.exit as [number, number], [0, 1], ease.in);
  const dolly = tween(frame, [0, 124], [0, 1], ease.inOut);
  const minutes = Math.min(9, Math.max(0, Math.floor((frame - P.clockTicksFrom) / 11)));
  const ring = tween(frame, [P.clockTicksFrom, P.clockTicksTo], [0, 0.75], ease.inOut);
  const stretch = tween(frame, P.slowStretch as [number, number], [0, 0.16], ease.out);

  return (
    <AbsoluteFill style={{ opacity: 1 - exit }}>
      {/* The register, lit by a desk lamp, in slow push. */}
      <AbsoluteFill style={{ perspective: 1900 }}>
        <div
          style={{
            position: 'absolute',
            left: 1010,
            top: 40,
            transformOrigin: '50% 40%',
            transform: `translateY(${60 - 70 * dolly}px) rotateX(${50 - 4 * dolly}deg) rotateZ(${-16 + 3 * dolly}deg) scale(${1.02 + 0.08 * dolly + 0.15 * exit})`,
            filter: `blur(${exit * 6}px)`,
          }}
        >
          <Paper frame={frame} />
        </div>
      </AbsoluteFill>

      {/* Keep the headline legible against the page. */}
      <AbsoluteFill style={{ background: 'linear-gradient(90deg, rgba(8,7,5,0.92) 0%, rgba(8,7,5,0.75) 38%, rgba(8,7,5,0) 62%)' }} />

      {/* The lecture clock: concept only, no figures about ScanMark. */}
      <div style={{ position: 'absolute', left: 140, top: 262, display: 'flex', alignItems: 'center', gap: 18, opacity: tween(frame, [4, 20], [0, 0.85]) }}>
        <svg width="46" height="46" viewBox="0 0 46 46">
          <circle cx="23" cy="23" r="19" fill="none" stroke="rgba(242,237,227,0.18)" strokeWidth="3" />
          <circle cx="23" cy="23" r="19" fill="none" stroke="#e8c27a" strokeWidth="3" strokeLinecap="round" pathLength={1} strokeDasharray={`${ring} 1`} transform="rotate(-90 23 23)" />
        </svg>
        <span style={{ fontFamily: FONT, fontWeight: 300, fontSize: 30, letterSpacing: '0.04em', color: 'rgba(242,237,227,0.8)' }}>
          10:0{minutes} AM
        </span>
        <span style={{ fontFamily: FONT, fontWeight: 500, fontSize: 16, letterSpacing: '0.18em', color: 'rgba(242,237,227,0.42)' }}>LECTURE TIME</span>
      </div>

      <div style={{ position: 'absolute', left: 136, top: 350, width: 1200, whiteSpace: 'nowrap' }}>
        <Kinetic frame={frame} words={[{ text: 'Attendance' }, { text: 'shouldn’t' }]} start={P.words[0]} stagger={P.words[1] - P.words[0]} size={76} color={C.warmWhite} />
        <div style={{ display: 'flex', alignItems: 'baseline' }}>
          <Kinetic frame={frame} words={[{ text: 'slow' }]} start={P.words[2]} size={76} color={C.warmWhite} tracking={`${-0.02 + stretch}em`} />
          <Kinetic frame={frame} words={[{ text: ' learning' }, { text: 'down.' }]} start={P.words[3]} stagger={P.words[4] - P.words[3]} size={76} color={C.warmWhite} />
        </div>
      </div>
    </AbsoluteFill>
  );
};
