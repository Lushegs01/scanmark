import React from 'react';
import { AbsoluteFill, Img, staticFile } from 'remotion';
import cues from '../cues.json';
import { Kinetic, LightSweep } from '../components';
import { C, ease, hash, tween } from '../theme';

const B = cues.brand;

// The logo exactly as ScanMark ships it (static/logo.png, 512x481, black on
// white), on a white tile so it is never recoloured.
const LOGO = staticFile('brand/logo.png');
const LOGO_W = 318;
const LOGO_H = (LOGO_W * 481) / 512;
const COLS = 16;
const ROWS = 15;

/** The real logo, assembled from its own pixels, one module at a time. */
const AssemblingLogo: React.FC<{ frame: number }> = ({ frame }) => {
  const [m0, m1] = B.modules;
  if (frame >= m1 + 2) {
    return <Img src={LOGO} style={{ width: LOGO_W, height: LOGO_H, display: 'block' }} />;
  }
  const cellW = LOGO_W / COLS;
  const cellH = LOGO_H / ROWS;
  const cells = [];
  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      const i = r * COLS + c;
      const dist = Math.hypot(c - COLS / 2, r - ROWS / 2) / Math.hypot(COLS / 2, ROWS / 2);
      const t0 = m0 + dist * (m1 - m0 - 14) + hash(i) * 6;
      const t = tween(frame, [t0, t0 + 14], [0, 1], ease.out);
      const dx = (hash(i + 0.3) - 0.5) * 340 * (1 - t);
      const dy = (hash(i + 0.7) - 0.5) * 340 * (1 - t);
      cells.push(
        <div
          key={i}
          style={{
            position: 'absolute',
            left: c * cellW,
            top: r * cellH,
            width: cellW + 0.6,
            height: cellH + 0.6,
            overflow: 'hidden',
            opacity: t,
            transform: `translate(${dx}px, ${dy}px) scale(${0.4 + 0.6 * t}) rotate(${(hash(i + 1.1) - 0.5) * 90 * (1 - t)}deg)`,
          }}
        >
          <Img src={LOGO} style={{ position: 'absolute', left: -c * cellW, top: -r * cellH, width: LOGO_W, height: LOGO_H, maxWidth: 'none' }} />
        </div>,
      );
    }
  }
  return <div style={{ position: 'relative', width: LOGO_W, height: LOGO_H }}>{cells}</div>;
};

export const Brand: React.FC<{ frame: number }> = ({ frame }) => {
  const tileIn = tween(frame, [B.tileIn, B.tileIn + 18], [0, 1], ease.out);
  const tileOpacity = tween(frame, [B.tileIn, B.tileIn + 5], [0, 1]);
  // The exit dives into the logo's QR modules, which the next scene's real
  // projector QR then takes over.
  const dive = tween(frame, B.zoomOut as [number, number], [0, 1], ease.in);
  const textOut = tween(frame, [B.zoomOut[0] - 4, B.zoomOut[0] + 8], [1, 0], ease.inOut);
  // Cut on the dive at full zoom, as the projector card focus-pulls in.
  const fadeOut = tween(frame, [B.zoomOut[0] + 14, B.zoomOut[0] + 21], [1, 0], ease.inOut);
  const lift = tween(frame, [B.words[0] - 6, B.words[0] + 16], [0, -70], ease.inOut);

  return (
    <AbsoluteFill style={{ opacity: fadeOut }}>
      <AbsoluteFill style={{ alignItems: 'center', justifyContent: 'center' }}>
        <div
          style={{
            position: 'absolute',
            left: 960 - 170,
            top: 540 - 170 + lift,
            width: 340,
            height: 340,
            borderRadius: 76,
            background: '#fdfdfd',
            boxShadow: `0 40px 90px rgba(0,0,0,${0.5 * tileIn}), 0 0 0 1px rgba(255,255,255,0.4), 0 0 120px rgba(0,168,84,${0.18 * tileIn})`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            overflow: 'hidden',
            opacity: tileOpacity,
            transformOrigin: '38% 36%',
            transform: `scale(${(0.7 + 0.3 * tileIn) * (1 + dive * 16)})`,
          }}
        >
          <AssemblingLogo frame={frame} />
          <LightSweep frame={frame} from={B.sweep[0]} to={B.sweep[1]} strength={0.55} />
        </div>
      </AbsoluteFill>
      <div style={{ position: 'absolute', left: 0, right: 0, top: 760, display: 'flex', justifyContent: 'center', opacity: textOut }}>
        <Kinetic
          frame={frame}
          words={[{ text: 'Meet', weight: 300 }, { text: 'Scan', weight: 800 }]}
          start={B.words[0]}
          stagger={B.words[1] - B.words[0]}
          size={100}
          align="center"
        />
        <Kinetic frame={frame} words={[{ text: 'Mark.', weight: 800, color: C.gold }]} start={B.words[1]} size={100} align="center" style={{ marginLeft: -2 }} />
      </div>
    </AbsoluteFill>
  );
};
