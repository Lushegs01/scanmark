import React from 'react';
import { AbsoluteFill, Img, staticFile } from 'remotion';
import cues from '../cues.json';
import { LightSweep } from '../components';
import { C, FONT, ease, tween } from '../theme';

const E = cues.endCard;
const LETTERS = [...'Scan'].map((l) => ({ l, color: C.white })).concat([...'Mark'].map((l) => ({ l, color: C.gold })));

export const EndCard: React.FC<{ frame: number }> = ({ frame }) => {
  const tile = tween(frame, [E.tileIn, E.tileIn + 22], [0, 1], ease.out);
  const rule = tween(frame, E.rule as [number, number], [0, 1], ease.inOut);
  const tagline = tween(frame, [E.tagline, E.tagline + 20], [0, 1], ease.out);
  // Everything is settled by frame ~872; the last second is a clean hold.
  return (
    <AbsoluteFill style={{ opacity: tween(frame, [804, 814], [0, 1], ease.soft) }}>
      <div
        style={{
          position: 'absolute',
          left: 960 - 118,
          top: 236,
          width: 236,
          height: 236,
          borderRadius: 54,
          background: '#fdfdfd',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          overflow: 'hidden',
          opacity: tile,
          transform: `translateY(${40 * (1 - tile)}px) scale(${0.82 + 0.18 * tile})`,
          boxShadow: '0 40px 90px rgba(0,0,0,0.5), 0 0 140px rgba(0,168,84,0.22)',
        }}
      >
        <Img src={staticFile('brand/logo.png')} style={{ width: 222, height: (222 * 481) / 512 }} />
        <LightSweep frame={frame} from={E.sweep[0]} to={E.sweep[1]} strength={0.6} />
      </div>

      <div style={{ position: 'absolute', left: 0, right: 0, top: 528, display: 'flex', justifyContent: 'center', fontFamily: FONT, fontWeight: 800, fontSize: 132, letterSpacing: '-0.035em', lineHeight: 1 }}>
        {LETTERS.map(({ l, color }, i) => {
          const t = tween(frame, [E.wordmark + i * 1.6, E.wordmark + i * 1.6 + 16], [0, 1], ease.out);
          return (
            <span key={i} style={{ display: 'inline-block', overflow: 'hidden', paddingBottom: 16, marginBottom: -16 }}>
              <span style={{ display: 'inline-block', color, transform: `translateY(${(1 - t) * 105}%)`, opacity: t }}>{l}</span>
            </span>
          );
        })}
      </div>

      <div style={{ position: 'absolute', left: 960 - 160 * rule, top: 700, width: 320 * rule, height: 3, borderRadius: 2, background: `linear-gradient(90deg, rgba(255,215,0,0), ${C.gold} 20%, ${C.gold} 80%, rgba(255,215,0,0))` }} />

      <div style={{ position: 'absolute', left: 0, right: 0, top: 734, textAlign: 'center', fontFamily: FONT, fontWeight: 400, fontSize: 42, letterSpacing: '0.01em', color: 'rgba(245,248,246,0.86)', opacity: tagline, transform: `translateY(${18 * (1 - tagline)}px)` }}>
        Smarter attendance. Less friction.
      </div>
    </AbsoluteFill>
  );
};
