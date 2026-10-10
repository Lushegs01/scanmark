import React from 'react';
import { AbsoluteFill, Audio, Img, staticFile, useCurrentFrame } from 'remotion';
import { Brand } from './scenes/Brand';
import { Credibility } from './scenes/Credibility';
import { EndCard } from './scenes/EndCard';
import { Impact } from './scenes/Impact';
import { Problem } from './scenes/Problem';
import { Signature } from './scenes/Signature';
import { FONT, ease, tween } from './theme';

/** Lighting: a lamp-lit room for the problem, ScanMark green after. */
const Backdrop: React.FC<{ frame: number }> = ({ frame }) => {
  const toGreen = tween(frame, [110, 132], [0, 1], ease.inOut);
  const drift = Math.sin(frame / 90) * 6;
  const endGlow = tween(frame, [796, 830], [0, 1], ease.soft);
  return (
    <>
      <AbsoluteFill
        style={{
          opacity: 1 - toGreen,
          background:
            'radial-gradient(ellipse 70% 60% at 76% 34%, rgba(255,186,104,0.17), rgba(255,186,104,0) 70%), radial-gradient(ellipse at 50% 50%, #12100c 0%, #070605 100%)',
        }}
      />
      <AbsoluteFill
        style={{
          opacity: toGreen,
          background: `radial-gradient(ellipse 60% 55% at ${50 + drift}% 36%, rgba(0,122,61,0.42), rgba(0,122,61,0) 72%), radial-gradient(ellipse 45% 40% at ${78 - drift}% 88%, rgba(255,215,0,0.06), rgba(255,215,0,0) 70%), linear-gradient(180deg, #03170c 0%, #020d07 100%)`,
        }}
      />
      <AbsoluteFill style={{ opacity: endGlow, background: 'radial-gradient(ellipse 55% 50% at 50% 46%, rgba(0,140,70,0.35), rgba(0,140,70,0) 75%)' }} />
    </>
  );
};

export const Film: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ background: '#020a05', fontFamily: FONT, overflow: 'hidden' }}>
      <Backdrop frame={frame} />
      {frame < 126 && <Problem frame={frame} />}
      {frame >= 114 && frame < 248 && <Brand frame={frame} />}
      {frame >= 230 && frame < 460 && <Signature frame={frame} />}
      {frame >= 444 && frame < 674 && <Credibility frame={frame} />}
      {frame >= 656 && frame < 808 && <Impact frame={frame} />}
      {frame >= 796 && <EndCard frame={frame} />}
      <AbsoluteFill style={{ pointerEvents: 'none', background: 'radial-gradient(ellipse at center, rgba(0,0,0,0) 58%, rgba(0,0,0,0.5) 100%)' }} />
      {/* Dither: a fixed 4.5 % grain plate keeps the gradients from banding. */}
      <AbsoluteFill style={{ pointerEvents: 'none', opacity: 0.045, mixBlendMode: 'overlay' }}>
        <Img src={staticFile('brand/grain.png')} style={{ width: 1920, height: 1080 }} />
      </AbsoluteFill>
      {/* Fade up from black. */}
      <AbsoluteFill style={{ background: '#000', opacity: tween(frame, [0, 16], [1, 0], ease.soft), pointerEvents: 'none' }} />
      <Audio src={staticFile('audio/soundtrack.wav')} />
    </AbsoluteFill>
  );
};

