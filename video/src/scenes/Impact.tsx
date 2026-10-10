import React from 'react';
import { AbsoluteFill } from 'remotion';
import cues from '../cues.json';
import { Kinetic, Phone, Plane, SHOT, Shot } from '../components';
import { C, FONT, ease, tween } from '../theme';

const I = cues.impact;
const CARD_H = 380;
const TOP = 350;
const DOT_Y = TOP + CARD_H + 64;

// One step of the workflow each, all real captures. The labels describe what
// the app does at that step and nothing more.
const STEPS = [
  { label: 'Open a class', shot: SHOT.dashboard, crop: { x: 588, y: 886, w: 882, h: 840 } },
  { label: 'Students scan', phone: true },
  { label: 'Register updates', shot: SHOT.rollCall, crop: { x: 2166, y: 764, w: 1048, h: 900 } },
  { label: 'Review the term', shot: SHOT.analytics, crop: { x: 1944, y: 204, w: 1072, h: 888 } },
] as const;

const PHONE_SCREEN = 168;
const widthOf = (step: (typeof STEPS)[number]) =>
  'phone' in step ? PHONE_SCREEN * 1.09 : (CARD_H * step.crop.w) / step.crop.h;
const GAP = 64;
const TOTAL = STEPS.reduce((sum, step) => sum + widthOf(step), 0) + GAP * (STEPS.length - 1);
const LEFTS = STEPS.reduce<number[]>((acc, step, i) => [...acc, i === 0 ? (1920 - TOTAL) / 2 : acc[i - 1] + widthOf(STEPS[i - 1]) + GAP], []);
const CENTRES = STEPS.map((step, i) => LEFTS[i] + widthOf(step) / 2);
const TILT = [11, 4, -4, -11];

export const Impact: React.FC<{ frame: number }> = ({ frame }) => {
  const enter = tween(frame, [656, 664], [0, 1], ease.out);
  const exit = tween(frame, I.exit as [number, number], [0, 1], ease.in);
  const orbit = tween(frame, [660, 810], [-5, 5], ease.inOut);
  const draw = tween(frame, I.connector as [number, number], [0, 1], ease.inOut);
  const lineStart = CENTRES[0];
  const lineEnd = CENTRES[CENTRES.length - 1];
  const travel = lineStart + (lineEnd - lineStart) * draw;

  return (
    <AbsoluteFill style={{ opacity: enter * (1 - exit) }}>
      <div style={{ position: 'absolute', left: 0, right: 0, top: 176, display: 'flex', justifyContent: 'center' }}>
        <Kinetic
          frame={frame}
          words={[{ text: 'Built' }, { text: 'for' }, { text: 'modern' }, { text: 'university' }, { text: 'campuses.', color: C.gold }]}
          start={I.headline}
          stagger={3}
          size={70}
          align="center"
        />
      </div>

      <AbsoluteFill style={{ perspective: 2000 }}>
        <AbsoluteFill style={{ transformStyle: 'preserve-3d', transform: `rotateY(${orbit}deg) scale(${1 - 0.06 * exit})` }}>
          {/* A soft pool of light the row stands in. */}
          <div style={{ position: 'absolute', left: 260, right: 260, top: TOP + CARD_H - 30, height: 120, borderRadius: '50%', background: 'radial-gradient(ellipse at center, rgba(0,168,84,0.22), rgba(0,168,84,0) 70%)' }} />

          {STEPS.map((step, i) => {
            const t = tween(frame, [I.cards[i], I.cards[i] + 20], [0, 1], ease.out);
            return (
              <div
                key={step.label}
                style={{
                  position: 'absolute',
                  left: LEFTS[i],
                  top: TOP + ('phone' in step ? -19 : 0),
                  opacity: t,
                  transform: `translateY(${70 * (1 - t)}px) rotateY(${TILT[i]}deg) rotateX(${14 * (1 - t)}deg) translateZ(${i === 0 || i === 3 ? -40 : 0}px)`,
                }}
              >
                {'phone' in step ? (
                  <Phone screenWidth={PHONE_SCREEN}>
                    <Shot shot={SHOT.scanner} width={PHONE_SCREEN} />
                  </Phone>
                ) : (
                  <Plane radius={14}>
                    <Shot shot={step.shot} crop={step.crop} width={widthOf(step)} />
                  </Plane>
                )}
              </div>
            );
          })}

          {/* The connector: one organised path through the four steps. */}
          <div style={{ position: 'absolute', left: lineStart, top: DOT_Y - 1, width: (lineEnd - lineStart) * draw, height: 2, background: `linear-gradient(90deg, rgba(255,215,0,0.15), ${C.gold})` }} />
          {draw > 0 && draw < 1 && (
            <div style={{ position: 'absolute', left: travel - 9, top: DOT_Y - 9, width: 18, height: 18, borderRadius: '50%', background: '#fff6c2', boxShadow: '0 0 18px 6px rgba(255,215,0,0.55)' }} />
          )}
          {STEPS.map((step, i) => {
            const reached = tween(frame, [I.connector[0] + ((I.connector[1] - I.connector[0]) * i) / 3 - 2, I.connector[0] + ((I.connector[1] - I.connector[0]) * i) / 3 + 8], [0, 1], ease.out);
            const shown = tween(frame, [I.cards[i] + 6, I.cards[i] + 20], [0, 1]);
            return (
              <div key={step.label} style={{ position: 'absolute', left: CENTRES[i] - 200, width: 400, top: DOT_Y - 8, display: 'flex', flexDirection: 'column', alignItems: 'center', opacity: shown }}>
                <div style={{ width: 16, height: 16, borderRadius: '50%', background: reached > 0.5 ? C.gold : 'rgba(255,255,255,0.25)', boxShadow: reached > 0.5 ? '0 0 0 5px rgba(255,215,0,0.18)' : 'none', transform: `scale(${1 + 0.35 * Math.sin(Math.PI * reached)})` }} />
                <div style={{ marginTop: 20, fontFamily: FONT, fontSize: 25, fontWeight: 500, color: C.white, whiteSpace: 'nowrap' }}>
                  <span style={{ color: C.gold, fontWeight: 600, marginRight: 12 }}>0{i + 1}</span>
                  {step.label}
                </div>
              </div>
            );
          })}
        </AbsoluteFill>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
