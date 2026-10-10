import React from 'react';
import { Img, OffthreadVideo, Sequence, staticFile } from 'remotion';
import { C, FONT, ease, tween } from './theme';

/* ---------------------------------------------------------------------------
 * Real captures
 *
 * Every product image in the film is a window onto an unaltered capture from
 * ../artifacts/scanmark-demo. `crop` is in the source file's own pixels, so
 * the numbers can be checked against the PNG / MP4 directly.
 * ------------------------------------------------------------------------- */

export type Crop = { x: number; y: number; w: number; h: number };

export const SHOT = {
  dashboard: { file: 'shots/01-product-dashboard.png', w: 3840, h: 2160 },
  projector: { file: 'shots/02-lecturer-session-qr.png', w: 3840, h: 2160 },
  rollCall: { file: 'shots/02b-lecturer-live-checkins.png', w: 3840, h: 2160 },
  scanner: { file: 'shots/03-student-checkin.png', w: 1170, h: 2532 },
  confirmed: { file: 'shots/04-attendance-confirmation.png', w: 1170, h: 2532 },
  records: { file: 'shots/05-attendance-records.png', w: 3840, h: 2160 },
  recordsFull: { file: 'shots/05b-attendance-records-full.png', w: 3840, h: 3636 },
  analytics: { file: 'shots/06b-dashboard-analytics-full.png', w: 3840, h: 2432 },
  portal: { file: 'shots/07-mobile-experience.png', w: 1170, h: 2532 },
} as const;

export const FOOTAGE = {
  phone: { file: 'footage/08-student-checkin-flow.mp4', w: 1170, h: 2532 },
  desktop: { file: 'footage/09-lecturer-dashboard-flow.mp4', w: 1920, h: 1080 },
} as const;

type Source = { file: string; w: number; h: number };

/** A crop of a still, rendered `width` px wide. */
export const Shot: React.FC<{
  shot: Source;
  crop?: Crop;
  width: number;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}> = ({ shot, crop = { x: 0, y: 0, w: shot.w, h: shot.h }, width, style, children }) => {
  const scale = width / crop.w;
  return (
    <div style={{ position: 'relative', width, height: crop.h * scale, overflow: 'hidden', ...style }}>
      <Img
        src={staticFile(shot.file)}
        style={{
          position: 'absolute',
          left: -crop.x * scale,
          top: -crop.y * scale,
          width: shot.w * scale,
          height: shot.h * scale,
          maxWidth: 'none',
        }}
      />
      {children}
    </div>
  );
};

/**
 * A crop of a real screen recording. `from`/`to` are film frames; the clip
 * starts `sourceSeconds` into the recording and plays at `rate`.
 */
export const Footage: React.FC<{
  source: Source;
  crop?: Crop;
  width: number;
  from: number;
  to: number;
  sourceSeconds: number;
  rate?: number;
  fps: number;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}> = ({ source, crop = { x: 0, y: 0, w: source.w, h: source.h }, width, from, to, sourceSeconds, rate = 1, fps, style, children }) => {
  const scale = width / crop.w;
  return (
    <div style={{ position: 'relative', width, height: crop.h * scale, overflow: 'hidden', ...style }}>
      <Sequence from={from} durationInFrames={to - from} layout="none">
        <OffthreadVideo
          src={staticFile(source.file)}
          trimBefore={Math.round(sourceSeconds * fps)}
          playbackRate={rate}
          muted
          style={{
            position: 'absolute',
            left: -crop.x * scale,
            top: -crop.y * scale,
            width: source.w * scale,
            height: source.h * scale,
            maxWidth: 'none',
          }}
        />
      </Sequence>
      {children}
    </div>
  );
};

/** The glass-and-shadow frame every product plane sits in. */
export const Plane: React.FC<{ radius?: number; style?: React.CSSProperties; children: React.ReactNode }> = ({
  radius = 18,
  style,
  children,
}) => (
  <div
    style={{
      position: 'relative',
      borderRadius: radius,
      overflow: 'hidden',
      boxShadow:
        '0 50px 110px rgba(0, 0, 0, 0.55), 0 18px 40px rgba(0, 0, 0, 0.35), 0 0 0 1px rgba(255, 255, 255, 0.10)',
      ...style,
    }}
  >
    {children}
  </div>
);

/** A soft band of light that crosses its parent once between two frames. */
export const LightSweep: React.FC<{ frame: number; from: number; to: number; strength?: number; angle?: number }> = ({
  frame,
  from,
  to,
  strength = 0.32,
  angle = 115,
}) => {
  if (frame < from || frame > to) return null;
  const position = tween(frame, [from, to], [-60, 160], ease.inOut);
  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        pointerEvents: 'none',
        background: `linear-gradient(${angle}deg, transparent ${position - 22}%, rgba(255,255,255,${strength}) ${position}%, transparent ${position + 22}%)`,
        mixBlendMode: 'screen',
      }}
    />
  );
};

/* ---------------------------------------------------------------------------
 * Type
 * ------------------------------------------------------------------------- */

export type Word = { text: string; color?: string; weight?: number };

/** Words rise out of a mask one after another. */
export const Kinetic: React.FC<{
  frame: number;
  words: Word[];
  start: number;
  stagger?: number;
  duration?: number;
  size: number;
  weight?: number;
  color?: string;
  align?: React.CSSProperties['textAlign'];
  tracking?: string;
  style?: React.CSSProperties;
}> = ({ frame, words, start, stagger = 4, duration = 20, size, weight = 600, color = C.white, align = 'left', tracking = '-0.02em', style }) => (
  <div style={{ fontFamily: FONT, fontSize: size, fontWeight: weight, color, letterSpacing: tracking, lineHeight: 1.12, textAlign: align, ...style }}>
    {words.map((word, i) => {
      const t0 = start + i * stagger;
      const rise = tween(frame, [t0, t0 + duration], [105, 0], ease.out);
      const opacity = tween(frame, [t0, t0 + duration * 0.6], [0, 1], ease.soft);
      return (
        <span key={i} style={{ display: 'inline-block', overflow: 'hidden', verticalAlign: 'top', paddingBottom: '0.12em', marginBottom: '-0.12em' }}>
          <span
            style={{
              display: 'inline-block',
              transform: `translateY(${rise}%)`,
              opacity,
              color: word.color ?? color,
              fontWeight: word.weight ?? weight,
              whiteSpace: 'pre',
            }}
          >
            {word.text}
            {i < words.length - 1 ? ' ' : ''}
          </span>
        </span>
      );
    })}
  </div>
);

/** "ScanMark" set the way the app's navbar sets it: Scan, then Mark in gold. */
export const Wordmark: React.FC<{ size: number; scanColor?: string; style?: React.CSSProperties }> = ({ size, scanColor = C.white, style }) => (
  <span style={{ fontFamily: FONT, fontWeight: 800, fontSize: size, letterSpacing: '-0.03em', ...style }}>
    <span style={{ color: scanColor }}>Scan</span>
    <span style={{ color: C.gold }}>Mark</span>
  </span>
);

/* ---------------------------------------------------------------------------
 * Devices and callouts
 * ------------------------------------------------------------------------- */

/** A neutral phone body; no notch, so nothing covers the app's own navbar. */
export const Phone: React.FC<{ screenWidth: number; children: React.ReactNode; style?: React.CSSProperties }> = ({ screenWidth, children, style }) => {
  const screenHeight = (screenWidth * 2532) / 1170;
  const bezel = Math.round(screenWidth * 0.045);
  return (
    <div
      style={{
        position: 'relative',
        width: screenWidth + bezel * 2,
        height: screenHeight + bezel * 2,
        padding: bezel,
        borderRadius: screenWidth * 0.17,
        background: 'linear-gradient(145deg, #2b3330 0%, #0b0f0d 45%, #1a201d 100%)',
        boxShadow:
          '0 60px 120px rgba(0,0,0,0.6), 0 20px 40px rgba(0,0,0,0.4), inset 0 0 0 1.5px rgba(255,255,255,0.14), inset 0 0 0 4px rgba(0,0,0,0.6)',
        ...style,
      }}
    >
      <div style={{ position: 'relative', width: screenWidth, height: screenHeight, borderRadius: screenWidth * 0.13, overflow: 'hidden', background: '#000' }}>
        {children}
      </div>
    </div>
  );
};

/** Gold outline that draws itself around a region of a plane. */
export const Highlight: React.FC<{ frame: number; at: number; box: { x: number; y: number; w: number; h: number }; radius?: number; out?: number }> = ({
  frame,
  at,
  box,
  radius = 10,
  out,
}) => {
  if (frame < at) return null;
  const grow = tween(frame, [at, at + 12], [0, 1], ease.out);
  const fade = out ? tween(frame, [out, out + 10], [1, 0], ease.inOut) : 1;
  const pad = tween(frame, [at, at + 14], [14, 4], ease.out);
  return (
    <div
      style={{
        position: 'absolute',
        left: box.x - pad,
        top: box.y - pad,
        width: box.w + pad * 2,
        height: box.h + pad * 2,
        borderRadius: radius,
        border: `2.5px solid ${C.gold}`,
        background: 'rgba(255, 215, 0, 0.07)',
        boxShadow: '0 0 0 6px rgba(255, 215, 0, 0.12)',
        opacity: grow * fade,
        transform: `scale(${0.96 + 0.04 * grow})`,
        pointerEvents: 'none',
      }}
    />
  );
};

/** A small explanatory callout. Film graphics, deliberately unlike the app's UI. */
export const Chip: React.FC<{ frame: number; at: number; text: string; style?: React.CSSProperties }> = ({ frame, at, text, style }) => {
  const t = tween(frame, [at, at + 16], [0, 1], ease.out);
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        padding: '13px 22px 13px 14px',
        borderRadius: 999,
        background: 'rgba(4, 23, 12, 0.86)',
        border: '1px solid rgba(255, 255, 255, 0.14)',
        boxShadow: '0 18px 40px rgba(0,0,0,0.45)',
        fontFamily: FONT,
        fontSize: 23,
        fontWeight: 500,
        color: C.white,
        opacity: t,
        transform: `translateX(${(1 - t) * -40}px)`,
        whiteSpace: 'nowrap',
        ...style,
      }}
    >
      <svg width="30" height="30" viewBox="0 0 30 30">
        <circle cx="15" cy="15" r="14" fill={C.greenLight} />
        <path d="M8.5 15.5l4.2 4.2 8.8-9.2" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {text}
    </div>
  );
};
