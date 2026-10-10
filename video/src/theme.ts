import { Easing, interpolate } from 'remotion';

// ScanMark's own palette (ScanMark/static/style.css :root).
export const C = {
  night: '#020c06',
  deep: '#04170c',
  forest: '#003719',
  green: '#005A2B',
  greenMid: '#007A3D',
  greenLight: '#00A854',
  gold: '#FFD700',
  white: '#F5F8F6',
  warmWhite: '#F2EDE3',
  muted: 'rgba(245, 248, 246, 0.62)',
  dim: 'rgba(245, 248, 246, 0.36)',
};

export const FONT = 'Poppins, sans-serif';
export const HAND = 'Caveat, cursive';

export const ease = {
  out: Easing.bezier(0.16, 1, 0.3, 1),
  inOut: Easing.bezier(0.65, 0, 0.35, 1),
  in: Easing.bezier(0.7, 0, 0.84, 0),
  soft: Easing.bezier(0.33, 1, 0.68, 1),
};

/** interpolate() between two frames, clamped, with an easing. */
export const tween = (
  frame: number,
  [from, to]: [number, number],
  [a, b]: [number, number],
  easing: (t: number) => number = ease.out,
) =>
  interpolate(frame, [from, to], [a, b], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
    easing,
  });

/** 0 -> 1 -> 0 envelope: fade in over [a, b], out over [c, d]. */
export const window4 = (frame: number, a: number, b: number, c: number, d: number) =>
  Math.min(tween(frame, [a, b], [0, 1], ease.soft), tween(frame, [c, d], [1, 0], ease.inOut));

/** Deterministic pseudo-random in [0, 1) for a given seed. */
export const hash = (seed: number) => {
  const x = Math.sin(seed * 127.1 + 311.7) * 43758.5453;
  return x - Math.floor(x);
};
