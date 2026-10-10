import React from 'react';
import { AbsoluteFill, useVideoConfig } from 'remotion';
import cues from '../cues.json';
import { FOOTAGE, Footage, Highlight, Kinetic, LightSweep, Plane, SHOT, Shot } from '../components';
import { C, ease, tween, window4 } from '../theme';

const K = cues.credibility;
const PANEL_X = 1300;         // centre of the product plane
const PANEL_Y = 560;

// 09-lecturer-dashboard-flow.mp4 (1920x1080): the projector while classmates
// arrive. The newest name lands in the top row of "Present Today".
const RT_CROP = { x: 700, y: 230, w: 920, h: 850 };
const RT_W = 900;
const RT_SCALE = RT_W / RT_CROP.w;
const RT_TOP_ROW = { x: (1083 - RT_CROP.x) * RT_SCALE, y: (914 - RT_CROP.y) * RT_SCALE, w: 524 * RT_SCALE, h: 64 * RT_SCALE };

// 05b-attendance-records-full.png (4K, whole page): the CSC 201 register after
// the class ended. The page continues below the frame, so the push-in toward
// Tolu Adeyemi's row (#15) never runs out of real content.
const REC_CROP = { x: 600, y: 150, w: 2640, h: 2010 };
const REC_SOURCE_CROP = { ...REC_CROP, h: 2900 };
const REC_W = 1000;
const REC_SCALE = REC_W / REC_CROP.w;
const TOLU = { x: 26 * REC_SCALE, y: 1776 * REC_SCALE, w: 2587 * REC_SCALE, h: 94 * REC_SCALE };
const PILL = { x: 2212 * REC_SCALE, y: 272 * REC_SCALE, w: 290 * REC_SCALE, h: 44 * REC_SCALE };

// 06b-dashboard-analytics-full.png (4K): tiles and the attendance line.
const AN_CROP = { x: 600, y: 150, w: 2640, h: 2140 };
const AN_W = 1000;
const AN_SCALE = AN_W / AN_CROP.w;
const CHART = { y: 992 * AN_SCALE, h: 1144 * AN_SCALE };
const TILES = { x: 1442 * AN_SCALE, y: 404 * AN_SCALE, w: 874 * AN_SCALE, h: 316 * AN_SCALE };

// 05-attendance-records.png (4K): the register's own export button.
const CSV_CROP = { x: 2190, y: 206, w: 504, h: 120 };

/** One product plane: enters from the right, leaves to the left. */
const Stage: React.FC<{ frame: number; window: [number, number]; children: React.ReactNode }> = ({ frame, window, children }) => {
  const [a, b] = window;
  const enter = tween(frame, [a, a + 18], [0, 1], ease.out);
  const leave = tween(frame, [b - 12, b + 4], [0, 1], ease.in);
  if (frame < a || frame > b + 4) return null;
  return (
    <div
      style={{
        position: 'absolute',
        left: PANEL_X,
        top: PANEL_Y,
        opacity: enter * (1 - leave),
        transform: `translate(-50%, -50%) translateX(${220 * (1 - enter) - 160 * leave}px) rotateY(${-22 + 10 * enter - 8 * leave}deg) rotateX(3deg) scale(${0.94 + 0.06 * enter - 0.05 * leave})`,
      }}
    >
      {children}
    </div>
  );
};

export const Credibility: React.FC<{ frame: number }> = ({ frame }) => {
  const { fps } = useVideoConfig();
  const exit = tween(frame, K.exit as [number, number], [0, 1], ease.in);

  // Records: hold wide on the session header, then push in to Tolu's row.
  const push = tween(frame, [548, 588], [0, 1], ease.inOut);
  // Analytics: drift from the tiles down to the line.
  const drift = tween(frame, [K.analytics[0], K.analytics[1]], [0, 1], ease.inOut);
  const csv = tween(frame, [K.csvChip, K.csvChip + 16], [0, 1], ease.out);

  const line = (start: number, next?: number) => (next && frame >= next ? 0.36 : 1) * tween(frame, [start, start + 8], [0, 1]);
  const marker = (start: number, end: number) => window4(frame, start, start + 10, end - 6, end + 4);

  return (
    <AbsoluteFill style={{ opacity: 1 - exit }}>
      <AbsoluteFill style={{ perspective: 2400 }}>
        <Stage frame={frame} window={[K.rtFootage.from, K.rtFootage.to]}>
          <Plane>
            <Footage source={FOOTAGE.desktop} crop={RT_CROP} width={RT_W} fps={fps} {...K.rtFootage}>
              {K.rtArrivals.map((at) => (
                <div
                  key={at}
                  style={{
                    position: 'absolute',
                    left: RT_TOP_ROW.x,
                    top: RT_TOP_ROW.y,
                    width: RT_TOP_ROW.w,
                    height: RT_TOP_ROW.h,
                    background: 'rgba(0, 168, 84, 0.16)',
                    boxShadow: 'inset 0 0 0 2px rgba(0, 168, 84, 0.55)',
                    opacity: window4(frame, at, at + 2, at + 8, at + 20),
                  }}
                />
              ))}
            </Footage>
          </Plane>
        </Stage>

        <Stage frame={frame} window={K.records as [number, number]}>
          <Plane>
            <div style={{ width: REC_W, height: REC_CROP.h * REC_SCALE, overflow: 'hidden' }}>
              <div style={{ transformOrigin: `120px ${TOLU.y + TOLU.h / 2}px`, transform: `translateY(${-230 * push}px) scale(${1 + 0.55 * push})` }}>
                <Shot shot={SHOT.recordsFull} crop={REC_SOURCE_CROP} width={REC_W}>
                  <Highlight frame={frame} at={534} box={PILL} radius={14} out={552} />
                  <Highlight frame={frame} at={K.recordsHighlight} box={TOLU} radius={6} />
                  <LightSweep frame={frame} from={K.recordsHighlight} to={K.recordsHighlight + 20} strength={0.3} />
                </Shot>
              </div>
            </div>
          </Plane>
        </Stage>

        <Stage frame={frame} window={K.analytics as [number, number]}>
          <Plane>
            <div style={{ width: AN_W, height: 760, overflow: 'hidden' }}>
              <div style={{ transform: `translateY(${-50 * drift}px)` }}>
                <Shot shot={SHOT.analytics} crop={AN_CROP} width={AN_W}>
                  <Highlight frame={frame} at={604} box={TILES} radius={18} out={628} />
                  <div style={{ position: 'absolute', left: 0, right: 0, top: CHART.y, height: CHART.h, overflow: 'hidden' }}>
                    <LightSweep frame={frame} from={K.chartReveal[0]} to={K.chartReveal[1]} strength={0.38} angle={100} />
                  </div>
                </Shot>
              </div>
            </div>
          </Plane>
          {/* The register's real export button, lifted off the page. */}
          <div
            style={{
              position: 'absolute',
              left: -150,
              bottom: 40,
              opacity: csv,
              transform: `translateY(${30 * (1 - csv)}px) translateZ(120px) rotateY(10deg)`,
            }}
          >
            <Plane radius={14}>
              <Shot shot={SHOT.records} crop={CSV_CROP} width={420} />
            </Plane>
          </div>
        </Stage>
      </AbsoluteFill>

      {/* Copy column, with a gold marker beside the line on screen. */}
      <div style={{ position: 'absolute', left: 110, top: 312, width: 660 }}>
        {[
          { words: [{ text: 'Real-time' }, { text: 'attendance.' }], at: K.line1, next: K.line2, end: K.records[0] },
          { words: [{ text: 'Clearer' }, { text: 'records.' }], at: K.line2, next: K.line3, end: K.analytics[0] },
          { words: [{ text: 'Less' }, { text: 'manual' }, { text: 'work.' }], at: K.line3, end: K.exit[1] },
        ].map(({ words, at, next, end }) => (
          <div key={at} style={{ position: 'relative', marginBottom: 22, opacity: line(at, next) }}>
            <div style={{ position: 'absolute', left: -34, top: 14, width: 6, height: 54, borderRadius: 3, background: C.gold, opacity: marker(at, end), transform: `scaleY(${marker(at, end)})` }} />
            <Kinetic frame={frame} words={words} start={at} stagger={4} size={66} />
          </div>
        ))}
      </div>
    </AbsoluteFill>
  );
};
