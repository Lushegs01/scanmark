import React from 'react';
import { AbsoluteFill, useVideoConfig } from 'remotion';
import cues from '../cues.json';
import { Chip, FOOTAGE, Footage, Highlight, Kinetic, LightSweep, Phone, Plane, SHOT, Shot } from '../components';
import { C, ease, tween, window4 } from '../theme';

const S = cues.signature;

// 02-lecturer-session-qr.png (4K): the projector card, header to refresh timer.
const CARD_CROP = { x: 1320, y: 222, w: 1200, h: 1228 };
const CARD_W = 700;
const CARD_SCALE = CARD_W / CARD_CROP.w;
// The QR's green frame inside that crop.
const QR = { x: 300 * CARD_SCALE, y: 486 * CARD_SCALE, w: 600 * CARD_SCALE, h: 600 * CARD_SCALE };

// 02b-lecturer-live-checkins.png (4K): "Present Today", newest arrival on top.
const LIST_CROP = { x: 2166, y: 764, w: 1048, h: 766 };
const LIST_W = 600;
const LIST_SCALE = LIST_W / LIST_CROP.w;
const TOLU_ROW = { x: 4, y: 118 * LIST_SCALE, w: LIST_W - 8, h: 128 * LIST_SCALE };
const COUNT_BADGE = { x: 720 * LIST_SCALE, y: 32 * LIST_SCALE, w: 284 * LIST_SCALE, h: 52 * LIST_SCALE };

const PHONE_SCREEN = 330;
// Where the app's success banner sits on the phone (CSS px of a 390-wide page).
const BANNER = { x: (195 * PHONE_SCREEN) / 390, y: (297 * PHONE_SCREEN) / 390 };

const Brackets: React.FC<{ frame: number }> = ({ frame }) => {
  const lock = tween(frame, [S.lock - 6, S.lock + 4], [0, 1], ease.out);
  if (frame < S.lock - 6) return null;
  const gap = 40 * (1 - lock) + 10;
  const arm = 54;
  const corner = (left: boolean, top: boolean): React.CSSProperties => ({
    position: 'absolute',
    width: arm,
    height: arm,
    left: left ? QR.x - gap : QR.x + QR.w + gap - arm,
    top: top ? QR.y - gap : QR.y + QR.h + gap - arm,
    borderColor: C.gold,
    borderStyle: 'solid',
    borderWidth: 0,
    [top ? 'borderTopWidth' : 'borderBottomWidth']: 6,
    [left ? 'borderLeftWidth' : 'borderRightWidth']: 6,
    borderRadius: 10,
    opacity: lock,
  });
  return (
    <>
      <div style={corner(true, true)} />
      <div style={corner(false, true)} />
      <div style={corner(true, false)} />
      <div style={corner(false, false)} />
    </>
  );
};

const Beam: React.FC<{ frame: number }> = ({ frame }) => {
  const [b0, b1] = S.beam;
  if (frame < b0 || frame > b1 + 6) return null;
  const y = tween(frame, [b0, b1], [0, 1], ease.inOut) * QR.h;
  const fade = tween(frame, [b1, b1 + 6], [1, 0]);
  return (
    <div style={{ position: 'absolute', left: QR.x, top: QR.y, width: QR.w, height: QR.h, overflow: 'hidden', opacity: fade }}>
      <div style={{ position: 'absolute', left: 0, right: 0, top: y - 90, height: 90, background: 'linear-gradient(to bottom, rgba(0,168,84,0), rgba(0,168,84,0.28))' }} />
      <div style={{ position: 'absolute', left: -10, right: -10, top: y - 2, height: 4, background: C.greenLight, boxShadow: '0 0 18px 4px rgba(0,168,84,0.75)' }} />
    </div>
  );
};

export const Signature: React.FC<{ frame: number }> = ({ frame }) => {
  const { fps } = useVideoConfig();
  const exit = tween(frame, S.exit as [number, number], [0, 1], ease.in);

  // The projector card: arrives out of the logo dive, then turns to face the phone.
  const arrive = tween(frame, [232, S.cardSettle[1]], [0, 1], ease.out);
  const toPhone = tween(frame, S.phoneIn as [number, number], [0, 1], ease.inOut);
  // The QR card is gone before the roll call lands: no double exposure.
  const cardOut = tween(frame, [S.listIn[0] - 12, S.listIn[0] + 1], [0, 1], ease.in);
  const cardX = 1300 - 250 * toPhone - 200 * cardOut;
  const cardScale = (2.3 - 1.3 * arrive) * (1 - 0.2 * toPhone);
  const focus = tween(frame, [232, 248], [10, 0], ease.out);
  const flash = window4(frame, S.lock, S.lock + 2, S.lock + 3, S.lock + 12);

  // The phone slides in from the right.
  const phoneT = tween(frame, S.phoneIn as [number, number], [0, 1], ease.out);
  const phoneX = 1580 + 520 * (1 - phoneT);
  const success = frame >= S.success;
  const ring = tween(frame, [S.success, S.success + 26], [0, 1], ease.out);

  // The lecturer's roll call replaces the QR card.
  const listT = tween(frame, S.listIn as [number, number], [0, 1], ease.out);

  // Copy: each phrase brightens as it lands, then steps back.
  const lineOpacity = (start: number, next?: number) => (next && frame >= next ? 0.36 : 1) * tween(frame, [start, start + 8], [0, 1]);

  return (
    <AbsoluteFill style={{ opacity: 1 - exit, transform: `translateX(${-140 * exit}px)` }}>
      <AbsoluteFill style={{ perspective: 2200 }}>
        {/* The real projector screen, centred on its QR. */}
        <div
          style={{
            position: 'absolute',
            left: cardX - CARD_W / 2,
            top: 540 - (QR.y + QR.h / 2) + 40 * toPhone,
            opacity: arrive * (1 - cardOut),
            transformOrigin: `${CARD_W / 2}px ${QR.y + QR.h / 2}px`,
            transform: `scale(${cardScale}) rotateY(${-10 + 22 * toPhone}deg) rotateX(${4 - 2 * toPhone}deg)`,
            filter: focus > 0.05 ? `blur(${focus}px)` : undefined,
          }}
        >
          <Plane radius={22}>
            <Shot shot={SHOT.projector} crop={CARD_CROP} width={CARD_W}>
              <div style={{ position: 'absolute', inset: 0, background: '#fff', opacity: flash * 0.35 }} />
              <div style={{ position: 'absolute', inset: 0, background: '#02130a', opacity: 0.22 * toPhone }} />
            </Shot>
          </Plane>
          <Beam frame={frame} />
          <Brackets frame={frame} />
        </div>

        {/* The lecturer's live roll call, Tolu Adeyemi on top. */}
        {frame >= S.listIn[0] && (
          <div
            style={{
              position: 'absolute',
              left: 1075 - LIST_W / 2 - 160 * (1 - listT),
              top: 300,
              opacity: listT,
              transformOrigin: '100% 50%',
              transform: `rotateY(${18 - 6 * listT}deg) scale(${0.92 + 0.08 * listT})`,
            }}
          >
            <Plane radius={16}>
              <Shot shot={SHOT.rollCall} crop={LIST_CROP} width={LIST_W}>
                <Highlight frame={frame} at={S.highlight} box={TOLU_ROW} radius={8} />
                <Highlight frame={frame} at={S.highlight + 6} box={COUNT_BADGE} radius={10} />
                <LightSweep frame={frame} from={S.highlight} to={S.highlight + 18} strength={0.4} />
              </Shot>
            </Plane>
          </div>
        )}

        {/* The student's phone: the real scanner, then the real confirmation. */}
        <div
          style={{
            position: 'absolute',
            left: phoneX - (PHONE_SCREEN * 1.09) / 2,
            top: 540 - (PHONE_SCREEN * 2532) / 1170 / 2 - 15,
            opacity: phoneT,
            transform: `rotateY(${-14 + 6 * phoneT}deg) rotateZ(${2 * (1 - phoneT)}deg)`,
          }}
        >
          <Phone screenWidth={PHONE_SCREEN}>
            {!success ? (
              <Footage source={FOOTAGE.phone} width={PHONE_SCREEN} fps={fps} {...S.phoneFootage} />
            ) : (
              <Footage source={FOOTAGE.phone} width={PHONE_SCREEN} fps={fps} from={S.successFootage.from} to={S.exit[1] + 4} sourceSeconds={S.successFootage.sourceSeconds}>
                <div
                  style={{
                    position: 'absolute',
                    left: BANNER.x - 150 * ring,
                    top: BANNER.y - 150 * ring,
                    width: 300 * ring,
                    height: 300 * ring,
                    borderRadius: '50%',
                    border: `3px solid ${C.greenLight}`,
                    opacity: 0.9 * (1 - ring),
                  }}
                />
                <LightSweep frame={frame} from={S.success + 2} to={S.success + 22} strength={0.45} />
              </Footage>
            )}
          </Phone>
        </div>

        {/* What the server checked before it said yes. All three are real checks. */}
        <div style={{ position: 'absolute', left: 850, top: 676, display: 'flex', flexDirection: 'column', gap: 14, opacity: 1 - tween(frame, [S.success - 8, S.success + 4], [0, 1]) }}>
          <Chip frame={frame} at={S.chips[0]} text="Signed, rotating code" />
          <Chip frame={frame} at={S.chips[1]} text="Inside the classroom geofence" />
          <Chip frame={frame} at={S.chips[2]} text="Enrolled in CSC 201" />
        </div>
      </AbsoluteFill>

      {/* Copy column. */}
      <div style={{ position: 'absolute', left: 110, top: 300, width: 620 }}>
        <div style={{ opacity: lineOpacity(S.wordScan, S.wordVerify) }}>
          <Kinetic frame={frame} words={[{ text: 'Scan.' }]} start={S.wordScan} size={84} />
        </div>
        <div style={{ opacity: lineOpacity(S.wordVerify, S.wordPresent), marginTop: 6 }}>
          <Kinetic frame={frame} words={[{ text: 'Verify.' }]} start={S.wordVerify} size={84} />
        </div>
        <div style={{ opacity: lineOpacity(S.wordPresent), marginTop: 6 }}>
          <Kinetic
            frame={frame}
            words={[{ text: 'You’re' }, { text: 'marked' }, { text: 'present.', color: C.gold }]}
            start={S.wordPresent}
            stagger={4}
            size={84}
          />
        </div>
      </div>
    </AbsoluteFill>
  );
};
