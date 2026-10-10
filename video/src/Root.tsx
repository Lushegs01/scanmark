import { Composition } from 'remotion';
import cues from './cues.json';
import { Film } from './Film';
import { loadFonts } from './fonts';

loadFonts();

export const RemotionRoot: React.FC = () => (
  <Composition
    id="ScanMarkLaunch"
    component={Film}
    durationInFrames={cues.durationInFrames}
    fps={cues.fps}
    width={1920}
    height={1080}
  />
);
