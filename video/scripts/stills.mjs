// Render chosen frames as PNGs for review: node scripts/stills.mjs <outDir> <frame> [frame ...]
import { bundle } from '@remotion/bundler';
import { renderStill, selectComposition } from '@remotion/renderer';
import path from 'node:path';

const [outDir, ...frames] = process.argv.slice(2);
const browserExecutable = process.env.REMOTION_BROWSER_EXECUTABLE || null;
const serveUrl = await bundle({ entryPoint: path.resolve('src/index.ts'), publicDir: path.resolve('public') });
const composition = await selectComposition({ serveUrl, id: 'ScanMarkLaunch', browserExecutable, chromiumOptions: { gl: 'swangle' } });
for (const frame of frames.map(Number)) {
  const output = path.join(outDir, `frame-${String(frame).padStart(3, '0')}.png`);
  await renderStill({ serveUrl, composition, frame, output, browserExecutable, chromiumOptions: { gl: 'swangle' } });
  console.log('still', output);
}
