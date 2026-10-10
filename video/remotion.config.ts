import { Config } from '@remotion/cli/config';

// Render with an existing Chromium when one is provided (render.sh points this
// at Playwright's headless shell), instead of downloading Remotion's own.
if (process.env.REMOTION_BROWSER_EXECUTABLE) {
  Config.setBrowserExecutable(process.env.REMOTION_BROWSER_EXECUTABLE);
}
Config.setVideoImageFormat('jpeg');
Config.setJpegQuality(95);
Config.setChromiumOpenGlRenderer('swangle');
