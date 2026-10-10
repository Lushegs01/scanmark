import { continueRender, delayRender, staticFile } from 'remotion';

// Poppins is ScanMark's own typeface (static/style.css); Caveat is only the
// handwriting on the paper register in the opening. Both SIL OFL, from npm.
const FACES: Array<[family: string, weight: number, file: string]> = [
  ['Poppins', 300, 'poppins-latin-300-normal.woff2'],
  ['Poppins', 400, 'poppins-latin-400-normal.woff2'],
  ['Poppins', 500, 'poppins-latin-500-normal.woff2'],
  ['Poppins', 600, 'poppins-latin-600-normal.woff2'],
  ['Poppins', 700, 'poppins-latin-700-normal.woff2'],
  ['Poppins', 800, 'poppins-latin-800-normal.woff2'],
  ['Caveat', 600, 'caveat-latin-600-normal.woff2'],
];

let started = false;

export const loadFonts = () => {
  if (started) return;
  started = true;
  const handle = delayRender('Loading fonts');
  Promise.all(
    FACES.map(([family, weight, file]) =>
      new FontFace(family, `url(${staticFile(`fonts/${file}`)}) format('woff2')`, {
        weight: String(weight),
      })
        .load()
        .then((face) => (document.fonts as unknown as { add: (f: FontFace) => void }).add(face)),
    ),
  )
    .then(() => continueRender(handle))
    .catch((error) => {
      // A missing face must fail the render, not silently fall back.
      throw error;
    });
};
