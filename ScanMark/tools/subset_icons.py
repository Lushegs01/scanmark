"""
Cut Font Awesome's icon fonts down to the icons ScanMark actually uses.

    pip install fonttools brotli        # development only, never deployed
    python tools/subset_icons.py

WHY
---
fa-solid-900.woff2 is 150 KB for ~1,400 glyphs, and ScanMark draws about
sixty of them. On a phone's first visit it was half of everything the
dashboard downloaded — five seconds of a 2G cell, with icons invisible
until it arrived (Font Awesome uses ``font-display: block``). Subset, the
two fonts the pages use come to a few kilobytes.

The stylesheet (``all.min.css``) stays complete, so every class name still
resolves; only glyphs nothing references are dropped. ``icons.json`` records
what the subset holds, and ``test_student_journey.py`` fails if a template or
script uses an icon that is not in it — so adding an icon means re-running
this script, and forgetting to cannot ship a blank square.

The full fonts are fetched from the pinned Font Awesome release, so the
repository only carries the subsets.
"""

import json
import pathlib
import re
import sys
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
FONT_DIR = ROOT / 'static' / 'vendor' / 'fontawesome'
CSS = FONT_DIR / 'css' / 'all.min.css'
MANIFEST = FONT_DIR / 'icons.json'
RELEASE = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/'
# The one family the templates draw with (`fas`/`fa`). Regular (`far`) and
# brands (`fab`) are left as shipped: nothing uses them, and a browser only
# downloads a font that a page actually draws with.
FONTS = ('fa-solid-900.woff2',)

_ICON_CLASS = re.compile(r'fa-([a-z0-9]+(?:-[a-z0-9]+)*)')
# `fa-{{ 'circle-xmark' if error else 'circle-check' }}` builds the name.
_TEMPLATED = re.compile(r'fa-\{\{(.*?)\}\}', re.S)
_QUOTED = re.compile(r"'([a-z0-9-]+)'")


def sources():
    yield from sorted((ROOT / 'templates').rglob('*.html'))
    for script in sorted((ROOT / 'static').glob('*.js')):
        yield script


def icons_used():
    """Every icon-shaped name the templates and first-party scripts mention."""
    names = set()
    for path in sources():
        text = path.read_text(encoding='utf-8')
        names.update(_ICON_CLASS.findall(text))
        for expression in _TEMPLATED.findall(text):
            names.update(_QUOTED.findall(expression))
    return names


def codepoints():
    """{icon name: codepoint} from the full stylesheet, aliases included."""
    css = CSS.read_text(encoding='utf-8')
    found = {}
    for selectors, code in re.findall(
            r'((?:\.fa-[a-z0-9-]+:before,?)+)\{content:"\\([0-9a-f]+)"\}', css):
        for name in re.findall(r'\.fa-([a-z0-9-]+):before', selectors):
            found[name] = int(code, 16)
    return found


def main():
    from fontTools import subset  # noqa: deferred: development-only dependency

    mapping = codepoints()
    used = sorted(name for name in icons_used() if name in mapping)
    wanted = sorted({mapping[name] for name in used})
    with tempfile.TemporaryDirectory() as scratch:
        for font in FONTS:
            source = pathlib.Path(scratch) / font
            urllib.request.urlretrieve(RELEASE + font, source)
            options = subset.Options()
            options.flavor = 'woff2'
            options.layout_features = ['*']
            options.notdef_outline = True
            loaded = subset.load_font(str(source), options)
            subsetter = subset.Subsetter(options)
            subsetter.populate(unicodes=wanted)
            subsetter.subset(loaded)
            target = FONT_DIR / 'webfonts' / font
            subset.save_font(loaded, str(target), options)
            print(f'{font}: {source.stat().st_size} -> {target.stat().st_size} bytes')
    MANIFEST.write_text(json.dumps({'icons': used}, indent=1) + '\n', encoding='utf-8')
    print(f'{len(used)} icons, {len(wanted)} glyphs -> {MANIFEST.relative_to(ROOT)}')


if __name__ == '__main__':
    sys.exit(main())
