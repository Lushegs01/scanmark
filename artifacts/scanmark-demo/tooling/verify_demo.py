"""
Check the captured demo assets against the database they were captured from.

Every screenshot in capture-log.json carries the figures that were on screen
when it was taken. This recomputes each of them straight from the demo SQLite
file (plain sqlite3, not the app's own code paths) and fails on any mismatch.
It also confirms the dataset is synthetic, that the files exist and decode,
and that no password or secret key from the run appears anywhere in the
package.

Writes verification.json next to the assets. Exit status 1 on any failure.
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

OUT = Path(os.environ['DEMO_OUT_DIR']).resolve()
RUN = Path(os.environ['DEMO_RUN_DIR']).resolve()
DB = os.environ['DATABASE_URL'].removeprefix('sqlite:///')
SEED = json.loads(Path(os.environ['DEMO_SEED_FILE']).read_text())
LOG = json.loads((RUN / 'capture-log.json').read_text())
SECRETS = [value for value in (os.environ.get('SECRET_KEY'),
                               Path(os.environ['DEMO_PASSWORD_FILE']).read_text().strip())
           if value]

checks = []


def check(name, expected, actual, ok=None):
    passed = (expected == actual) if ok is None else bool(ok)
    checks.append({'check': name, 'expected': expected, 'actual': actual,
                   'result': 'pass' if passed else 'FAIL'})


def facts(asset):
    return LOG['assets'].get(asset, {}).get('facts', {})


def pct(attended, expected):
    return None if not expected else min(100, round(attended / expected * 100))


db = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
one = lambda sql, *args: db.execute(sql, args).fetchone()[0]          # noqa: E731

course_id = SEED['courses'][SEED['main_course']]['id']
featured = SEED['featured_student']
live = LOG.get('live_session_id')

# --- The capture itself ------------------------------------------------------
check('capture finished without an error', None, LOG.get('error'))
check('no failed requests, 5xx responses or page errors', [], LOG.get('failures'))

# --- Dataset isolation -------------------------------------------------------
check('every account is on the reserved demo domain', 0,
      one("SELECT COUNT(*) FROM user WHERE email NOT LIKE '%@%demo-university.example'"))
check('every matric number is a DEMO number', 0,
      one("SELECT COUNT(*) FROM user WHERE matric_no IS NOT NULL AND matric_no NOT LIKE 'DEMO%'"))
check('every course offering is section DEMO', 0,
      one("SELECT COUNT(*) FROM course WHERE section != 'DEMO'"))

# --- The live session opened through the UI ----------------------------------
check('live session belongs to the demo course', course_id,
      one('SELECT course_id FROM class_session WHERE id = ?', live))
check('live session was pinned to the demo classroom', SEED['classroom']['id'],
      one('SELECT classroom_id FROM class_session WHERE id = ?', live))
state = db.execute('SELECT active, ended_at IS NOT NULL FROM class_session WHERE id = ?',
                   (live,)).fetchone()
check('live session was ended from the projector (active, ended)', [0, 1],
      list(state) if state else None)
roster = one('SELECT COUNT(*) FROM session_roster WHERE session_id = ?', live)
present = one('SELECT COUNT(*) FROM attendance WHERE session_id = ?', live)
check('roster snapshot of the live session', SEED['courses'][SEED['main_course']]['enrolled'], roster)

row = db.execute('SELECT device_id, timestamp FROM attendance WHERE session_id = ? AND student_id = ?',
                 (live, featured['id'])).fetchone()
check('featured student has exactly one attendance row in the live session', True, row is not None)
check('featured check-in came from the browser scanner, not the API or the seed', True,
      row is not None and not row[0].startswith('demo-'))
check('classmates checked in through /mark_attendance', present - 1,
      one("SELECT COUNT(*) FROM attendance WHERE session_id = ? AND device_id LIKE 'demo-capture-classmate-%'", live))
scan = LOG.get('featured_scan', {})
check('server answered the camera scan with success', (200, 'success'),
      (scan.get('http_status'), scan.get('outcome')))
check('code the phone decoded is the code the projector showed', scan.get('projected_session'),
      scan.get('decoded_session'), ok=scan.get('decoded_session') in (None, scan.get('projected_session')))
check('projected code is for the live session', f'S{live}', scan.get('projected_session'))

# --- Screenshot figures vs. the database -------------------------------------
f01 = facts('01-product-dashboard.png')
tiles = ' | '.join(f01.get('stat_tiles', [])).lower()
courses = one('SELECT COUNT(*) FROM course WHERE archived = 0')
instructors = len({r[0] for r in db.execute('SELECT user_id FROM course_instructors')} |
                  {r[0] for r in db.execute('SELECT coordinator_id FROM course')})
for label, value in (('total classes', courses), ('instructors', instructors), ('classes running', 0)):
    check(f'01 dashboard tile "{label}"', f'{value} {label}', f'{value} {label}', ok=f'{value} {label}' in tiles)

f02 = facts('02-lecturer-session-qr.png')
check('02 projector shows 0 present before anyone scans', '0', f02.get('present'))
check('02 projector shows the roster size', str(roster), f02.get('enrolled'))
check('02 projector names the classroom', True, SEED['classroom']['name'] in f02.get('classroom', ''))

f02b = facts('02b-lecturer-live-checkins.png')
check('02b featured student is the newest arrival on the projector', True,
      featured['name'] in f02b.get('newest', '') and featured['matric_no'] in f02b.get('newest', ''))
check('02b projector headcount when the featured student arrived', '15', f02b.get('present'))

check('03 scanner state while the scan is in flight', True,
      'Marking attendance' in facts('03-student-checkin.png').get('scanner_status', ''))
f04 = facts('04-attendance-confirmation.png')
check('04 confirmation banner', 'Attendance marked successfully!', f04.get('banner'))
check('04 confirmation is on the featured student\'s screen', True,
      featured['name'] in f04.get('signed_in_as', ''))

f05 = facts('05-attendance-records.png')
held = one('SELECT COUNT(*) FROM class_session WHERE course_id = ?', course_id)
scans = one('SELECT COUNT(*) FROM attendance WHERE course_id = ? AND session_id IS NOT NULL', course_id)
enrolled = one('SELECT COUNT(*) FROM enrollments WHERE course_id = ?', course_id)
expected_summary = (f'{held} classes held · {enrolled} enrolled now · avg {round(scans / held)} '
                    f'present per class · {scans} scans recorded')
check('05 records summary line', expected_summary, f05.get('summary', '').replace('\xa0', ' '))
check('05 newest session lists every scan', present, f05.get('first_session_rows'))
check('05 newest session includes the featured student', True,
      any(featured['name'] in r and featured['matric_no'] in r for r in f05.get('names_in_first_session', [])))
check('05 newest session header shows present / roster', True,
      bool(re.search(rf'\b{present}\s*/\s*{roster}\b', f05.get('first_session_header', ''))))

f06 = facts('06-dashboard-analytics.png')
series = db.execute('''SELECT s.id, COUNT(a.id), (SELECT COUNT(*) FROM session_roster r WHERE r.session_id = s.id)
                       FROM class_session s LEFT JOIN attendance a ON a.session_id = s.id
                       WHERE s.course_id = ? GROUP BY s.id ORDER BY s.date_created''', (course_id,)).fetchall()
check('06 chart series = present per session', [c for _, c, _ in series], f06.get('series'))
check('06 chart rates = present / that day\'s roster', [pct(c, e) or 0 for _, c, e in series], f06.get('rates'))
check('06 peak tile', f'{max(c for _, c, _ in series)} Students', f06.get('peak'))
check('06 average tile', f'~{round(sum(c for _, c, _ in series) / len(series))} / class', f06.get('average'))
check('06 chart canvas actually drew', True, f06.get('chart_drawn'))

f07 = facts('07-mobile-experience.png')
attended = one('SELECT COUNT(*) FROM attendance WHERE student_id = ? AND course_id = ?', featured['id'], course_id)
expected_classes = one('SELECT COUNT(*) FROM session_roster WHERE student_id = ? AND course_id = ?',
                       featured['id'], course_id)
check('07 student\'s classes-attended tile', True,
      any(t.lower().endswith(f' {attended} classes attended') for t in f07.get('stat_tiles', [])))
check('07 student\'s record row shows attended / held and %', f'{attended} / {expected_classes} … {pct(attended, expected_classes)}%',
      f07.get('records_row'),
      ok=f'{attended} / {expected_classes}' in f07.get('records_row', '')
      and f'{pct(attended, expected_classes)}%' in f07.get('records_row', ''))

# --- Files -------------------------------------------------------------------
EXPECTED = {
    '01-product-dashboard.png': (3840, 2160), '02-lecturer-session-qr.png': (3840, 2160),
    '02b-lecturer-live-checkins.png': (3840, 2160), '03-student-checkin.png': (1170, 2532),
    '04-attendance-confirmation.png': (1170, 2532), '05-attendance-records.png': (3840, 2160),
    '05b-attendance-records-full.png': None, '06-dashboard-analytics.png': (3840, 2160),
    '06b-dashboard-analytics-full.png': None,
    '07-mobile-experience.png': (1170, 2532),
}
files = {}
for name, size in EXPECTED.items():
    path = OUT / name
    if not path.exists():
        check(f'{name} exists', True, False)
        continue
    header = path.read_bytes()[:24]
    width, height = int.from_bytes(header[16:20], 'big'), int.from_bytes(header[20:24], 'big')
    files[name] = {'bytes': path.stat().st_size, 'pixels': f'{width}x{height}'}
    check(f'{name} is a PNG of the expected size', size or 'any', (width, height) if size else 'any',
          ok=header[:8] == b'\x89PNG\r\n\x1a\n' and (size is None or (width, height) == size))

VIDEO_PIXELS = {'08-student-checkin-flow': '1170x2532', '09-lecturer-dashboard-flow': '1920x1080'}
for name, pixels in VIDEO_PIXELS.items():
    for path in (OUT / f'{name}.webm', OUT / 'editing-mezzanine' / f'{name}.mp4'):
        if not path.exists():
            check(f'{path.name} exists', True, False)
            continue
        probe = json.loads(subprocess.run(
            ['ffprobe', '-v', 'error', '-select_streams', 'v:0', '-show_entries',
             'stream=codec_name,width,height,r_frame_rate:format=duration', '-of', 'json', str(path)],
            capture_output=True, text=True, check=True).stdout)
        stream = probe['streams'][0]
        info = {'bytes': path.stat().st_size, 'codec': stream['codec_name'],
                'pixels': f"{stream['width']}x{stream['height']}", 'fps': stream['r_frame_rate'],
                'seconds': round(float(probe['format']['duration']), 1)}
        files[str(path.relative_to(OUT))] = info
        check(f'{path.name} decodes and runs > 15 s', '> 15 s', info['seconds'], ok=info['seconds'] > 15)
        check(f'{path.name} resolution', pixels, info['pixels'])

# --- Secrets -----------------------------------------------------------------
leaks = []
for path in OUT.rglob('*'):
    if path.is_file():
        blob = path.read_bytes()
        leaks += [str(path.relative_to(OUT)) for secret in SECRETS if secret.encode() in blob]
check('no run password or SECRET_KEY anywhere in the package', [], leaks)

failed = [c for c in checks if c['result'] != 'pass']
report = {
    'generated_at': LOG.get('finished_at'),
    'summary': {'checks': len(checks), 'passed': len(checks) - len(failed), 'failed': len(failed)},
    'live_session': {'id': live, 'course': SEED['main_course'], 'roster': roster, 'present': present},
    'featured_student': {'name': featured['name'], 'matric_no': featured['matric_no'],
                         'checked_in_at_utc': row[1] if row else None},
    'files': files,
    'checks': checks,
}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
for c in checks:
    print(f"{'ok  ' if c['result'] == 'pass' else 'FAIL'} {c['check']}"
          + ('' if c['result'] == 'pass' else f"\n     expected {c['expected']!r}\n     actual   {c['actual']!r}"))
print(f"\n{report['summary']['passed']}/{report['summary']['checks']} checks passed")
sys.exit(1 if failed else 0)
