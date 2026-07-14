"""Load test for the /mark_attendance endpoint.

Simulates a lecture hall: N students (default 2000), all enrolled in one
course, hitting one live class session in a burst, while the lecturer's
projector polls the roll-call feed — against a REAL gunicorn server with the
production Procfile settings (4 workers x 8 threads).

    python scripts/load_test.py --students 2000

Run from the ScanMark directory. Uses a throwaway SQLite database in /tmp;
production Postgres only gets faster than this.
"""
import argparse
import hashlib
import hmac
import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import urllib3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = 'load-test-secret'
PASSWORD = 'load-test-pass'


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--students', type=int, default=2000)
    p.add_argument('--concurrency', type=int, default=250,
                   help='parallel client threads during the burst')
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--threads', type=int, default=8)
    p.add_argument('--port', type=int, default=8035)
    return p.parse_args()


def make_env(db_path):
    env = dict(os.environ)
    env.update({
        'DATABASE_URL': f'sqlite:///{db_path}',
        'SECRET_KEY': SECRET,
        # Dead SMTP so any stray mail fails instantly instead of hanging
        'MAIL_SERVER': '127.0.0.1',
        'MAIL_PORT': '1',
    })
    return env


def seed(db_path, n_students):
    """Create coordinator, course, one live session, and N enrolled students."""
    os.environ.update(make_env(db_path))
    sys.path.insert(0, BASE_DIR)
    from app import app, db, _get_or_create_todays_session
    from models import User, Course, enrollments
    from werkzeug.security import generate_password_hash

    # One cheap (test-only) hash shared by every seeded account keeps both
    # seeding and the login phase fast; production stays on scrypt.
    pw_hash = generate_password_hash(PASSWORD, method='pbkdf2:sha256:1000')

    with app.app_context():
        lecturer = User(full_name='Load Lecturer', email='lect@staff.funaab.edu.ng',
                        password=pw_hash, role='Course Coordinator', email_verified=True)
        db.session.add(lecturer)
        db.session.flush()
        course = Course(code='LOAD 101', title='Load Testing', coordinator_id=lecturer.id,
                        current_semester='2025/2026')
        db.session.add(course)
        db.session.flush()

        students = [User(full_name=f'Student {i}', email=f'load{i}@gmail.com',
                         password=pw_hash, role='student', email_verified=True,
                         matric_no=f'LT{i:06d}', level='300')
                    for i in range(n_students)]
        db.session.add_all(students)
        db.session.flush()
        db.session.execute(enrollments.insert(),
                           [{'user_id': s.id, 'course_id': course.id} for s in students])
        session_row = _get_or_create_todays_session(course)
        db.session.commit()
        return course.id, session_row.id


def sign_token(session_id):
    """Mint a QR token exactly like the app does (same secret)."""
    message = f"S{session_id}|{int(time.time())}"
    sig = hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{message}|{sig}"


def wait_ready(http, base, deadline=60):
    end = time.time() + deadline
    while time.time() < end:
        try:
            if http.request('GET', f'{base}/login', retries=False).status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def login_all(http, base, n, concurrency):
    """Untimed setup phase: get a session cookie for every student."""
    cookies = [None] * n

    def login(i):
        body = f'email=load{i}%40gmail.com&password={PASSWORD}'
        r = http.request('POST', f'{base}/login', body=body, retries=False, redirect=False,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
        set_cookie = r.headers.get('Set-Cookie', '')
        assert r.status == 302 and 'session=' in set_cookie, f'login {i}: {r.status}'
        cookies[i] = set_cookie.split(';', 1)[0]

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(login, range(n)))
    return cookies


def percentile(sorted_vals, pct):
    idx = min(len(sorted_vals) - 1, int(round(pct / 100 * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def main():
    args = parse_args()
    fd, db_path = tempfile.mkstemp(prefix='scanmark_load_', suffix='.db')
    os.close(fd)
    os.remove(db_path)

    print(f'Seeding {args.students} students…')
    t0 = time.time()
    course_id, session_id = seed(db_path, args.students)
    print(f'  seeded in {time.time() - t0:.1f}s (course={course_id}, session={session_id})')

    base = f'http://127.0.0.1:{args.port}'
    gunicorn = os.path.join(os.path.dirname(sys.executable), 'gunicorn')
    server = subprocess.Popen(
        [gunicorn, 'loadtest_app:app',
         '--chdir', os.path.join(BASE_DIR, 'scripts'),
         '--workers', str(args.workers), '--threads', str(args.threads),
         '--timeout', '60', '--bind', f'127.0.0.1:{args.port}'],
        env=make_env(db_path),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    http = urllib3.PoolManager(maxsize=args.concurrency + 10)
    try:
        assert wait_ready(http, base), 'server did not become ready'
        print(f'Server up: gunicorn {args.workers} workers x {args.threads} threads')

        print('Logging every student in (setup, untimed)…')
        t0 = time.time()
        cookies = login_all(http, base, args.students, args.concurrency)
        lecturer_cookie = None
        r = http.request('POST', f'{base}/login',
                         body=f'email=lect%40staff.funaab.edu.ng&password={PASSWORD}',
                         retries=False, redirect=False,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
        lecturer_cookie = r.headers.get('Set-Cookie', '').split(';', 1)[0]
        print(f'  {args.students} logins in {time.time() - t0:.1f}s')

        # Lecturer's projector polls the roll-call feed during the burst,
        # exactly like the real page (with the ?known= shortcut).
        stop_poll = threading.Event()
        poll_stats = {'polls': 0, 'errors': 0}

        def projector():
            known = -1
            while not stop_poll.is_set():
                try:
                    r = http.request(
                        'GET', f'{base}/api/session/{session_id}/attendees?known={known}',
                        headers={'Cookie': lecturer_cookie}, retries=False)
                    if r.status == 200:
                        known = json.loads(r.data)['present']
                    else:
                        poll_stats['errors'] += 1
                    poll_stats['polls'] += 1
                except Exception:
                    poll_stats['errors'] += 1
                stop_poll.wait(2)

        poller = threading.Thread(target=projector, daemon=True)
        poller.start()

        print(f'BURST: {args.students} scans, {args.concurrency} concurrent…')
        latencies, failures = [], []

        def scan(i):
            payload = json.dumps({
                'qr_data': sign_token(session_id),
                'lat': 7.2233, 'lon': 3.4403,
                'device_id': f'load-device-{i}',
            })
            t = time.time()
            try:
                r = http.request('POST', f'{base}/mark_attendance', body=payload,
                                 headers={'Content-Type': 'application/json',
                                          'Cookie': cookies[i]},
                                 retries=False, timeout=urllib3.Timeout(total=60))
                elapsed = time.time() - t
                body = json.loads(r.data)
                if r.status == 200 and body.get('status') == 'success':
                    latencies.append(elapsed)
                else:
                    failures.append(body.get('message', f'HTTP {r.status}'))
            except Exception as e:
                failures.append(str(e))

        t0 = time.time()
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            list(pool.map(scan, range(args.students)))
        wall = time.time() - t0
        stop_poll.set()
        poller.join(timeout=5)

        # Verify every scan actually landed in the database
        import sqlite3
        conn = sqlite3.connect(db_path)
        db_rows = conn.execute('SELECT COUNT(*) FROM attendance WHERE session_id=?',
                               (session_id,)).fetchone()[0]
        conn.close()

        latencies.sort()
        print('\n================ RESULTS ================')
        print(f'students          : {args.students}')
        print(f'successful scans  : {len(latencies)}')
        print(f'failed scans      : {len(failures)}')
        print(f'rows in database  : {db_rows}')
        print(f'burst wall time   : {wall:.1f}s')
        print(f'throughput        : {len(latencies) / wall:.0f} scans/second')
        if latencies:
            print(f'latency p50       : {percentile(latencies, 50) * 1000:.0f} ms')
            print(f'latency p95       : {percentile(latencies, 95) * 1000:.0f} ms')
            print(f'latency p99       : {percentile(latencies, 99) * 1000:.0f} ms')
            print(f'latency max       : {latencies[-1] * 1000:.0f} ms')
            print(f'latency mean      : {statistics.mean(latencies) * 1000:.0f} ms')
        print(f'projector polls   : {poll_stats["polls"]} ({poll_stats["errors"]} errors)')
        if failures:
            print('\nfirst failures:')
            for f in failures[:5]:
                print(f'  - {f}')
        print('=========================================')
        ok = len(latencies) == args.students == db_rows and not failures
        print('LOAD TEST PASSED' if ok else 'LOAD TEST FAILED')
        return 0 if ok else 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        for suffix in ('', '-wal', '-shm'):
            try:
                os.remove(db_path + suffix)
            except OSError:
                pass


if __name__ == '__main__':
    sys.exit(main())
