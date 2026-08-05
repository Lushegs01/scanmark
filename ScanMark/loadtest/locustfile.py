"""
Full-class scan-burst load test for ScanMark.

Simulates N students logging in and scanning the class QR within a short
window — the worst-case load pattern (start of a large lecture).

⚠️  Run this against a STAGING deployment only, never production: it creates
real attendance rows and real notification work.

Setup
-----
1. Seed staging. Run this WHERE DATABASE_URL REACHES STAGING (a staging shell,
   or your laptop with DATABASE_URL pointed at the staging database):

    python loadtest/seed_staging.py --students 2000

   It prints TARGET_SESSION_ID and STUDENT_PASSWORD. Clean up afterwards with
   `--teardown`.

2. Install locust (not a runtime dependency): pip install locust

3. Run locust ON YOUR OWN MACHINE — never on the server, or the load generator
   competes with the app for CPU and you measure the wrong thing.

   One locust process is single-threaded and becomes the bottleneck long
   before 2000 users, so a real burst needs one process per core.

   macOS / Linux / WSL
   -------------------
    export TARGET_SECRET_KEY=<staging SECRET_KEY>
    export TARGET_SESSION_ID=<printed by the seeder>
    export STUDENT_PASSWORD=<printed by the seeder>
    export STUDENT_POOL=2000     # how many students you actually seeded
    export WORKER_COUNT=4        # must match --processes below

    ulimit -n 8192               # 2000 concurrent sockets need the headroom
    locust -f loadtest/locustfile.py --host https://staging.yourdomain \
           --users 2000 --spawn-rate 50 --headless --run-time 5m --processes 4

   Windows
   -------
   `--processes` is not supported on Windows (locust forks, which Windows has
   no equivalent of), and there is no `ulimit`. WSL is by far the easier
   route — inside it, use the Unix block above verbatim.

   To stay in native cmd.exe, set variables with `set` and start the master
   and workers as separate processes by hand. In the first window:

    set TARGET_SECRET_KEY=<staging SECRET_KEY>
    set TARGET_SESSION_ID=<printed by the seeder>
    set STUDENT_PASSWORD=<printed by the seeder>
    set STUDENT_POOL=2000
    set WORKER_COUNT=4
    locust -f loadtest/locustfile.py --host https://staging.yourdomain ^
           --users 2000 --spawn-rate 50 --headless --run-time 5m ^
           --master --expect-workers 4

   Then in four more windows, each with the SAME five `set` lines:

    locust -f loadtest/locustfile.py --worker

   (PowerShell uses $env:NAME="value" instead of `set`, and a backtick ` for
   line continuation instead of ^.)

Watch for: p95 response time on /mark_attendance, 429/5xx rates, and
"expired" errors (means the queue is longer than QR_CODE_WINDOW).

If you see a flood of "could not sign in" on stderr, STUDENT_POOL does not
match what you seeded — that is the harness, not the server.
"""
import hashlib
import hmac
import itertools
import os
import re
import sys
import time

from locust import HttpUser, task, between
from locust.exception import StopUser

SECRET_KEY = os.environ.get('TARGET_SECRET_KEY', '')
SESSION_ID = int(os.environ.get('TARGET_SESSION_ID', '1'))
PASSWORD = os.environ.get('STUDENT_PASSWORD', 'pass1234')
EMAIL_PATTERN = os.environ.get('EMAIL_PATTERN', 'st{n}@student.funaab.edu.ng')

# How many students were actually seeded. Each simulated student scans once and
# stops, so locust keeps spawning replacements to hold the population at
# --users; without a bound the counter runs past the seeded pool and every
# replacement tries to sign in as an account that does not exist. That shows up
# as a wall of CSRF 400s which reads like the server failing under load when it
# is really the harness asking for students nobody created. Wrapping the
# counter reuses real accounts instead; a reused student gets "already marked
# present", which this file already counts as a success.
STUDENT_POOL = int(os.environ.get('STUDENT_POOL', '0'))

# How many locust processes are running (match --processes, or the number of
# --worker processes you started by hand). Every process gets its OWN copy of
# the counter below, starting at 1 — so with 4 workers and no offset, all four
# drive st1, st2, st3 … simultaneously: the first quarter of the pool gets
# hammered by four concurrent sessions each while the rest is never touched.
# Duplicate scans answer "already marked present", which this file counts as a
# success, so the run would look healthy while measuring the duplicate-check
# path instead of 2000 real inserts. Interleaving by worker index fixes that.
WORKER_COUNT = int(os.environ.get('WORKER_COUNT', '1'))

_user_counter = itertools.count(1)


def _next_email(worker_index=0):
    local = next(_user_counter)
    # Worker 0 takes students 1, 1+W, 1+2W …; worker 1 takes 2, 2+W …
    n = (local - 1) * WORKER_COUNT + worker_index + 1
    if STUDENT_POOL > 0:
        n = ((n - 1) % STUDENT_POOL) + 1
    return EMAIL_PATTERN.format(n=n)


def make_qr_token(session_id: int) -> str:
    """Mint a token exactly like the server does (see generate_signed_qr)."""
    message = f"S{session_id}|{int(time.time())}"
    sig = hmac.new(SECRET_KEY.encode(), message.encode(),
                   hashlib.sha256).hexdigest()[:16]
    return f"{message}|{sig}"


class ScanningStudent(HttpUser):
    # Students don't scan in perfect lock-step; a little natural spread.
    wait_time = between(0.5, 3)

    def on_start(self):
        # 0 when running single-process; distinct per worker otherwise.
        self.email = _next_email(getattr(self.environment.runner, 'worker_index', 0) or 0)

        # Login: GET the form for the CSRF token, then POST credentials.
        page = self.client.get('/login')
        m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        if not m:
            raise StopUser()
        self.client.post('/login', data={
            'csrf_token': m.group(1),
            'email': self.email,
            'password': PASSWORD,
        })
        # A FAILED login also returns HTTP 200 — it re-renders the form — so the
        # status code proves nothing. The scan page is the real test: it is
        # @login_required, so an anonymous client gets redirected to /login and
        # never sees a CSRF token. Checking the status code here instead let
        # unauthenticated users through to POST /mark_attendance with an empty
        # token, turning "this account was never seeded" into a misleading 400.
        scan_page = self.client.get('/scan_page')
        m = re.search(r'CSRF_TOKEN = "([^"]+)"', scan_page.text)
        if not m:
            print(f"[setup] {self.email} could not sign in — is it seeded, "
                  f"verified, and is STUDENT_PASSWORD right? "
                  f"(set STUDENT_POOL to the number of seeded students)",
                  file=sys.stderr)
            raise StopUser()
        self.csrf = m.group(1)

    @task
    def scan_attendance(self):
        with self.client.post('/mark_attendance',
                              json={'qr_data': make_qr_token(SESSION_ID),
                                    'lat': None, 'lon': None},
                              headers={'X-CSRFToken': self.csrf},
                              catch_response=True) as resp:
            try:
                body = resp.json()
            except Exception:
                resp.failure(f"non-JSON reply (HTTP {resp.status_code})")
                return
            if body.get('status') == 'success' or 'already marked' in body.get('message', ''):
                resp.success()
                # A real student scans once and puts the phone away.
                self.client.get('/student_dashboard')
                raise StopUser()
            elif 'expired' in body.get('message', ''):
                # Queueing exceeded QR_CODE_WINDOW — the metric to watch.
                resp.failure('token expired in queue')
            else:
                resp.failure(body.get('message', 'unknown error'))
