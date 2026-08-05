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

3. On YOUR OWN MACHINE — never on the server, or the load generator competes
   with the app for CPU and you measure the wrong thing — export the staging
   config so the test can mint valid QR tokens:

    export TARGET_SECRET_KEY=<staging SECRET_KEY>
    export TARGET_SESSION_ID=<printed by the seeder>
    export STUDENT_PASSWORD=<printed by the seeder>
    export STUDENT_POOL=2000       # how many students you actually seeded
    # optional: export EMAIL_PATTERN='st{n}@student.funaab.edu.ng'

4. Run the burst (2000 students, spawning 50/second). `--processes -1` uses
   every core: one locust process is single-threaded and becomes the
   bottleneck long before 2000 users, so without it you measure your laptop.

    ulimit -n 8192      # 2000 concurrent sockets need the headroom
    locust -f loadtest/locustfile.py --host https://staging.yourdomain \
           --users 2000 --spawn-rate 50 --headless --run-time 5m --processes -1

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

_user_counter = itertools.count(1)


def _next_email():
    n = next(_user_counter)
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
        self.email = _next_email()

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
