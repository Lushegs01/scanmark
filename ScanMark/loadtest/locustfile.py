"""
Full-class scan-burst load test for ScanMark.

Simulates N students logging in and scanning the class QR within a short
window — the worst-case load pattern (start of a large lecture).

⚠️  Run this against a STAGING deployment only, never production: it creates
real attendance rows and real notification work.

Setup
-----
1. Seed staging with students st1..stN@student.funaab.edu.ng (all with the
   same password), enrolled in one course, and start a class session.
2. Install locust (not a runtime dependency): pip install locust
3. Export the staging server's config so the test can mint valid QR tokens:

    export TARGET_SECRET_KEY=<staging SECRET_KEY>
    export TARGET_SESSION_ID=<class session id>
    export STUDENT_PASSWORD=<seeded password>
    # optional: export EMAIL_PATTERN='st{n}@student.funaab.edu.ng'

4. Run the burst (2000 students, spawning 50/second):

    locust -f loadtest/locustfile.py --host https://staging.yourdomain \
           --users 2000 --spawn-rate 50 --headless --run-time 5m

Watch for: p95 response time on /mark_attendance, 429/5xx rates, and
"expired" errors (means the queue is longer than QR_CODE_WINDOW).
"""
import hashlib
import hmac
import itertools
import os
import re
import time

from locust import HttpUser, task, between
from locust.exception import StopUser

SECRET_KEY = os.environ.get('TARGET_SECRET_KEY', '')
SESSION_ID = int(os.environ.get('TARGET_SESSION_ID', '1'))
PASSWORD = os.environ.get('STUDENT_PASSWORD', 'pass1234')
EMAIL_PATTERN = os.environ.get('EMAIL_PATTERN', 'st{n}@student.funaab.edu.ng')

_user_counter = itertools.count(1)


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
        self.email = EMAIL_PATTERN.format(n=next(_user_counter))

        # Login: GET the form for the CSRF token, then POST credentials.
        page = self.client.get('/login')
        m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        if not m:
            raise StopUser()
        resp = self.client.post('/login', data={
            'csrf_token': m.group(1),
            'email': self.email,
            'password': PASSWORD,
        })
        if resp.status_code != 200:
            raise StopUser()

        # Grab the JSON-request CSRF token the way the scan page does.
        scan_page = self.client.get('/scan_page')
        m = re.search(r'CSRF_TOKEN = "([^"]+)"', scan_page.text)
        self.csrf = m.group(1) if m else ''

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
