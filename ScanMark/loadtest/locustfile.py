"""Authenticated ScanMark staging scenarios.

Every request this file sends is the request a real phone sends. That is the
whole point of it: the previous version posted ``lat=None, lon=None`` and left
out ``accuracy_m``, ``location_age_ms`` and ``captured_at`` entirely, so it
exercised a path production does not have. With the geofence on, those scans
are refused at the location check — before the database insert, the CampOS
enqueue and most of the work a real scan does — so the numbers it produced
were not capacity evidence for anything.

Select with ``SCENARIO=scan|login|double_scan|feed``. ``TARGET_SESSION_IDS``
may contain one id or a comma-separated set for simultaneous-class
rehearsals. Never point this at production: successful runs create attendance.

Run it with CSRF, rate limiting, Redis, Postgres, sessions and the geofence
ALL enabled. Turning any of them off to make a number look better means the
number describes a system nobody is running.
"""

import hashlib
import hmac
import itertools
import math
import os
import random
import re
import time
import uuid

from gevent.pool import Pool
from locust import HttpUser, between, task
from locust.exception import StopUser


SECRET_KEY = os.environ.get('TARGET_SECRET_KEY', '')
SESSION_IDS = [
    int(value) for value in os.environ.get('TARGET_SESSION_IDS', '1').split(',')
    if value.strip()
]
PASSWORD = os.environ.get('STUDENT_PASSWORD', 'pass1234')
EMAIL_PATTERN = os.environ.get('EMAIL_PATTERN', 'st{n}@student.funaab.edu.ng')
SCENARIO = os.environ.get('SCENARIO', 'scan').strip().lower()
DOUBLE_SCAN_CONCURRENCY = int(os.environ.get('DOUBLE_SCAN_CONCURRENCY', '20'))

# ---------------------------------------------------------------------------
# The classroom the virtual students are sitting in.
#
# This MUST match the location the staging lecturer pinned for the session
# under test, or every scan is legitimately refused as out of geofence and the
# run measures the rejection path. Set it from the pin you made; the default is
# FUNAAB's coordinates so a misconfigured run fails visibly rather than
# silently measuring the wrong thing.
# ---------------------------------------------------------------------------
CLASS_LAT = float(os.environ.get('CLASS_LAT', '7.2257'))
CLASS_LON = float(os.environ.get('CLASS_LON', '3.4372'))

# How far apart the virtual students sit, in metres. A lecture theatre is tens
# of metres across, and phone GPS indoors adds its own error — this is the
# spread of reported positions, not the size of the room.
CLASS_SPREAD_M = float(os.environ.get('CLASS_SPREAD_M', '25'))

# Reported GPS accuracy. Indoors this is routinely 15-40m; sampling it rather
# than sending a flattering constant is what makes the run exercise the same
# accuracy checks production applies.
ACCURACY_MIN_M = float(os.environ.get('ACCURACY_MIN_M', '8'))
ACCURACY_MAX_M = float(os.environ.get('ACCURACY_MAX_M', '35'))

# Age of the position fix a phone hands back, in milliseconds. Real devices
# serve a cached fix a few seconds old.
LOCATION_AGE_MIN_MS = int(os.environ.get('LOCATION_AGE_MIN_MS', '200'))
LOCATION_AGE_MAX_MS = int(os.environ.get('LOCATION_AGE_MAX_MS', '8000'))

# Delay between the camera reading the code and the request being sent, in
# milliseconds: the GPS wait plus the request build. The server checks
# captured_at against the token's own timestamp, so this has to be realistic.
CAPTURE_LAG_MIN_MS = int(os.environ.get('CAPTURE_LAG_MIN_MS', '150'))
CAPTURE_LAG_MAX_MS = int(os.environ.get('CAPTURE_LAG_MAX_MS', '2500'))

_METRES_PER_DEGREE_LAT = 111_194.9266

_user_counter = itertools.count()

# ---------------------------------------------------------------------------
# Which seeded students THIS process is allowed to sign in as.
#
# Locust spreads load across OS processes with --processes, and each one
# imports this module fresh — so a plain module-level counter restarts at 1 in
# every process and three processes all sign in as st1, st2, st3... The run
# still "passes": the second and third copies get 409 duplicate, which the
# scenario treats as success because for a student it is. What you get is a
# run that reports 2,000 scans and writes 667 rows.
#
# Each process therefore takes a disjoint slice by interleaving: worker 0
# takes students 1, 4, 7...; worker 1 takes 2, 5, 8...; and so on. Dense, so
# it still fits the seeded range exactly.
#
# LOCUST_WORKER_COUNT must match --processes; run_matrix.sh sets both from one
# value so they cannot drift.
# ---------------------------------------------------------------------------
WORKER_COUNT = max(1, int(os.environ.get('LOCUST_WORKER_COUNT', '1')))


def _worker_index(environment):
    """0-based index of this Locust process, or 0 when running single-process."""
    runner = getattr(environment, 'runner', None)
    index = getattr(runner, 'worker_index', None)
    if index is None:
        index = int(os.environ.get('LOCUST_WORKER_INDEX', '0'))
    return max(0, int(index)) % WORKER_COUNT


def make_qr_token(session_id, age_seconds=0):
    """Mint a token the server will accept, using the server's own algorithm."""
    message = f"S{session_id}|{int(time.time()) - age_seconds}"
    signature = hmac.new(
        SECRET_KEY.encode(), message.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"{message}|{signature}"


def seat_position():
    """A plausible seat in the room, as (lat, lon)."""
    north = random.uniform(-CLASS_SPREAD_M, CLASS_SPREAD_M)
    east = random.uniform(-CLASS_SPREAD_M, CLASS_SPREAD_M)
    latitude = CLASS_LAT + north / _METRES_PER_DEGREE_LAT
    # Longitude degrees shrink with latitude; at FUNAAB the difference is
    # small, but getting it wrong biases every distance the server computes.
    metres_per_degree_lon = _METRES_PER_DEGREE_LAT * max(
        0.1, abs(math.cos(math.radians(CLASS_LAT)))
    )
    longitude = CLASS_LON + east / metres_per_degree_lon
    return latitude, longitude


class AuthenticatedUser(HttpUser):
    abstract = True
    wait_time = between(0.2, 1.0)

    def login(self):
        # Interleaved so no two Locust processes claim the same student.
        number = next(_user_counter) * WORKER_COUNT + _worker_index(self.environment) + 1
        self.student_number = number
        self.session_id = SESSION_IDS[(number - 1) % len(SESSION_IDS)]
        # One stable id per virtual phone, exactly as the browser stores one
        # in localStorage. A fresh id per request would look like 2,000
        # devices belonging to one student.
        self.device_id = f"loadtest-{uuid.uuid4()}"
        self.latitude, self.longitude = seat_position()

        email = EMAIL_PATTERN.format(n=number)
        page = self.client.get('/login', name='/login [form]')
        match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        if not match:
            raise StopUser()
        response = self.client.post('/login', data={
            'csrf_token': match.group(1),
            'email': email,
            'password': PASSWORD,
        }, name='/login [authenticate]')
        if response.status_code >= 400 or '/login' in response.url:
            raise StopUser()
        scan_page = self.client.get('/scan_page', name='/scan_page [preload]')
        match = re.search(r'csrfToken:\s*"([^"]+)"', scan_page.text)
        if not match:
            raise StopUser()
        self.csrf = match.group(1)
        match = re.search(r'userMarker:\s*"([^"]+)"', scan_page.text)
        self.user_marker = match.group(1) if match else None

    def scan_payload(self, token=None):
        """
        The body a real phone posts. Every field production requires is here,
        because a scan that omits one is refused before it reaches the work
        this test exists to measure.
        """
        capture_lag_ms = random.uniform(CAPTURE_LAG_MIN_MS, CAPTURE_LAG_MAX_MS)
        return {
            'qr_data': token or make_qr_token(self.session_id),
            # Jittered per student around the pinned classroom.
            'lat': self.latitude,
            'lon': self.longitude,
            'accuracy_m': random.uniform(ACCURACY_MIN_M, ACCURACY_MAX_M),
            'location_age_ms': random.uniform(LOCATION_AGE_MIN_MS,
                                              LOCATION_AGE_MAX_MS),
            # When the camera read the code, not when we are posting it.
            'captured_at': (time.time() * 1000) - capture_lag_ms,
            'user_marker': self.user_marker,
            'device_id': self.device_id,
            'client_metrics': {
                'camera_ready_ms': random.uniform(200, 1200),
                'qr_decode_ms': random.uniform(20, 250),
                'gps_wait_ms': random.uniform(50, 2000),
                'capture_to_request_ms': capture_lag_ms,
            },
        }

    def scan(self, name='/mark_attendance [scan]', token=None):
        return self.client.post(
            '/mark_attendance',
            json=self.scan_payload(token),
            headers={'X-CSRFToken': self.csrf},
            name=name,
            catch_response=True,
        )


class ScanningStudent(AuthenticatedUser):
    """One student, one scan — the shape of a real class marking attendance."""

    abstract = SCENARIO != 'scan'

    def on_start(self):
        self.login()

    @task
    def scan_once(self):
        with self.scan() as response:
            try:
                payload = response.json()
            except ValueError:
                response.failure(f'non-JSON HTTP {response.status_code}')
                raise StopUser()

            outcome = payload.get('outcome', '')
            message = payload.get('message', '')

            if payload.get('status') == 'success' or outcome == 'duplicate':
                # Already-marked is a success from where the student stands.
                response.success()
            elif outcome == 'admission_throttled':
                # Deliberate shedding, not a fault — but it must be counted,
                # because a run that sheds most of a class has not proved the
                # class can be marked. The acceptance checker reads this name.
                response.failure('admission_throttled')
            elif outcome == 'database_saturated':
                response.failure('database_saturated')
            elif 'expired' in message.lower():
                # The failure mode that amplifies: expired scans make phones
                # retry, which is the burst again but larger.
                response.failure('token expired while queued')
            else:
                response.failure(
                    f'{outcome or "unexpected"}: {message or response.status_code}')
        raise StopUser()


class LoginStampedeStudent(AuthenticatedUser):
    """The pre-lecture login rush, measured separately from scanning."""

    abstract = SCENARIO != 'login'

    @task
    def login_once(self):
        self.login()
        raise StopUser()


class ProjectorFeedWatcher(AuthenticatedUser):
    """
    The lecturer's screen polling while the class scans.

    Worth its own scenario: during a 2,000-scan burst the projector is also
    hitting the server every second, and its cost has to be in the picture.
    """

    abstract = SCENARIO != 'feed'
    wait_time = between(1.0, 2.0)

    def on_start(self):
        self.login()
        self.cursor = 0

    @task
    def poll_feed(self):
        with self.client.get(
            f'/api/session/{self.session_id}/attendees'
            f'?after={self.cursor}&limit=250',
            name='/api/session/[id]/attendees',
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f'HTTP {response.status_code}')
                return
            payload = response.json()
            self.cursor = payload.get('last_id', self.cursor)
            response.success()


class ConcurrentDoubleScanner(AuthenticatedUser):
    """One student firing N simultaneous scans: the duplicate guard, under race."""

    abstract = SCENARIO != 'double_scan'

    def on_start(self):
        self.login()

    @task
    def race_duplicate_requests(self):
        # One token for all of them, as a real double-tap would produce.
        token = make_qr_token(self.session_id)
        pool = Pool(DOUBLE_SCAN_CONCURRENCY)
        jobs = [pool.spawn(self.scan, '/mark_attendance [duplicate race]', token)
                for _ in range(DOUBLE_SCAN_CONCURRENCY)]
        pool.join()
        successes = 0
        throttled = 0
        for job in jobs:
            response = job.value
            try:
                payload = response.json()
            except ValueError:
                response.failure('non-JSON duplicate-race response')
                continue
            outcome = payload.get('outcome', '')
            if payload.get('status') == 'success':
                successes += 1
                response.success()
            elif outcome == 'duplicate':
                response.success()
            elif outcome == 'admission_throttled':
                # Shed rather than rejected: it never reached the guard.
                throttled += 1
                response.success()
            else:
                response.failure(payload.get('message', 'unexpected duplicate-race result'))
        if successes > 1:
            raise RuntimeError(
                f'duplicate guard failed: {successes} inserts for one student')
        if successes == 0 and throttled == 0:
            raise RuntimeError('duplicate race recorded no attendance at all')
        raise StopUser()
