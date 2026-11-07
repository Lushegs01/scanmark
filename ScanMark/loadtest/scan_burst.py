"""
A truly simultaneous scan burst against an already-authenticated class.

WHY THIS EXISTS, SEPARATELY FROM locustfile.py
----------------------------------------------
Every Locust scenario in this directory signs its virtual student in and then
scans, so a 2,000-user run measures ``login + scan`` and reports the sum under
the scan's name. That matters more than it sounds: verifying one password
costs ~100 ms of CPU (Werkzeug's scrypt), so a 2,000-user spawn spends minutes
of CPU on authentication while the scans it is supposed to be measuring queue
behind it. The published "scan p95" then describes password hashing.

Real classes do not work that way. Students are signed in before the lecturer
projects the code — the session cookie is already in the phone. The burst that
has to be survived is 2,000 *scans* inside a few seconds, from sessions that
already exist.

So this tool splits the two:

  Phase 1 (untimed)  sign every student in, keep the cookie jar
  Phase 2 (timed)    release every scan at once against a barrier

Phase 2 is the number. Phase 1 is reported separately, because the login
stampede is its own capacity question and deserves its own answer.

It also verifies the invariant that matters more than any latency figure:
every admitted scan is in the database exactly once.

``--mode manual`` sends the typed eight-digit attendance code instead of a QR
token (POST /api/attendance/manual), and ``--mode mixed`` deals students
between the two by ``--manual-ratio``, as a real hall does: most scan, the
ones whose cameras cannot, type. Codes are derived with the server's own
algorithm (manual_code.py) from the same secret, exactly as tokens are, and
the burst waits for a window with at least 30 seconds left, so a rotation
mid-burst is not mistaken for a capacity problem.

    python loadtest/scan_burst.py --host https://staging.example \\
        --students 2000 --session-id 1 --secret "$TARGET_SECRET_KEY" \\
        --database-url "$DATABASE_URL"

Never point it at production: successful runs create attendance.
"""

from gevent import monkey  # isort:skip
monkey.patch_all()  # noqa: E402  must precede every stdlib import below

import argparse  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402
import random  # noqa: E402
import re  # noqa: E402
import statistics  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402
from collections import Counter  # noqa: E402

import gevent  # noqa: E402
import requests  # noqa: E402
import gevent.lock  # noqa: E402
from gevent.pool import Pool  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from scan_validation import (  # noqa: E402
    acceptance_errors, attendance_counts, expected_attendance, verify_attendance,
)

# manual_code.py is framework-free on purpose, so the harness derives the
# projector's code exactly as the server does, without importing the app.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import manual_code  # noqa: E402

_METRES_PER_DEGREE_LAT = 111_194.9266


def percentile(ordered, ratio):
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * ratio) - 1))
    return ordered[index]


def summarise(name, samples, extra=''):
    if not samples:
        print(f'  {name:<24} no samples')
        return
    ordered = sorted(samples)
    print(f'  {name:<24} n={len(ordered):<6} '
          f'p50={percentile(ordered, .50):7.1f}  p75={percentile(ordered, .75):7.1f}  '
          f'p90={percentile(ordered, .90):7.1f}  p95={percentile(ordered, .95):7.1f}  '
          f'p99={percentile(ordered, .99):7.1f}  max={ordered[-1]:7.1f}  '
          f'mean={statistics.fmean(ordered):7.1f} ms {extra}')


def make_token(secret, session_id, age_seconds=0):
    message = f'S{session_id}|{int(time.time()) - age_seconds}'
    signature = hmac.new(secret.encode(), message.encode(),
                         hashlib.sha256).hexdigest()[:16]
    return f'{message}|{signature}'


def seat(lat, lon, spread_m):
    north = random.uniform(-spread_m, spread_m)
    east = random.uniform(-spread_m, spread_m)
    per_lon = _METRES_PER_DEGREE_LAT * max(0.1, abs(math.cos(math.radians(lat))))
    return lat + north / _METRES_PER_DEGREE_LAT, lon + east / per_lon


class _AcceptSecureCookies(requests.cookies.RequestsCookieJar):
    """
    A cookie jar that carries a ``Secure`` cookie over plain HTTP.

    Only ever used with ``--proxied-https``. Production terminates TLS at a
    load balancer, so the app sets ``Secure`` and the browser — which really
    is on an HTTPS connection — sends it back. A rehearsal that talks HTTP
    straight to gunicorn is standing where the load balancer stands, and
    ``requests`` would drop the cookie, so every POST fails CSRF and the run
    measures the rejection path.

    The alternative, terminating TLS inside gunicorn, charges the application
    for handshakes production does not do there: at 600 simultaneous
    connections it produced 489 SSL transport errors and a scan measurement
    of 111 requests. Nothing here weakens the server, which still sets the
    flag.
    """

    def set_cookie(self, cookie, *args, **kwargs):
        cookie.secure = False
        return super().set_cookie(cookie, *args, **kwargs)


class Phone:
    """One student's browser: a cookie jar, a CSRF token, a seat."""

    __slots__ = ('number', 'session', 'csrf', 'marker', 'lat', 'lon',
                 'device_id', 'session_id', 'login_ms', 'method')

    def __init__(self, number, session_id, lat, lon, method='qr'):
        self.method = method
        self.number = number
        self.session_id = session_id
        self.session = requests.Session()
        self.csrf = None
        self.marker = None
        self.lat = lat
        self.lon = lon
        self.device_id = f'burst-{uuid.uuid4()}'
        self.login_ms = 0.0

    def sign_in(self, host, email, password, verify, headers=None, attempts=3):
        base = dict(headers or {})
        started = time.perf_counter()
        try:
            for attempt in range(attempts):
                reason, response = self._try_sign_in(host, email, password,
                                                     verify, base)
                if reason != 'retry':
                    return reason
                # 503 + Retry-After is deliberate shedding, not a failure: the
                # server is protecting its password-hashing budget and telling
                # us when to come back. Honouring it — bounded, with jitter —
                # is the difference between a queue that drains and a retry
                # storm. A client that ignored it would put the instance
                # straight back into the state the shedding exists to prevent.
                if attempt == attempts - 1:
                    return f'login_http_{response.status_code}_after_retries'
                delay = float(response.headers.get('Retry-After', 3) or 3)
                gevent.sleep(delay * (1 + random.random()))
            return 'login_retry_exhausted'
        except requests.RequestException as error:
            return f'login_error:{type(error).__name__}'
        finally:
            self.login_ms = (time.perf_counter() - started) * 1000

    def _try_sign_in(self, host, email, password, verify, base):
        """(reason|None|'retry', response)."""
        if True:
            page = self.session.get(f'{host}/login', timeout=60, verify=verify,
                                    headers=base)
            match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
            if not match:
                return 'no_login_form', page
            # Referer: Flask-WTF's WTF_CSRF_SSL_STRICT refuses an HTTPS POST
            # without one. Browsers send it; so must anything pretending to be
            # one.
            response = self.session.post(
                f'{host}/login',
                data={'csrf_token': match.group(1), 'email': email,
                      'password': password},
                headers=base | {'Referer': f'{self.origin(host, base)}/login'},
                timeout=60, verify=verify, allow_redirects=True)
            if response.status_code in (429, 503) and response.headers.get('Retry-After'):
                return 'retry', response
            if response.status_code >= 400:
                return f'login_http_{response.status_code}', response
            if response.url.endswith('/login'):
                return 'login_rejected', response
            scan_page = self.session.get(f'{host}/scan_page', timeout=60,
                                         verify=verify, headers=base)
            match = re.search(r'csrfToken:\s*"([^"]+)"', scan_page.text)
            if not match:
                return 'no_scan_csrf', scan_page
            self.csrf = match.group(1)
            marker = re.search(r'userMarker:\s*"([^"]+)"', scan_page.text)
            self.marker = marker.group(1) if marker else None
            return None, response

    @staticmethod
    def origin(host, headers):
        """The origin the SERVER believes it is serving, for the Referer."""
        if headers.get('X-Forwarded-Proto') == 'https' and host.startswith('http://'):
            return 'https://' + host[len('http://'):]
        return host

    def manual_body(self, code, accuracy_range, age_range):
        """What the attendance-code form posts: no camera, no capture time."""
        return {
            'code': f'{code[:4]} {code[4:]}',
            'session_id': self.session_id,
            'lat': self.lat,
            'lon': self.lon,
            'accuracy_m': random.uniform(*accuracy_range),
            'location_age_ms': random.uniform(*age_range),
            'user_marker': self.marker,
            'device_id': self.device_id,
        }

    def scan_body(self, secret, accuracy_range, age_range, lag_range):
        lag_ms = random.uniform(*lag_range)
        return {
            'qr_data': make_token(secret, self.session_id),
            'lat': self.lat,
            'lon': self.lon,
            'accuracy_m': random.uniform(*accuracy_range),
            'location_age_ms': random.uniform(*age_range),
            'captured_at': (time.time() * 1000) - lag_ms,
            'user_marker': self.marker,
            'device_id': self.device_id,
            'client_metrics': {
                'camera_ready_ms': random.uniform(200, 1200),
                'qr_decode_ms': random.uniform(20, 250),
                'gps_wait_ms': random.uniform(50, 2000),
                'capture_to_request_ms': lag_ms,
            },
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default=os.environ.get('TARGET_HOST',
                                                         'http://127.0.0.1:8100'))
    parser.add_argument('--students', type=int, default=600)
    parser.add_argument('--first-student', type=int, default=1)
    parser.add_argument('--session-id', default=os.environ.get(
        'TARGET_SESSION_IDS', '1'),
        help='one id, or a comma-separated set for concurrent classes')
    parser.add_argument('--secret', default=os.environ.get('TARGET_SECRET_KEY', ''))
    parser.add_argument('--password', default=os.environ.get('STUDENT_PASSWORD',
                                                             'pass1234'))
    parser.add_argument('--email-pattern', default=os.environ.get(
        'EMAIL_PATTERN', 'st{n}@student.funaab.edu.ng'))
    parser.add_argument('--lat', type=float,
                        default=float(os.environ.get('CLASS_LAT', '7.2257')))
    parser.add_argument('--lon', type=float,
                        default=float(os.environ.get('CLASS_LON', '3.4372')))
    parser.add_argument('--spread-m', type=float, default=25.0)
    parser.add_argument('--login-concurrency', type=int, default=32,
                        help='Phase 1 only. Kept low on purpose: password '
                             'verification is CPU-bound, and saturating it '
                             'here would just be the login stampede test.')
    parser.add_argument('--burst-concurrency', type=int, default=0,
                        help='0 = all at once, which is the point')
    parser.add_argument('--arrival-seconds', type=float, default=0,
                        help='spread the class evenly over this many seconds '
                             'instead of releasing it in one instant: the '
                             '"500 students mark attendance within 30-90 s" '
                             'shape of a real lecture (0 = simultaneous)')
    parser.add_argument('--projector-watchers', type=int, default=0,
                        help='poll the lecturer attendee feed for the whole of '
                             'Phase 2, as the projected roll-call screen does. '
                             'During a burst the projector is hitting the '
                             'server every second too, and its cost belongs in '
                             'the picture.')
    parser.add_argument('--projector-interval', type=float, default=1.0)
    parser.add_argument('--projector-email', default=os.environ.get(
        'PROJECTOR_EMAIL', 'lect@staff.funaab.edu.ng'),
        help='the feed is authorised per course, so the projector has to be '
             'signed in as somebody who teaches it. Polling it as a student '
             'measures the 403 path.')
    parser.add_argument('--projector-password', default=os.environ.get(
        'PROJECTOR_PASSWORD', ''))
    parser.add_argument('--login-noise', type=int, default=0,
                        help='run this many CONCURRENT login attempts for the '
                             'whole of Phase 2, from students who are not in '
                             'the burst. This is the interference test: '
                             'verifying a password costs ~100 ms of CPU and '
                             '~32 MB, so a pre-lecture sign-in rush competes '
                             'directly with the scans, and the question that '
                             'matters is what it does to scan latency.')
    parser.add_argument('--warm-connections', action='store_true',
                        help='reuse the TCP connection Phase 1 opened. Off by '
                             'default because it is not what a phone does: it '
                             'sits on the scan page waiting for the lecturer '
                             'to project the code, and whichever of the phone, '
                             'the router or the server has the shortest idle '
                             'timeout closes the socket first. Scanning then '
                             'costs a fresh handshake. Leaving this off '
                             'measures that case; turning it on measures the '
                             'best case.')
    parser.add_argument('--mode', choices=('qr', 'manual', 'mixed'), default='qr',
                        help='qr: every phone scans; manual: every phone types '
                             'the attendance code; mixed: deal them by '
                             '--manual-ratio')
    parser.add_argument('--manual-ratio', type=float, default=0.5,
                        help='mixed mode: fraction of phones typing the code')
    parser.add_argument('--manual-secret', default=os.environ.get('MANUAL_CODE_SECRET', ''),
                        help='the server\'s MANUAL_CODE_SECRET, if it sets one; '
                             'otherwise the code key is derived from --secret')
    parser.add_argument('--resource-out', default='',
                        help='write server CPU/RSS, database connections and '
                             'Redis command cost for the burst window here '
                             '(runs loadtest/resource_sampler.py; the server '
                             'must be on this host)')
    parser.add_argument('--redis-url', default=os.environ.get('REDIS_URL', ''),
                        help='for --resource-out: the Redis the server uses')
    parser.add_argument('--label', default='burst')
    parser.add_argument('--json-out', default='')
    parser.add_argument('--insecure', action='store_true',
                        help='skip TLS verification (self-signed rehearsal certs)')
    parser.add_argument('--proxied-https', action='store_true',
                        help='the target is a plain-HTTP rehearsal of a '
                             'deployment that terminates TLS at a load '
                             'balancer. Sends X-Forwarded-Proto: https and an '
                             'https Referer, and accepts the Secure session '
                             'cookie the app correctly sets — which is what '
                             'the browser on the far side of a real router '
                             'does. Nothing on the server is relaxed; this '
                             'keeps TLS CPU out of a measurement of the app.')
    parser.add_argument('--database-url', default=os.environ.get('DATABASE_URL', ''),
                        help='required: verify the exact student/session cohort')
    arguments = parser.parse_args()

    if not arguments.secret:
        parser.error('--secret (or TARGET_SECRET_KEY) is required: the tool '
                     'mints the QR tokens with the server\'s own algorithm.')
    if not arguments.database_url:
        parser.error('--database-url (or DATABASE_URL) is required for correctness checks')
    if (arguments.students < 1 or arguments.login_concurrency < 1
            or arguments.burst_concurrency < 0 or arguments.login_noise < 0
            or arguments.projector_watchers < 0 or arguments.projector_interval <= 0):
        parser.error('Use positive students/login concurrency/interval and nonnegative concurrency/watchers')

    host = arguments.host.rstrip('/')
    verify = not arguments.insecure
    proxy_headers = ({'X-Forwarded-Proto': 'https'}
                     if arguments.proxied_https else {})
    try:
        session_ids = [int(value) for value in str(arguments.session_id).split(',')
                       if str(value).strip()]
        if not session_ids or min(session_ids) < 1:
            raise ValueError()
    except ValueError:
        parser.error('--session-id must contain positive integer IDs')
    numbers = list(range(arguments.first_student,
                         arguments.first_student + arguments.students))

    # Check BEFORE any writes. Old attendance must never masquerade as the
    # result of this burst, and another class's rows must not affect it.
    engine = create_engine(arguments.database_url)
    try:
        expected = expected_attendance(engine, [
            arguments.email_pattern.format(n=number) for number in numbers
        ], session_ids)
        if attendance_counts(engine, expected):
            parser.error('This cohort already has attendance; use fresh staging sessions')
    except Exception as error:
        # Database exceptions can contain credentials/connection strings.
        parser.error(f'Staging cohort preflight failed ({type(error).__name__}); '
                     'check database access, student emails and session IDs')

    print(f'== {arguments.label}: {arguments.students} students, '
          f'session(s) {session_ids}, host {host} ==')

    # ---------------- Phase 1: sign in (untimed, deliberately throttled) ----
    def method_for(index):
        if arguments.mode == 'mixed':
            # Even spacing rather than random: the ratio is exact, and typed
            # codes arrive interleaved with scans as they would in a hall.
            return ('manual' if math.floor((index + 1) * arguments.manual_ratio)
                    > math.floor(index * arguments.manual_ratio) else 'qr')
        return arguments.mode

    phones = []
    for index, number in enumerate(numbers):
        latitude, longitude = seat(arguments.lat, arguments.lon, arguments.spread_m)
        phones.append(Phone(number, session_ids[index % len(session_ids)],
                            latitude, longitude, method_for(index)))
    code_generator = manual_code.ManualCodeGenerator(
        manual_code.derive_key(arguments.manual_secret or arguments.secret))
    print(f'  methods: {dict(Counter(phone.method for phone in phones))}')

    login_failures = Counter()
    started = time.perf_counter()

    def do_login(phone):
        if proxy_headers:
            phone.session.cookies = _AcceptSecureCookies()
        reason = phone.sign_in(host, arguments.email_pattern.format(n=phone.number),
                              arguments.password, verify, proxy_headers)
        if reason:
            login_failures[reason] += 1

    pool = Pool(arguments.login_concurrency)
    pool.map(do_login, phones)
    login_wall = time.perf_counter() - started
    ready = [phone for phone in phones if phone.csrf]
    print('\nPhase 1 — authentication (NOT the burst measurement)')
    print(f'  signed in {len(ready)}/{len(phones)} in {login_wall:.1f}s '
          f'at concurrency {arguments.login_concurrency} '
          f'({len(ready)/max(login_wall, 1e-9):.1f} logins/sec)')
    summarise('login', [phone.login_ms for phone in phones])
    if login_failures:
        print(f'  login failures: {dict(login_failures)}')

    # ---------------- Phase 2: the burst (timed) ---------------------------
    latencies = []
    outcomes = Counter()
    statuses = Counter()
    server_ms = []
    retry_after = []
    by_method = {method: {'client': [], 'server': [], 'outcomes': Counter()}
                 for method in ('qr', 'manual')}
    gate = gevent.event.Event()

    def do_scan(phone):
        gate.wait()
        if arguments.arrival_seconds > 0:
            # Evenly spaced arrivals across the window, in roster order.
            gevent.sleep(arrival_offsets[phone.number])
        # Concurrency, when capped, is capped AFTER the gate. Capping it by
        # sizing the spawn pool instead would block the main greenlet inside
        # the spawn loop and it would never reach gate.set().
        if throttle is not None:
            throttle.acquire()
        try:
            _run_scan(phone)
        finally:
            if throttle is not None:
                throttle.release()

    def _run_scan(phone):
        if phone.method == 'manual':
            # In a simultaneous burst every phone types the code projected at
            # the gate, including phones delayed by a concurrency cap — never
            # a fresher one. Spread over a lecture, a student types whatever
            # the projector shows when they get to it.
            code = (code_generator.window(phone.session_id, time.time()).code
                    if arguments.arrival_seconds > 0 else burst_codes[phone.session_id])
            body = phone.manual_body(code, (8, 35), (200, 8000))
            path = '/api/attendance/manual'
        else:
            body = phone.scan_body(arguments.secret, (8, 35), (200, 8000), (150, 2500))
            # In a simultaneous burst all phones scan the same projected
            # token, including phones delayed by a concurrency cap: never
            # mint a fresher QR to conceal queueing. Spread over a lecture,
            # each phone reads whatever the projector shows when it arrives.
            if arguments.arrival_seconds > 0:
                body['qr_data'] = make_token(arguments.secret, phone.session_id)
                body['captured_at'] = time.time() * 1000
            else:
                body['qr_data'] = burst_tokens[phone.session_id]
                body['captured_at'] = burst_captured_at
            path = '/mark_attendance'
        stats = by_method[phone.method]
        request_started = time.perf_counter()
        try:
            # requests' timeout alone is a socket inactivity timeout, not
            # the browser's total AbortController deadline.
            with gevent.Timeout(20):
                response = phone.session.post(
                    f'{host}{path}', json=body,
                    headers=proxy_headers | {
                        'X-CSRFToken': phone.csrf,
                        'Referer': f'{Phone.origin(host, proxy_headers)}/scan_page'},
                    timeout=20, verify=verify, allow_redirects=False)
        except (requests.RequestException, gevent.Timeout) as error:
            outcomes[f'transport:{type(error).__name__}'] += 1
            stats['outcomes'][f'transport:{type(error).__name__}'] += 1
            statuses['transport_error'] += 1
            return
        latencies.append((time.perf_counter() - request_started) * 1000)
        stats['client'].append(latencies[-1])
        statuses[response.status_code] += 1
        # Server-Timing carries the per-stage numbers the app measured for
        # THIS request, which is how client-observed queueing is told apart
        # from work the application actually did.
        timing = response.headers.get('Server-Timing', '')
        total = sum(float(value) for value in
                    re.findall(r';dur=([0-9.]+)', timing)) if timing else 0.0
        if total:
            server_ms.append(total)
            stats['server'].append(total)
        if response.headers.get('Retry-After'):
            retry_after.append(response.headers['Retry-After'])
        try:
            outcome = response.json().get('outcome', 'no_outcome')
        except ValueError:
            outcome = f'non_json_{response.status_code}'
        outcomes[outcome] += 1
        stats['outcomes'][outcome] += 1

    # ---- optional: a login stampede running THROUGH the burst -------------
    noise_stop = gevent.event.Event()
    noise_logins = []
    noise_shed = Counter()

    def login_noise(seed):
        number = arguments.first_student + arguments.students + seed
        while not noise_stop.is_set():
            phone = Phone(number, session_ids[0], arguments.lat, arguments.lon)
            if proxy_headers:
                phone.session.cookies = _AcceptSecureCookies()
            started = time.perf_counter()
            reason = phone.sign_in(
                host, arguments.email_pattern.format(n=number),
                arguments.password, verify, proxy_headers, attempts=1)
            noise_logins.append((time.perf_counter() - started) * 1000)
            if reason:
                noise_shed[reason] += 1
            phone.session.close()

    noise = [gevent.spawn(login_noise, index)
             for index in range(arguments.login_noise)]

    # ---- optional: the lecturer's screen polling through the burst ---------
    feed_latencies = []
    feed_bytes = []
    feed_failures = Counter()

    def projector(session_id):
        lecturer = Phone(0, session_id, arguments.lat, arguments.lon)
        if proxy_headers:
            lecturer.session.cookies = _AcceptSecureCookies()
        reason = lecturer.sign_in(
            host, arguments.projector_email,
            arguments.projector_password or arguments.password,
            verify, proxy_headers)
        if reason and reason != 'no_scan_csrf':
            # 'no_scan_csrf' is expected: a lecturer has no scan page.
            feed_failures[f'projector_login:{reason}'] += 1
            return
        watcher = lecturer.session
        cursor = 0
        while not noise_stop.is_set():
            started = time.perf_counter()
            try:
                response = watcher.get(
                    f'{host}/api/session/{session_id}/attendees'
                    f'?after={cursor}&limit=250',
                    headers=proxy_headers, timeout=60, verify=verify)
                feed_latencies.append((time.perf_counter() - started) * 1000)
                feed_bytes.append(len(response.content))
                if response.status_code == 200:
                    cursor = response.json().get('last_id', cursor)
                else:
                    feed_failures[response.status_code] += 1
            except requests.RequestException as error:
                feed_failures[type(error).__name__] += 1
            gevent.sleep(arguments.projector_interval)

    watchers = [gevent.spawn(projector, session_ids[index % len(session_ids)])
                for index in range(arguments.projector_watchers)]

    if not arguments.warm_connections:
        # Drop the sockets Phase 1 left open, so the burst pays for the
        # handshake a real phone pays for after waiting on the projector.
        for phone in ready:
            phone.session.close()

    throttle = (gevent.lock.BoundedSemaphore(arguments.burst_concurrency)
                if arguments.burst_concurrency else None)
    arrival_offsets = {phone.number: index * arguments.arrival_seconds / max(1, len(ready))
                       for index, phone in enumerate(ready)}
    greenlets = [gevent.spawn(do_scan, phone) for phone in ready]
    gevent.sleep(0.2)                     # let every greenlet reach the gate
    if any(phone.method == 'manual' for phone in ready):
        # Release the class on a fresh code, as a lecturer's projector would
        # show it: a rotation mid-burst would turn a capacity run into a
        # measurement of how many students typed during the grace period.
        left = code_generator.window(session_ids[0], time.time()).expires_in(time.time())
        if left < 30:
            print(f'  waiting {left + 1:.0f}s for a fresh attendance code')
            gevent.sleep(left + 1)
    burst_codes = {sid: code_generator.window(sid, time.time()).code for sid in session_ids}
    burst_tokens = {sid: make_token(arguments.secret, sid) for sid in session_ids}
    sampler = None
    if arguments.resource_out:
        import signal
        import subprocess
        sampler = subprocess.Popen([
            sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         'resource_sampler.py'),
            '--out', arguments.resource_out,
            '--database-url', arguments.database_url,
            '--redis-url', arguments.redis_url])
        gevent.sleep(0.5)                 # its baseline, before the gate opens
    burst_captured_at = time.time() * 1000
    burst_started = time.perf_counter()
    gate.set()                            # release the whole class at once
    gevent.joinall(greenlets, raise_error=True)
    burst_wall = time.perf_counter() - burst_started
    resources = None
    if sampler is not None:
        sampler.send_signal(signal.SIGINT)
        sampler.wait(timeout=30)
        try:
            with open(arguments.resource_out, encoding='utf-8') as handle:
                resources = json.load(handle)
        except (OSError, ValueError):
            resources = None
    noise_stop.set()
    gevent.joinall(noise, timeout=30)
    gevent.joinall(watchers, timeout=30)

    admitted = outcomes.get('success', 0) + outcomes.get('duplicate', 0)
    print(f'\nPhase 2 — the burst ({len(ready)} simultaneous scans)')
    print(f'  wall {burst_wall:.2f}s   '
          f'{len(latencies)/max(burst_wall, 1e-9):.1f} scans/sec completed')
    summarise('scan (client)', latencies)
    summarise('scan (server stages)', server_ms,
              extra='<- excludes queueing in front of the app')
    if arguments.projector_watchers:
        print(f'  projector: {arguments.projector_watchers} screen(s) polled '
              f'every {arguments.projector_interval}s throughout '
              f'({len(feed_latencies)} polls)')
        summarise('  attendee feed', feed_latencies)
        if feed_bytes:
            print(f'    payload bytes  min={min(feed_bytes)} '
                  f'median={sorted(feed_bytes)[len(feed_bytes) // 2]} '
                  f'max={max(feed_bytes)}')
        if feed_failures:
            print(f'    feed failures: {dict(feed_failures)}')
    if arguments.login_noise:
        print(f'  interference: {arguments.login_noise} concurrent logins ran '
              f'throughout ({len(noise_logins)} completed)')
        summarise('  competing login', noise_logins)
        if noise_shed:
            print(f'  login outcomes while shedding: {dict(noise_shed)}')
    for method, stats in by_method.items():
        if stats['client']:
            print(f'  -- {method} ({len(stats["client"])} requests)')
            summarise(f'  {method} (client)', stats['client'])
            summarise(f'  {method} (server stages)', stats['server'])
            print(f'     outcomes {dict(stats["outcomes"].most_common())}')
    print(f'  statuses  {dict(sorted(statuses.items(), key=lambda kv: str(kv[0])))}')
    print(f'  outcomes  {dict(outcomes.most_common())}')
    if retry_after:
        print(f'  Retry-After seen on {len(retry_after)} responses '
              f'(values: {sorted(set(retry_after))})')
    if resources:
        print(f'  server resources over {resources["window_s"]}s: '
              f'cpu_s={resources["cpu_seconds"]} peak_cores={resources["peak_cores_busy"]} '
              f'peak_rss_mb={resources["peak_rss_mb"]} db={resources["db_connections"]}')
        for command, cost in list(resources.get('redis_commands', {}).items())[:6]:
            print(f'    redis {command:<10} calls={cost["calls"]:<6} usec/call={cost["usec_per_call"]}')

    # ---------------- Phase 3: what actually landed in the database --------
    verified = {}
    try:
        verified = verify_attendance(engine, expected)
        print('\nPhase 3 — correctness for this cohort only')
        print(f'  {verified}')
        print(f'  admitted by server   {admitted}')
    except Exception as error:                       # noqa: BLE001
        print(f'\nPhase 3 — correctness check failed ({type(error).__name__})')
    finally:
        engine.dispose()

    errors = acceptance_errors(arguments.students, len(ready), outcomes,
                               statuses, verified, latencies, feed_failures)
    if arguments.projector_watchers and not feed_latencies:
        errors.append('projector_not_measured')
    if arguments.burst_concurrency and arguments.burst_concurrency < arguments.students:
        errors.append('not_a_simultaneous_full_cohort_burst')
    if arguments.arrival_seconds > 0:
        print(f'  (arrivals spread over {arguments.arrival_seconds:.0f}s: a realistic '
              f'lecture, not the simultaneous-burst acceptance test)')
    print(f'\nAcceptance: {"FAIL: " + ", ".join(errors) if errors else "PASS"}')

    if arguments.json_out:
        ordered = sorted(latencies)
        with open(arguments.json_out, 'w', encoding='utf-8') as handle:
            json.dump({
                'label': arguments.label,
                'students': arguments.students,
                'authenticated': len(ready),
                'login_wall_s': login_wall,
                'login_failures': dict(login_failures),
                'burst_wall_s': burst_wall,
                'scans_per_second': len(latencies) / max(burst_wall, 1e-9),
                'client_ms': {stat: percentile(ordered, ratio) for stat, ratio in
                              (('p50', .50), ('p75', .75), ('p90', .90),
                               ('p95', .95), ('p99', .99))} | {
                    'max': ordered[-1] if ordered else 0},
                'server_stage_ms': {
                    stat: percentile(sorted(server_ms), ratio) for stat, ratio in
                    (('p50', .50), ('p95', .95), ('p99', .99))},
                'statuses': {str(key): value for key, value in statuses.items()},
                'outcomes': dict(outcomes),
                'verified': verified,
                'passed': not errors,
                'acceptance_errors': errors,
                'projector_failures': dict(feed_failures),
                'mode': arguments.mode,
                'resources': resources,
                'by_method': {
                    method: {
                        'requests': len(stats['client']),
                        'client_ms': {stat: percentile(sorted(stats['client']), ratio)
                                      for stat, ratio in (('p50', .50), ('p95', .95), ('p99', .99))},
                        'server_stage_ms': {stat: percentile(sorted(stats['server']), ratio)
                                            for stat, ratio in (('p50', .50), ('p95', .95), ('p99', .99))},
                        'outcomes': dict(stats['outcomes']),
                    } for method, stats in by_method.items() if stats['client']},
            }, handle, indent=2)
        print(f'\nwrote {arguments.json_out}')

    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
