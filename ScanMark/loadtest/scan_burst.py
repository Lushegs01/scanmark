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
                 'device_id', 'session_id', 'login_ms')

    def __init__(self, number, session_id, lat, lon):
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
                        help='if given, verify the rows the burst actually wrote')
    arguments = parser.parse_args()

    if not arguments.secret:
        parser.error('--secret (or TARGET_SECRET_KEY) is required: the tool '
                     'mints the QR tokens with the server\'s own algorithm.')

    host = arguments.host.rstrip('/')
    verify = not arguments.insecure
    proxy_headers = ({'X-Forwarded-Proto': 'https'}
                     if arguments.proxied_https else {})
    session_ids = [int(value) for value in str(arguments.session_id).split(',')
                   if str(value).strip()]
    numbers = list(range(arguments.first_student,
                         arguments.first_student + arguments.students))

    print(f'== {arguments.label}: {arguments.students} students, '
          f'session(s) {session_ids}, host {host} ==')

    # ---------------- Phase 1: sign in (untimed, deliberately throttled) ----
    phones = []
    for index, number in enumerate(numbers):
        latitude, longitude = seat(arguments.lat, arguments.lon, arguments.spread_m)
        phones.append(Phone(number, session_ids[index % len(session_ids)],
                            latitude, longitude))

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
    print(f'\nPhase 1 — authentication (NOT the burst measurement)')
    print(f'  signed in {len(ready)}/{len(phones)} in {login_wall:.1f}s '
          f'at concurrency {arguments.login_concurrency} '
          f'({len(ready)/max(login_wall, 1e-9):.1f} logins/sec)')
    summarise('login', [phone.login_ms for phone in phones])
    if login_failures:
        print(f'  login failures: {dict(login_failures)}')
    if not ready:
        print('  nothing authenticated; aborting before the burst')
        return 2

    # ---------------- Phase 2: the burst (timed) ---------------------------
    latencies = []
    outcomes = Counter()
    statuses = Counter()
    server_ms = []
    retry_after = []
    gate = gevent.event.Event()

    def do_scan(phone):
        gate.wait()
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
        body = phone.scan_body(arguments.secret, (8, 35), (200, 8000), (150, 2500))
        request_started = time.perf_counter()
        try:
            response = phone.session.post(
                f'{host}/mark_attendance', json=body,
                headers=proxy_headers | {
                    'X-CSRFToken': phone.csrf,
                    'Referer': f'{Phone.origin(host, proxy_headers)}/scan_page'},
                timeout=120, verify=verify)
        except requests.RequestException as error:
            detail = str(getattr(error, 'args', [''])[0])[:70]
            outcomes[f'transport:{type(error).__name__}: {detail}'] += 1
            statuses['transport_error'] += 1
            return
        latencies.append((time.perf_counter() - request_started) * 1000)
        statuses[response.status_code] += 1
        # Server-Timing carries the per-stage numbers the app measured for
        # THIS request, which is how client-observed queueing is told apart
        # from work the application actually did.
        timing = response.headers.get('Server-Timing', '')
        total = sum(float(value) for value in
                    re.findall(r';dur=([0-9.]+)', timing)) if timing else 0.0
        if total:
            server_ms.append(total)
        if response.headers.get('Retry-After'):
            retry_after.append(response.headers['Retry-After'])
        try:
            outcomes[response.json().get('outcome', 'no_outcome')] += 1
        except ValueError:
            outcomes[f'non_json_{response.status_code}'] += 1

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
    greenlets = [gevent.spawn(do_scan, phone) for phone in ready]
    gevent.sleep(0.2)                     # let every greenlet reach the gate
    burst_started = time.perf_counter()
    gate.set()                            # release the whole class at once
    gevent.joinall(greenlets)
    burst_wall = time.perf_counter() - burst_started
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
    print(f'  statuses  {dict(sorted(statuses.items(), key=lambda kv: str(kv[0])))}')
    print(f'  outcomes  {dict(outcomes.most_common())}')
    if retry_after:
        print(f'  Retry-After seen on {len(retry_after)} responses '
              f'(values: {sorted(set(retry_after))})')

    # ---------------- Phase 3: what actually landed in the database --------
    verified = {}
    if arguments.database_url:
        try:
            import sqlalchemy
            engine = sqlalchemy.create_engine(arguments.database_url)
            with engine.connect() as connection:
                rows, distinct_students, distinct_pairs = connection.execute(
                    sqlalchemy.text(
                        'SELECT count(*), count(DISTINCT student_id), '
                        'count(DISTINCT (student_id, session_id)) FROM attendance'
                    )).one()
            verified = {'rows': rows, 'distinct_students': distinct_students,
                        'duplicate_rows': rows - distinct_pairs}
            print(f'\nPhase 3 — correctness')
            print(f'  attendance rows      {rows}')
            print(f'  distinct students    {distinct_students}')
            print(f'  duplicate (student, session) rows {rows - distinct_pairs}')
            print(f'  admitted by server   {admitted}')
            if rows - distinct_pairs:
                print('  *** DUPLICATE ATTENDANCE — the unique index did not hold')
            if admitted != rows:
                print(f'  *** {admitted - rows} scans were told success/duplicate '
                      f'but are not on the register')
        except Exception as error:                       # noqa: BLE001
            print(f'\nPhase 3 — correctness check unavailable: {error}')

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
            }, handle, indent=2)
        print(f'\nwrote {arguments.json_out}')

    failures = sum(count for outcome, count in outcomes.items()
                   if outcome not in ('success', 'duplicate'))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
