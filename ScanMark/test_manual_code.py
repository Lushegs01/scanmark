"""
The manual attendance code ("can't scan the QR? enter this code").

Organised the way the feature is: the code itself (pure, exact, no app),
the wrong-guess guard, the lecturer's projector endpoint, the student's
submission endpoint and its shared validation, record integrity across both
methods, and the race between ending a class and marking attendance.

Runs on SQLite with no Redis by default, like the rest of the suite. With
SCANMARK_TEST_REDIS_URL set (CI's Postgres job), the Redis guard tests use
the real Lua scripts and the PostgreSQL-only lock tests run.
"""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import manual_code as mc
from conftest import VALID_PASSWORD, scan_body

UNIT_KEY = mc.derive_key('unit-test-secret')


def generator(**overrides):
    options = {'rotation_seconds': 60, 'grace_seconds': 5, 'clock_skew_seconds': 2}
    options.update(overrides)
    return mc.ManualCodeGenerator(UNIT_KEY, **options)


# ============================================================================
# The code: derivation and the exact acceptance windows
# ============================================================================

class TestCodeGeneration:

    def test_every_code_is_exactly_eight_ascii_digits(self):
        gen = generator()
        for session_id in (1, 7, 12345, 2 ** 31 - 1):
            for step in range(200):
                code = gen.code_for_step(session_id, step)
                assert len(code) == 8 and code.isascii() and code.isdigit(), code

    def test_leading_zeros_are_kept_end_to_end(self):
        gen = generator()
        found = None
        for step in range(5000):
            code = gen.code_for_step(3, step)
            if code.startswith('0'):
                found = (step, code)
                break
        assert found, 'expected a code with a leading zero within 5000 windows'
        step, code = found
        assert len(code) == 8
        now = step * 60 + 1
        assert gen.window(3, now).code == code
        # Typed or pasted with the projector's grouping, the zero survives.
        typed = mc.normalize_code(mc.format_code(code))
        assert typed == code
        assert gen.verify(3, typed, now).ok

    def test_a_code_is_valid_for_its_own_session_only(self):
        gen = generator()
        now = 1_800_000_000.0
        code = gen.window(41, now).code
        assert gen.verify(41, code, now).ok
        assert gen.verify(42, code, now).result == mc.INVALID
        # Concurrent classes get independent codes (a 1e-8 chance otherwise).
        codes = {gen.window(session_id, now).code for session_id in range(1, 201)}
        assert len(codes) >= 199

    def test_it_rotates_exactly_on_the_server_minute(self):
        gen = generator()
        boundary = 1_800_000_000 - (1_800_000_000 % 60) + 60
        before = gen.window(5, boundary - 0.001)
        after = gen.window(5, boundary)
        assert before.step + 1 == after.step
        assert before.code != after.code
        assert before.expires_at == boundary == after.starts_at
        assert after.expires_in(boundary) == 60
        assert before.expires_in(boundary - 0.001) == pytest.approx(0.001, abs=1e-6)

    def test_the_previous_code_is_accepted_only_inside_the_grace_period(self):
        gen = generator(grace_seconds=5)
        start = 1_800_000_000 - (1_800_000_000 % 60)
        previous = gen.code_for_step(9, gen.step_at(start) - 1)
        assert gen.verify(9, previous, start).reason == 'grace'
        assert gen.verify(9, previous, start + 4.999).ok
        # Not one moment longer: the whole previous window is never valid
        # just because it was recently.
        expired = gen.verify(9, previous, start + 5.0)
        assert expired.result == mc.EXPIRED
        assert gen.verify(9, previous, start + 59).result == mc.EXPIRED

    def test_older_codes_are_expired_then_simply_wrong(self):
        gen = generator()
        now = 1_800_000_030.0
        step = gen.step_at(now)
        assert gen.verify(9, gen.code_for_step(9, step - 2), now).result == mc.EXPIRED
        assert gen.verify(9, gen.code_for_step(9, step - 3), now).result == mc.INVALID

    def test_the_next_code_needs_the_clock_skew_tolerance_and_no_more(self):
        gen = generator(clock_skew_seconds=2)
        start = 1_800_000_000 - (1_800_000_000 % 60)
        upcoming = gen.code_for_step(9, gen.step_at(start) + 1)
        assert gen.verify(9, upcoming, start + 57.9).result == mc.INVALID
        assert gen.verify(9, upcoming, start + 58.0).reason == 'clock_skew'
        assert generator(clock_skew_seconds=0).verify(9, upcoming, start + 59.9).result \
            == mc.INVALID

    def test_independent_workers_derive_identical_codes(self):
        """No shared state: every worker on every instance computes the same."""
        first = mc.ManualCodeGenerator(mc.derive_key('deployment-secret'))
        second = mc.ManualCodeGenerator(mc.derive_key('deployment-secret'))
        other = mc.ManualCodeGenerator(mc.derive_key('another-deployment'))
        now = 1_800_000_123.0
        for session_id in range(1, 50):
            assert first.window(session_id, now) == second.window(session_id, now)
        assert first.window(1, now).code != other.window(1, now).code or \
            first.window(2, now).code != other.window(2, now).code

    def test_the_key_is_purpose_separated_from_the_secret(self):
        import hashlib
        import hmac
        secret = 'deployment-secret'
        key = mc.derive_key(secret)
        assert key != secret.encode()
        assert key != mc.derive_key(secret, label=b'something-else')
        # A QR signature over the same session/time reveals nothing usable:
        # it is keyed with the raw secret, the code with the derived key.
        qr_style = hmac.new(secret.encode(), b'S1|1800000000', hashlib.sha256).hexdigest()
        assert mc.ManualCodeGenerator(key).window(1, 1_800_000_000).code not in qr_style

    def test_adjacent_windows_never_show_the_same_code_for_real(self):
        gen = generator()
        for session_id in (1, 2, 3):
            codes = [gen.code_for_step(session_id, step) for step in range(3000)]
            assert all(a != b for a, b in zip(codes, codes[1:]))

    def test_a_forced_adjacent_collision_is_resolved_without_extending_validity(
            self, monkeypatch):
        """Make every first candidate identical, the worst possible case."""
        gen = generator()

        def colliding(session_id, step, attempt):
            return 12345678 if attempt == 0 else 87650000 + attempt

        monkeypatch.setattr(gen, '_candidate', colliding)
        codes = [gen.code_for_step(1, step) for step in range(10, 20)]
        assert all(a != b for a, b in zip(codes, codes[1:])), codes
        # Even steps keep the colliding value; odd steps had to re-roll.
        assert codes[0] == '12345678' and codes[1] == '87650001'
        # The even code reappearing two windows later is a NEW window, not an
        # extension: mid-way through odd step 11, the even code (steps 10 and
        # 12) is only "expired", never valid.
        start_11 = 11 * 60
        assert gen.verify(1, '12345678', start_11 + 30).result == mc.EXPIRED
        assert gen.verify(1, '87650001', start_11 + 30).ok

    def test_double_exclusion_needs_the_third_candidate(self, monkeypatch):
        gen = generator()
        values = {(10, 0): 11111111, (12, 0): 22222222,
                  (11, 0): 11111111, (11, 1): 22222222, (11, 2): 33333333}
        monkeypatch.setattr(gen, '_candidate',
                            lambda _s, step, attempt: values.get((step, attempt), 44444444))
        assert gen.code_for_step(1, 11) == '33333333'

    @pytest.mark.parametrize('raw, expected', [
        ('48269137', '48269137'),
        ('4826 9137', '48269137'),
        (' 4826-9137 ', '48269137'),
        ('4826 9137', '48269137'),
        ('01234567', '01234567'),
        ('4826 913', None),
        ('482691370', None),
        ('4826 913a', None),
        ('٤٨٢٦٩١٣٧', None),  # Arabic-Indic digits
        ('４８２６９１３７', None),  # full-width digits
        (48269137, None),           # a JSON number has already lost its zeros
        (None, None),
        ('1' * 40, None),
        ('', None),
    ])
    def test_submitted_codes_are_normalised_strictly(self, raw, expected):
        assert mc.normalize_code(raw) == expected

    def test_settings_that_would_widen_validity_are_refused(self):
        with pytest.raises(ValueError):
            mc.ManualCodeGenerator(UNIT_KEY, rotation_seconds=60, grace_seconds=30)
        with pytest.raises(ValueError):
            mc.ManualCodeGenerator(UNIT_KEY, rotation_seconds=5)
        with pytest.raises(ValueError):
            mc.ManualCodeGenerator(b'short')


# ============================================================================
# The wrong-guess guard
# ============================================================================

def _redis_or_none():
    import os
    import redis
    url = os.environ.get('REDIS_URL') or 'redis://127.0.0.1:6390/9'
    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=0.3)
        client.ping()
        return client
    except redis.RedisError:
        return None


LIMITS = mc.GuardLimits(max_failures_per_session=5, session_window_seconds=600,
                        session_lockout_seconds=120, max_failures_per_account=8,
                        account_window_seconds=3600)


@pytest.fixture(params=['local', 'redis'])
def guard(request):
    if request.param == 'local':
        yield mc.LocalAttemptGuard(LIMITS)
        return
    client = _redis_or_none()
    if client is None:
        pytest.skip('no Redis available for the distributed guard')
    prefix = f'test_manual_code_{time.time_ns()}'
    yield mc.RedisAttemptGuard(client, LIMITS, prefix=prefix)
    for key in client.scan_iter(f'{prefix}:*'):
        client.delete(key)


def _fail(guard, user, session):
    reservation = guard.reserve(user, session)
    if not reservation.allowed:
        return reservation, None
    return reservation, guard.record_failure(user, session)


class TestAttemptGuard:

    def test_five_wrong_codes_lock_this_class_with_a_retry_time(self, guard):
        records = [_fail(guard, 1, 10)[1] for _ in range(5)]
        assert [r.attempts_remaining for r in records[:4]] == [4, 3, 2, 1]
        assert records[4].locked_for_seconds == 120
        refused = guard.reserve(1, 10)
        assert not refused.allowed
        assert 110 <= refused.retry_after_seconds <= 120
        assert refused.scope == 'session' and not refused.in_flight

    def test_a_correct_code_gives_its_attempt_back(self, guard):
        for _ in range(20):
            assert guard.reserve(1, 10).allowed
            guard.refund(1, 10)
        assert guard.reserve(1, 10).allowed

    def test_switching_classes_cannot_escape_the_account_limit(self, guard):
        # 4 failures in each of two classes: under the per-class limit, but 8
        # in total reaches the per-account one.
        for session in (10, 11):
            for _ in range(4):
                _fail(guard, 1, session)
        refused = guard.reserve(1, 12)
        assert not refused.allowed
        assert refused.scope == 'account'
        assert refused.retry_after_seconds > 120

    def test_one_students_mistakes_never_block_another(self, guard):
        for _ in range(5):
            _fail(guard, 1, 10)
        assert not guard.reserve(1, 10).allowed
        assert guard.reserve(2, 10).allowed

    def test_concurrent_guesses_cannot_exceed_the_limit(self, guard):
        """Reserve-before-verify: 40 simultaneous guesses, exactly 5 compared."""
        barrier = threading.Barrier(40)

        def attempt(_):
            barrier.wait()
            return guard.reserve(7, 70).allowed

        with ThreadPoolExecutor(max_workers=40) as pool:
            allowed = sum(pool.map(attempt, range(40)))
        assert allowed == LIMITS.max_failures_per_session

    def test_attempts_still_in_flight_do_not_impose_a_lockout(self, guard):
        for _ in range(5):
            assert guard.reserve(3, 30).allowed
        busy = guard.reserve(3, 30)
        assert not busy.allowed and busy.retry_after_seconds == mc.IN_FLIGHT_RETRY_SECONDS
        assert busy.in_flight
        for _ in range(5):
            guard.refund(3, 30)       # they were all correct after all
        assert guard.reserve(3, 30).allowed

    def test_the_lockout_ends(self):
        clock = [1000.0]
        local = mc.LocalAttemptGuard(LIMITS, clock=lambda: clock[0])
        for _ in range(5):
            _fail(local, 1, 10)
        assert not local.reserve(1, 10).allowed
        clock[0] += 121
        assert local.reserve(1, 10).allowed

    def test_redis_errors_surface_as_unavailable_never_as_allowed(self):
        import redis

        class DeadRedis:
            def register_script(self, _source):
                def script(**_kwargs):
                    raise redis.ConnectionError('connection refused')
                return script

        dead = mc.RedisAttemptGuard(DeadRedis(), LIMITS)
        with pytest.raises(mc.GuardUnavailable):
            dead.reserve(1, 1)
        with pytest.raises(mc.GuardUnavailable):
            dead.record_failure(1, 1)


# ============================================================================
# Helpers for the endpoint tests
# ============================================================================

ROOM = (7.2200, 3.4400)


@pytest.fixture(autouse=True)
def frozen_code_clock(request, monkeypatch):
    """
    Hold the code generator's clock mid-window, so a code read by the test
    and a code checked by the server can never straddle a real rotation.
    Tests about rotation move it themselves.
    """
    if 'appmod' not in request.fixturenames:
        yield None
        return
    appmod = request.getfixturevalue('appmod')
    frozen = (int(time.time()) // 60) * 60 + 20.0
    monkeypatch.setattr(appmod.manual_code_generator, '_clock', lambda: frozen)
    yield frozen


def current_code(appmod, session_id):
    return appmod.manual_code_generator.window(session_id).code


def manual_body(appmod, session_id=None, code=None, **overrides):
    body = {'code': code if code is not None else
            mc.format_code(current_code(appmod, session_id)),
            'device_id': 'pytest-manual'}
    if session_id is not None:
        body['session_id'] = session_id
    body.update(overrides)
    return {key: value for key, value in body.items() if value is not None}


def at_metres(metres, **overrides):
    location = {'lat': ROOM[0] + metres / 111320.0, 'lon': ROOM[1],
                'accuracy_m': 10, 'location_age_ms': 1000}
    location.update(overrides)
    return location


def wrong_code(appmod, session_id):
    real = current_code(appmod, session_id)
    candidate = '00000000' if real != '00000000' else '11111111'
    gen = appmod.manual_code_generator
    step = gen.step_at(gen.now())
    neighbours = {gen.code_for_step(session_id, step + delta) for delta in (-2, -1, 1)}
    while candidate in neighbours or candidate == real:
        candidate = f'{(int(candidate) + 1234567) % 10**8:08d}'
    return candidate


def enrol(appmod, student_id, course_id):
    from models import db, enrollments
    with appmod.app.app_context():
        db.session.execute(enrollments.insert(), {'user_id': student_id, 'course_id': course_id})
        db.session.commit()


def post_manual(client, body):
    return client.post('/api/attendance/manual', json=body)


def pin(appmod, session_id, lat=ROOM[0], lon=ROOM[1]):
    with appmod.app.app_context():
        appmod.set_class_location(session_id, lat, lon)


def add_session(appmod, course_id, title='Week 2'):
    from models import db, ClassSession
    with appmod.app.app_context():
        row = ClassSession(course_id=course_id, title=title)
        db.session.add(row)
        db.session.flush()
        appmod._snapshot_roster(row)
        db.session.commit()
        return row.id


def attendance_rows(appmod, **filters):
    from models import Attendance
    with appmod.app.app_context():
        return [(row.student_id, row.session_id, row.submission_method)
                for row in Attendance.query.filter_by(**filters).order_by(Attendance.id)]


# ============================================================================
# The projector: who may read the code
# ============================================================================

class TestProjectorEndpoint:

    def test_the_lecturer_gets_the_current_code_and_its_lifetime(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        response = ada.get(f"/api/session/{seed['session_id']}/manual_code")
        assert response.status_code == 200
        assert 'no-store' in response.headers['Cache-Control']
        data = response.get_json()
        assert data['code'] == current_code(appmod, seed['session_id'])
        assert data['display'] == f"{data['code'][:4]} {data['code'][4:]}"
        assert 0 < data['expires_in_ms'] <= 60_000
        assert data['rotation_seconds'] == 60

    def test_an_invited_lecturer_may_read_it_too(self, appmod, seed, login):
        from models import db, Course, User
        with appmod.app.app_context():
            course = db.session.get(Course, seed['course_id'])
            course.instructors.append(db.session.get(User, seed['lecturer_id']))
            db.session.commit()
        grace = login(seed['lecturer_email'])
        assert grace.get(f"/api/session/{seed['session_id']}/manual_code").status_code == 200

    @pytest.mark.parametrize('who', ['student_email', 'outsider_email', 'lecturer_email'])
    def test_nobody_else_can_read_the_code(self, appmod, seed, login, who):
        response = login(seed[who]).get(f"/api/session/{seed['session_id']}/manual_code")
        assert response.status_code == 403
        assert current_code(appmod, seed['session_id']) not in response.get_data(as_text=True)

    def test_an_anonymous_visitor_cannot_read_the_code(self, appmod, seed, client):
        response = client.get(f"/api/session/{seed['session_id']}/manual_code")
        assert response.status_code in (302, 401)
        assert current_code(appmod, seed['session_id']) not in response.get_data(as_text=True)

    def test_an_ended_class_has_no_code(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        ada.post(f"/session/{seed['session_id']}/end")
        response = ada.get(f"/api/session/{seed['session_id']}/manual_code")
        assert response.status_code == 409
        assert 'code' not in response.get_json()

    def test_the_projector_page_shows_the_code_inside_the_full_screen_stage(
            self, appmod, seed, login):
        page = login(seed['coordinator_email']).get(f"/session/{seed['session_id']}/qr")
        html = page.get_data(as_text=True)
        assert 'no-store' in page.headers['Cache-Control']
        code = current_code(appmod, seed['session_id'])
        assert f'<span>{code[:4]}</span><span>{code[4:]}</span>' in html
        assert "Can't scan the QR? Enter this code in ScanMark." in html
        # Inside the element that full screen enlarges, so projecting the QR
        # cannot hide the code.
        stage = html[html.index('id="qrStage"'):html.index('id="qrFullscreenBtn"')]
        assert 'id="manualCode"' in stage
        assert '.qr-stage.is-full .manual-code-digits' in html
        # Screen readers hear the digits one by one, not "forty-eight million".
        assert f"Attendance code {' '.join(code)}" in html
        # The countdown is driven by the server, never the projector's clock.
        script = html[html.index('1c. MANUAL ATTENDANCE CODE'):html.index('2. GPS LOCATION SETTER')]
        assert 'data-expires-in-ms=' in html
        assert 'Date.now' not in script and 'performance.now()' in script

    def test_the_countdown_matches_what_the_server_will_accept(self, appmod, seed):
        """What the projector is told to show is exactly what verify accepts."""
        sid = seed['session_id']
        now = 1_800_000_017.25
        with appmod.app.app_context():
            payload = appmod.manual_code_payload(sid, now=now)
        gen = appmod.manual_code_generator
        expires_at = now + payload['expires_in_ms'] / 1000
        assert gen.verify(sid, payload['code'], now).reason == 'current'
        assert gen.verify(sid, payload['code'], expires_at - 0.01).reason == 'current'
        assert gen.verify(sid, payload['code'], expires_at + 0.01).reason == 'grace'
        assert gen.verify(sid, payload['code'],
                          expires_at + gen.grace_seconds + 0.01).result == mc.EXPIRED

    def test_the_kill_switch_hides_the_code_everywhere(self, appmod, seed, login, monkeypatch):
        monkeypatch.setattr(appmod, 'MANUAL_CODE_ENABLED', False)
        ada = login(seed['coordinator_email'])
        assert 'id="manualCode"' not in ada.get(f"/session/{seed['session_id']}/qr").get_data(as_text=True)
        assert ada.get(f"/api/session/{seed['session_id']}/manual_code").status_code == 404
        kemi = login(seed['student_email'])
        assert 'manualCodeForm' not in kemi.get('/student_dashboard').get_data(as_text=True)
        response = post_manual(kemi, manual_body(appmod, seed['session_id']))
        assert response.status_code == 404
        assert response.get_json()['outcome'] == 'manual_code_disabled'
        # QR is untouched by the switch.
        assert kemi.post('/mark_attendance', json=scan_body(appmod, seed['session_id'])).status_code == 200


# ============================================================================
# The student's submission
# ============================================================================

class TestManualSubmission:

    def test_a_valid_code_records_attendance_with_its_method(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = post_manual(kemi, manual_body(appmod, seed['session_id']))
        data = response.get_json()
        assert response.status_code == 200, data
        assert data['outcome'] == 'success'
        assert data['message'] == 'Attendance successfully marked for CSC201.'
        assert data['course_title'] == 'Data Structures'
        assert data['submission_method'] == 'manual_code'
        assert data['marked_at'] and data['marked_at_local']
        assert attendance_rows(appmod) == [(seed['student_id'], seed['session_id'], 'manual_code')]

    def test_the_class_is_chosen_for_the_student_only_when_unambiguous(
            self, appmod, seed, login):
        kemi = login(seed['student_email'])
        body = manual_body(appmod, seed['session_id'])
        body.pop('session_id')
        assert post_manual(kemi, body).status_code == 200

    def test_several_open_classes_are_never_guessed_between(self, appmod, seed, login):
        from models import db, Course
        with appmod.app.app_context():
            second = Course(code='MTH101', title='Calculus', coordinator_id=seed['coordinator_id'],
                            institution='funaab.edu.ng')
            db.session.add(second)
            db.session.commit()
            second_id = second.id
        enrol(appmod, seed['student_id'], second_id)
        other_session = add_session(appmod, second_id, 'MTH Week 1')

        kemi = login(seed['student_email'])
        body = manual_body(appmod, seed['session_id'])
        body.pop('session_id')
        response = post_manual(kemi, body)
        data = response.get_json()
        assert response.status_code == 400 and data['outcome'] == 'session_required'
        assert {entry['session_id'] for entry in data['sessions']} == \
            {seed['session_id'], other_session}
        assert attendance_rows(appmod) == []
        # Choosing one marks that one, and only that one.
        assert post_manual(kemi, manual_body(appmod, other_session)).status_code == 200
        assert attendance_rows(appmod) == [(seed['student_id'], other_session, 'manual_code')]

    def test_no_open_class_says_so(self, appmod, seed, login):
        login(seed['coordinator_email']).post(f"/session/{seed['session_id']}/end")
        kemi = login(seed['student_email'])
        response = post_manual(kemi, {'code': '1234 5678'})
        assert response.status_code == 404
        assert response.get_json()['outcome'] == 'no_active_session'

    def test_the_session_list_shows_only_the_students_own_open_classes(
            self, appmod, seed, other_institution, login):
        kemi = login(seed['student_email'])
        data = kemi.get('/api/attendance/manual/sessions').get_json()
        assert [entry['session_id'] for entry in data['sessions']] == [seed['session_id']]
        assert data['sessions'][0]['already_marked'] is False
        body = json.dumps(data)
        for fingerprint in other_institution['fingerprints']:
            assert fingerprint not in body
        post_manual(kemi, manual_body(appmod, seed['session_id']))
        entry = kemi.get('/api/attendance/manual/sessions').get_json()['sessions'][0]
        assert entry['already_marked'] is True
        assert entry['submission_method'] == 'manual_code'

    def test_the_session_list_is_for_signed_in_students(self, appmod, seed, client, login):
        assert client.get('/api/attendance/manual/sessions').status_code == 401
        assert login(seed['coordinator_email']).get(
            '/api/attendance/manual/sessions').status_code == 403

    # ---- who may submit ---------------------------------------------------

    def test_an_anonymous_submission_is_refused(self, appmod, seed, client):
        response = post_manual(client, manual_body(appmod, seed['session_id']))
        assert response.status_code == 401
        assert response.get_json()['outcome'] == 'not_authenticated'
        assert attendance_rows(appmod) == []

    @pytest.mark.parametrize('who', ['coordinator_email', 'lecturer_email'])
    def test_staff_cannot_mark_attendance_with_a_code(self, appmod, seed, login, who):
        response = post_manual(login(seed[who]), manual_body(appmod, seed['session_id']))
        assert response.status_code == 403
        assert response.get_json()['outcome'] == 'not_student'
        assert attendance_rows(appmod) == []

    def test_an_unenrolled_student_is_refused_without_learning_the_course(
            self, appmod, seed, login):
        tayo = login(seed['other_student_email'])
        response = post_manual(tayo, manual_body(appmod, seed['session_id']))
        data = response.get_json()
        assert response.status_code == 403 and data['outcome'] == 'not_enrolled'
        assert 'CSC201' not in data['message']
        assert attendance_rows(appmod) == []

    def test_a_session_that_does_not_exist_looks_exactly_like_one_you_are_not_on(
            self, appmod, seed, login):
        kemi = login(seed['student_email'])
        missing = post_manual(kemi, manual_body(appmod, seed['session_id'] + 999,
                                                code='1234 5678'))
        tayo = login(seed['other_student_email'])
        foreign = post_manual(tayo, manual_body(appmod, seed['session_id']))
        assert missing.status_code == foreign.status_code == 403
        assert missing.get_json() == foreign.get_json()

    def test_another_universitys_class_cannot_be_marked(
            self, appmod, seed, other_institution, login):
        # Kemi (FUNAAB) aims at UNILAG's live session, with its real code.
        kemi = login(seed['student_email'])
        response = post_manual(kemi, manual_body(appmod, other_institution['session_id']))
        assert response.status_code == 403
        assert 'Unilag' not in response.get_data(as_text=True)
        # ...and UNILAG's own student is unaffected by FUNAAB's class.
        ngozi = login(other_institution['student_email'])
        assert post_manual(ngozi, manual_body(appmod, seed['session_id'])).status_code == 403

    def test_two_universities_running_at_once_each_mark_their_own(
            self, appmod, seed, other_institution, login):
        from models import db, Attendance
        with appmod.app.app_context():
            db.session.query(Attendance).delete()
            db.session.commit()
        kemi = login(seed['student_email'])
        ngozi = login(other_institution['student_email'])
        assert post_manual(kemi, manual_body(appmod, seed['session_id'])).status_code == 200
        assert post_manual(ngozi, manual_body(appmod, other_institution['session_id'])).status_code == 200
        assert sorted(attendance_rows(appmod)) == sorted([
            (seed['student_id'], seed['session_id'], 'manual_code'),
            (other_institution['student_id'], other_institution['session_id'], 'manual_code')])

    def test_a_closed_class_refuses_even_a_correct_code(self, appmod, seed, login):
        code = current_code(appmod, seed['session_id'])
        login(seed['coordinator_email']).post(f"/session/{seed['session_id']}/end")
        response = post_manual(login(seed['student_email']),
                               manual_body(appmod, seed['session_id'], code=code))
        assert response.status_code == 409
        assert response.get_json()['outcome'] == 'session_ended'
        assert attendance_rows(appmod) == []

    def test_an_archived_course_refuses(self, appmod, seed, login):
        from models import db, Course
        with appmod.app.app_context():
            db.session.get(Course, seed['course_id']).archived = True
            db.session.commit()
        response = post_manual(login(seed['student_email']), manual_body(appmod, seed['session_id']))
        assert response.status_code == 409
        assert response.get_json()['outcome'] == 'course_archived'

    def test_the_student_is_always_the_signed_in_account(self, appmod, seed, login):
        enrol(appmod, seed['other_student_id'], seed['course_id'])
        kemi = login(seed['student_email'])
        body = manual_body(appmod, seed['session_id'], student_id=seed['other_student_id'],
                           user_id=seed['other_student_id'], matric_no='20200002')
        assert post_manual(kemi, body).status_code == 200
        assert attendance_rows(appmod) == [(seed['student_id'], seed['session_id'], 'manual_code')]
        # A page rendered for someone else on this phone is refused outright.
        response = post_manual(kemi, manual_body(appmod, seed['session_id'],
                                                 user_marker=str(seed['other_student_id'])))
        assert response.status_code == 409 and response.get_json()['outcome'] == 'wrong_user'

    # ---- the code -----------------------------------------------------------

    def test_a_wrong_code_is_refused_and_counted(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = post_manual(kemi, manual_body(
            appmod, seed['session_id'], code=wrong_code(appmod, seed['session_id'])))
        data = response.get_json()
        assert response.status_code == 400 and data['outcome'] == 'invalid_code'
        assert data['attempts_remaining'] == appmod.MANUAL_CODE_LIMITS.max_failures_per_session - 1
        assert attendance_rows(appmod) == []

    def test_an_expired_code_asks_for_the_new_one_without_counting(self, appmod, seed, login):
        gen = appmod.manual_code_generator
        old = gen.code_for_step(seed['session_id'], gen.step_at(gen.now()) - 2)
        kemi = login(seed['student_email'])
        for _ in range(appmod.MANUAL_CODE_LIMITS.max_failures_per_session + 2):
            response = post_manual(kemi, manual_body(appmod, seed['session_id'], code=old))
            assert response.status_code == 400
            assert response.get_json()['outcome'] == 'code_expired'
        assert post_manual(kemi, manual_body(appmod, seed['session_id'])).status_code == 200

    @pytest.mark.parametrize('bad', ['1234', '1234 56789', 'abcd efgh', '١٢٣٤٥٦٧٨', 12345678, ''])
    def test_malformed_codes_are_refused_without_counting(self, appmod, seed, login, bad):
        kemi = login(seed['student_email'])
        for _ in range(8):
            response = post_manual(kemi, {'code': bad, 'session_id': seed['session_id']})
            assert response.status_code == 400
            assert response.get_json()['outcome'] == 'invalid_code_format'
        assert post_manual(kemi, manual_body(appmod, seed['session_id'])).status_code == 200

    @pytest.mark.parametrize('body', [[], 'just a string', {'code': '1234 5678', 'session_id': 'x'},
                                      {'code': '1234 5678', 'session_id': True},
                                      {'code': '1234 5678', 'session_id': -4}])
    def test_malformed_requests_are_refused_cleanly(self, appmod, seed, login, body):
        response = login(seed['student_email']).post('/api/attendance/manual', json=body)
        assert response.status_code == 400
        assert response.get_json()['outcome'] in ('invalid_request', 'invalid_code_format')

    def test_the_code_typed_as_the_screen_changes_still_counts(self, appmod, seed, login,
                                                                monkeypatch):
        """Scenarios A and B: one second before rotation, and just after it."""
        gen = appmod.manual_code_generator
        sid = seed['session_id']
        boundary = (int(gen.now()) // 60 + 1) * 60
        code_before = gen.code_for_step(sid, gen.step_at(boundary) - 1)
        kemi = login(seed['student_email'])
        # Typed in the last second of its window, processed after rotation.
        monkeypatch.setattr(gen, '_clock', lambda: boundary + 1.5)
        assert post_manual(kemi, manual_body(appmod, sid, code=code_before)).status_code == 200

    def test_a_code_from_a_whole_window_ago_is_not_accepted(self, appmod, seed, login,
                                                             monkeypatch):
        gen = appmod.manual_code_generator
        sid = seed['session_id']
        boundary = (int(gen.now()) // 60 + 1) * 60
        code_before = gen.code_for_step(sid, gen.step_at(boundary) - 1)
        monkeypatch.setattr(gen, '_clock', lambda: boundary + gen.grace_seconds + 0.5)
        response = post_manual(login(seed['student_email']),
                               manual_body(appmod, sid, code=code_before))
        assert response.get_json()['outcome'] == 'code_expired'
        assert attendance_rows(appmod) == []

    # ---- guessing ------------------------------------------------------------

    def test_repeated_wrong_codes_lock_out_with_a_retry_time(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        limit = appmod.MANUAL_CODE_LIMITS.max_failures_per_session
        sid = seed['session_id']
        responses = [post_manual(kemi, manual_body(appmod, sid, code=wrong_code(appmod, sid)))
                     for _ in range(limit)]
        last = responses[-1]
        assert last.status_code == 400
        assert last.get_json()['retry_after_seconds'] == \
            appmod.MANUAL_CODE_LIMITS.session_lockout_seconds
        assert last.headers['Retry-After'] == str(appmod.MANUAL_CODE_LIMITS.session_lockout_seconds)
        # Locked: even the right code is not compared now.
        locked = post_manual(kemi, manual_body(appmod, sid))
        data = locked.get_json()
        assert locked.status_code == 429 and data['outcome'] == 'rate_limited'
        assert data['retry_after_seconds'] > 0 and locked.headers['Retry-After']
        assert attendance_rows(appmod) == []
        # The QR path does not share the lock: a student whose code entry is
        # locked can still scan.
        assert kemi.post('/mark_attendance', json=scan_body(appmod, sid)).status_code == 200

    def test_the_lockout_is_per_student_on_a_shared_network(self, appmod, seed, login):
        """Scenario K: a whole hall behind one campus NAT address."""
        enrol(appmod, seed['other_student_id'], seed['course_id'])
        sid = seed['session_id']
        kemi = login(seed['student_email'])            # same test client IP
        tayo = login(seed['other_student_email'])
        for _ in range(appmod.MANUAL_CODE_LIMITS.max_failures_per_session):
            post_manual(kemi, manual_body(appmod, sid, code=wrong_code(appmod, sid)))
        assert post_manual(kemi, manual_body(appmod, sid)).status_code == 429
        assert post_manual(tayo, manual_body(appmod, sid)).status_code == 200

    def test_a_hall_of_students_on_one_ip_is_not_rate_limited(self, appmod, seed):
        """The request limiter keys by account, so 60 phones on one IP pass."""
        from models import db, User, enrollments
        appmod.limiter.enabled = True
        appmod.limiter.reset()
        try:
            with appmod.app.app_context():
                students = [User(full_name=f'Hall {n}', email=f'hall{n}@student.funaab.edu.ng',
                                 password='!', role='student', email_verified=True,
                                 institution='funaab.edu.ng') for n in range(60)]
                db.session.add_all(students)
                db.session.flush()
                db.session.execute(enrollments.insert(), [
                    {'user_id': s.id, 'course_id': seed['course_id']} for s in students])
                db.session.commit()
                ids = [s.id for s in students]
            statuses = []
            for user_id in ids:
                client = appmod.app.test_client()
                with client.session_transaction() as session:
                    session['_user_id'] = f'{user_id}|'
                    session['_fresh'] = True
                statuses.append(post_manual(client, manual_body(appmod, seed['session_id'])).status_code)
            assert statuses == [200] * 60
        finally:
            appmod.limiter.reset()
            appmod.limiter.enabled = False

    def test_concurrent_guessing_cannot_bypass_the_limit(self, appmod, seed):
        """Scenario L: a script firing guesses in parallel from one account."""
        from models import db, User
        sid = seed['session_id']
        with appmod.app.app_context():
            student_id = db.session.get(User, seed['student_id']).id

        def guess(index):
            client = appmod.app.test_client()
            with client.session_transaction() as session:
                session['_user_id'] = f'{student_id}|'
                session['_fresh'] = True
            code = f'{(index * 7919 + 13) % 10**8:08d}'
            return post_manual(client, manual_body(appmod, sid, code=code)).get_json()['outcome']

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(guess, range(40)))
        compared = [o for o in outcomes if o in ('invalid_code', 'success', 'code_expired')]
        assert len(compared) <= appmod.MANUAL_CODE_LIMITS.max_failures_per_session, outcomes
        assert outcomes.count('rate_limited') >= 40 - appmod.MANUAL_CODE_LIMITS.max_failures_per_session

    def test_the_guard_fails_closed_when_its_store_is_down(self, appmod, seed, login,
                                                          monkeypatch):
        """Scenario E: Redis is unreachable. Codes refused; QR keeps working."""
        import redis

        class DeadRedis:
            def register_script(self, _source):
                def script(**_kwargs):
                    raise redis.ConnectionError('connection refused')
                return script

        dead_guard = appmod.RedisAttemptGuard(DeadRedis(), appmod.MANUAL_CODE_LIMITS)
        monkeypatch.setattr(appmod, 'manual_attempt_guard', lambda: dead_guard)
        kemi = login(seed['student_email'])
        response = post_manual(kemi, manual_body(appmod, seed['session_id']))
        assert response.status_code == 503
        assert response.get_json()['outcome'] == 'verification_unavailable'
        assert response.headers['Retry-After']
        assert attendance_rows(appmod) == []
        assert kemi.post('/mark_attendance', json=scan_body(appmod, seed['session_id'])).status_code == 200

    def test_production_without_a_shared_store_fails_closed(self, appmod, seed, login, monkeypatch):
        monkeypatch.setattr(appmod, 'redis_client', None)
        monkeypatch.setattr(appmod, 'IS_PRODUCTION', True)
        with pytest.raises(appmod.GuardUnavailable):
            appmod.manual_attempt_guard()

    # ---- integrity: one record, whichever way ------------------------------

    def test_a_second_manual_submission_is_a_duplicate(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        post_manual(kemi, manual_body(appmod, seed['session_id']))
        response = post_manual(kemi, manual_body(appmod, seed['session_id']))
        data = response.get_json()
        assert response.status_code == 409 and data['outcome'] == 'duplicate'
        assert data['submission_method'] == 'manual_code'
        assert len(attendance_rows(appmod)) == 1

    def test_qr_after_manual_is_a_duplicate(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        post_manual(kemi, manual_body(appmod, seed['session_id']))
        response = kemi.post('/mark_attendance', json=scan_body(appmod, seed['session_id']))
        assert response.status_code == 409 and response.get_json()['outcome'] == 'duplicate'
        assert attendance_rows(appmod) == [(seed['student_id'], seed['session_id'], 'manual_code')]

    def test_manual_after_qr_is_a_duplicate_and_spends_no_guess(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance', json=scan_body(appmod, seed['session_id']))
        # Even a wrong code: already being on the register is answered first,
        # so a student refreshing after success never locks themselves out.
        for _ in range(appmod.MANUAL_CODE_LIMITS.max_failures_per_session + 3):
            response = post_manual(kemi, manual_body(
                appmod, seed['session_id'], code=wrong_code(appmod, seed['session_id'])))
            data = response.get_json()
            assert response.status_code == 409 and data['outcome'] == 'duplicate'
            assert data['submission_method'] == 'qr'
        assert attendance_rows(appmod) == [(seed['student_id'], seed['session_id'], 'qr')]

    def test_simultaneous_duplicate_submissions_leave_one_row(self, appmod, seed):
        sid = seed['session_id']
        body = manual_body(appmod, sid)
        barrier = threading.Barrier(8)

        def submit(_):
            client = appmod.app.test_client()
            client.post('/login', data={'email': seed['student_email'], 'password': VALID_PASSWORD})
            barrier.wait()
            return post_manual(client, body).get_json()['outcome']

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(submit, range(8)))
        assert outcomes.count('success') == 1, outcomes
        # Eight copies in flight at once exceed the per-class allowance of
        # tries that may be checked simultaneously, so a few may be told to
        # retry in a moment ("too many attempts at once") rather than
        # compared. None of them may create a second row.
        assert set(outcomes) <= {'success', 'duplicate', 'rate_limited'}, outcomes
        assert len(attendance_rows(appmod)) == 1

    def test_qr_and_manual_at_the_same_moment_leave_one_row(self, appmod, seed):
        """Scenario D."""
        sid = seed['session_id']
        manual = manual_body(appmod, sid)
        scan = scan_body(appmod, sid)
        barrier = threading.Barrier(2)

        def go(kind):
            client = appmod.app.test_client()
            client.post('/login', data={'email': seed['student_email'], 'password': VALID_PASSWORD})
            barrier.wait()
            if kind == 'qr':
                return client.post('/mark_attendance', json=scan).get_json()['outcome']
            return post_manual(client, manual).get_json()['outcome']

        for attempt in range(3):
            from models import db, Attendance
            with appmod.app.app_context():
                db.session.query(Attendance).delete()
                db.session.commit()
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = sorted(pool.map(go, ['qr', 'manual']))
            assert outcomes == ['duplicate', 'success'], outcomes
            assert len(attendance_rows(appmod)) == 1

    def test_a_class_closed_between_the_check_and_the_insert_records_nothing(
            self, appmod, seed, login, monkeypatch):
        """
        Scenario C, made deterministic: the early "is it open?" read sees an
        open class, the lecturer's End Class commits, and only then does the
        insert run. The insert's own predicate is what refuses it.
        """
        from models import db, ClassSession
        sid = seed['session_id']
        original = appmod._attendance_target

        def stale_then_close(*args, **kwargs):
            target = original(*args, **kwargs)
            with appmod.app.app_context():
                row = db.session.get(ClassSession, sid)
                row.active = False
                row.ended_at = appmod._utcnow()
                db.session.commit()
            return target

        monkeypatch.setattr(appmod, '_attendance_target', stale_then_close)
        kemi = login(seed['student_email'])
        manual = post_manual(kemi, manual_body(appmod, sid))
        assert manual.status_code == 409 and manual.get_json()['outcome'] == 'session_ended'
        scan = kemi.post('/mark_attendance', json=scan_body(appmod, sid))
        assert scan.status_code == 409 and scan.get_json()['outcome'] == 'session_ended'
        assert attendance_rows(appmod) == []

    # ---- location --------------------------------------------------------------

    def test_inside_the_classroom_is_accepted(self, appmod, seed, login):
        pin(appmod, seed['session_id'])
        response = post_manual(login(seed['student_email']),
                               manual_body(appmod, seed['session_id'], **at_metres(40)))
        assert response.status_code == 200, response.get_json()

    @pytest.mark.parametrize('location, outcome', [
        ({}, 'missing_location'),
        ({'lat': 'here', 'lon': 3.44}, 'missing_location'),
        (at_metres(0, lat=95.0), 'invalid_location'),
        (at_metres(0, lon=-200.0), 'invalid_location'),
        (at_metres(0, location_age_ms=None), 'missing_location_age'),
        (at_metres(0, location_age_ms=10 ** 6), 'stale_location'),
        (at_metres(0, accuracy_m=None), 'missing_location_accuracy'),
        (at_metres(0, accuracy_m=5000), 'imprecise_location'),
        (at_metres(400), 'outside_geofence'),
    ])
    def test_the_same_geofence_as_scanning_refuses(self, appmod, seed, login, location, outcome):
        pin(appmod, seed['session_id'])
        body = manual_body(appmod, seed['session_id'])
        body.update({key: value for key, value in location.items() if value is not None})
        if location.get('location_age_ms', 1) is None:
            body.pop('location_age_ms', None)
        if location.get('accuracy_m', 1) is None:
            body.pop('accuracy_m', None)
        response = post_manual(login(seed['student_email']), body)
        assert response.status_code == 422, response.get_json()
        assert response.get_json()['outcome'] == outcome
        assert attendance_rows(appmod) == []

    @pytest.mark.parametrize('endpoint', ['manual', 'qr'])
    @pytest.mark.parametrize('field', ['accuracy_m', 'location_age_ms'])
    def test_not_a_number_is_not_a_reading(self, appmod, seed, login, endpoint, field):
        """NaN compared false against both bounds and used to pass for both methods."""
        pin(appmod, seed['session_id'])
        location = at_metres(10)
        payload = (manual_body(appmod, seed['session_id'], **location) if endpoint == 'manual'
                   else scan_body(appmod, seed['session_id'], **location))
        raw = json.dumps({**payload, field: '__NAN__'}).replace('"__NAN__"', 'NaN')
        url = '/api/attendance/manual' if endpoint == 'manual' else '/mark_attendance'
        response = login(seed['student_email']).post(url, data=raw,
                                                    content_type='application/json')
        assert response.status_code == 422, response.get_json()
        assert attendance_rows(appmod) == []

    def test_the_client_cannot_switch_the_geofence_off(self, appmod, seed, login):
        pin(appmod, seed['session_id'])
        body = manual_body(appmod, seed['session_id'], **at_metres(900),
                           geofence=False, skip_geofence=True, distance_m=0,
                           geofence_required=False, radius_m=5000)
        response = post_manual(login(seed['student_email']), body)
        assert response.get_json()['outcome'] == 'outside_geofence'

    def test_no_classroom_set_is_refused_when_the_geofence_is_required(
            self, appmod, seed, login, monkeypatch):
        monkeypatch.setattr(appmod, 'GEOFENCE_REQUIRED', True)
        response = post_manual(login(seed['student_email']),
                               manual_body(appmod, seed['session_id'], **at_metres(0)))
        assert response.status_code == 422
        assert response.get_json()['outcome'] == 'no_class_location'
        assert 'lecturer' in response.get_json()['message']

    def test_a_correct_code_refused_on_location_costs_no_guess(self, appmod, seed, login):
        pin(appmod, seed['session_id'])
        kemi = login(seed['student_email'])
        for _ in range(appmod.MANUAL_CODE_LIMITS.max_failures_per_session + 3):
            response = post_manual(kemi, manual_body(appmod, seed['session_id'], **at_metres(900)))
            assert response.get_json()['outcome'] == 'outside_geofence'
        assert post_manual(kemi, manual_body(appmod, seed['session_id'],
                                             **at_metres(5))).status_code == 200

    # ---- transport, secrets and logs ------------------------------------------

    def test_csrf_is_required_and_recoverable(self, appmod, seed, login):
        appmod.app.config['WTF_CSRF_ENABLED'] = True
        try:
            kemi = appmod.app.test_client()
            page = kemi.get('/login').get_data(as_text=True)
            token = page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
            kemi.post('/login', data={'email': seed['student_email'],
                                      'password': VALID_PASSWORD, 'csrf_token': token})
            refused = post_manual(kemi, manual_body(appmod, seed['session_id']))
            assert refused.status_code == 400
            data = refused.get_json()
            assert data['outcome'] == 'csrf_expired' and data['csrf_token']
            assert attendance_rows(appmod) == []
            accepted = kemi.post('/api/attendance/manual',
                                 json=manual_body(appmod, seed['session_id']),
                                 headers={'X-CSRFToken': data['csrf_token']})
            assert accepted.status_code == 200, accepted.get_json()
        finally:
            appmod.app.config['WTF_CSRF_ENABLED'] = False

    def test_no_response_or_log_line_carries_a_code_or_the_secret(
            self, appmod, seed, login, caplog):
        import logging
        caplog.set_level(logging.DEBUG)
        sid = seed['session_id']
        secret = appmod.app.config['SECRET_KEY']
        live = current_code(appmod, sid)
        wrong = wrong_code(appmod, sid)
        kemi = login(seed['student_email'])
        bodies = [post_manual(kemi, manual_body(appmod, sid, code=wrong)).get_data(as_text=True),
                  post_manual(kemi, manual_body(appmod, sid)).get_data(as_text=True),
                  post_manual(kemi, manual_body(appmod, sid)).get_data(as_text=True),
                  kemi.get('/api/attendance/manual/sessions').get_data(as_text=True),
                  kemi.get('/student_dashboard').get_data(as_text=True)]
        for body in bodies:
            assert live not in body and wrong not in body and secret not in body
        logs = caplog.text
        assert live not in logs and wrong not in logs and secret not in logs
        assert 'manual_code_performance' in logs

    def test_static_assets_carry_no_secret_material(self, appmod):
        import pathlib
        static = pathlib.Path(appmod.__file__).parent / 'static'
        secret = appmod.app.config['SECRET_KEY']
        for name in ('manual-code.js', 'attendance-common.js', 'scanner.js'):
            text = (static / name).read_text()
            assert secret not in text
            assert 'SECRET_KEY' not in text and 'MANUAL_CODE_SECRET' not in text
            # The algorithm's secret half never reaches the browser.
            assert 'hmac' not in text.lower() and 'derive_key' not in text


# ============================================================================
# The record: method, register, exports, CampOS
# ============================================================================

class TestRecordAndReporting:

    def test_campos_receives_a_manual_record_exactly_like_a_scan(self, appmod, seed, login,
                                                                monkeypatch):
        calls = []

        class Recorder:
            def submit(self, function, *args, **kwargs):
                calls.append(args[0])
                return object()

        monkeypatch.setenv('CAMPOS_API_KEY', 'test-key')
        monkeypatch.setattr(appmod, 'campos_executor', Recorder())
        assert post_manual(login(seed['student_email']),
                           manual_body(appmod, seed['session_id'])).status_code == 200
        from models import Attendance
        with appmod.app.app_context():
            row = Attendance.query.one()
            assert row.campos_state == 'pending'
            assert row.campos_next_attempt_at is not None
        assert len(calls) == 1
        payload = appmod._campos_payload(calls[0])
        assert payload['courseCode'] == 'CSC201'
        assert payload['externalId'] == f'scanmark-attendance:{row.id}'
        assert payload['status'] == 'present'

    def test_the_lecturer_sees_how_each_student_marked_attendance(self, appmod, seed, login):
        enrol(appmod, seed['other_student_id'], seed['course_id'])
        sid = seed['session_id']
        post_manual(login(seed['student_email']), manual_body(appmod, sid))
        login(seed['other_student_email']).post('/mark_attendance', json=scan_body(appmod, sid))
        ada = login(seed['coordinator_email'])

        sheet = ada.get(f'/session/{sid}/attendance').get_data(as_text=True)
        assert 'Manual code' in sheet and 'QR scan' in sheet
        overview = ada.get(f"/course/{seed['course_id']}/attendance").get_data(as_text=True)
        assert 'Manual code' in overview

        feed = ada.get(f'/api/session/{sid}/attendees').get_json()
        assert sorted(a['method'] for a in feed['new_attendees']) == ['manual_code', 'qr']

        csv_text = ada.get(f"/course/{seed['course_id']}/download_csv?session_id={sid}").get_data(as_text=True)
        lines = csv_text.splitlines()
        assert lines[0] == 'Matric Number,Full Name,Level,Status,Time Scanned,Device ID,Method'
        assert any('"Manual code"' in line and '"20200001"' in line for line in lines)
        assert any('"QR scan"' in line and '"20200002"' in line for line in lines)
        # The semester register keeps its shape: Present is Present.
        register = ada.get(f"/course/{seed['course_id']}/download_csv").get_data(as_text=True)
        assert 'Manual code' not in register and '"Present"' in register
        # The code itself is never part of a record.
        assert current_code(appmod, sid) not in csv_text + sheet + json.dumps(feed)

    def test_a_manual_record_counts_like_any_other(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        before = kemi.get('/student_dashboard').get_data(as_text=True)
        assert 'data-attended="0"' in before
        post_manual(kemi, manual_body(appmod, seed['session_id']))
        after = kemi.get('/student_dashboard').get_data(as_text=True)
        assert 'data-attended="1"' in after
        assert '100% · On Track' in after

    def test_reloading_the_dashboard_after_success_is_harmless(self, appmod, seed, login):
        """Scenario H."""
        kemi = login(seed['student_email'])
        assert post_manual(kemi, manual_body(appmod, seed['session_id'])).status_code == 200
        for _ in range(3):
            assert kemi.get('/student_dashboard').status_code == 200
        entry = kemi.get('/api/attendance/manual/sessions').get_json()['sessions'][0]
        assert entry['already_marked'] is True
        assert len(attendance_rows(appmod)) == 1

    def test_existing_qr_scans_default_to_qr(self, appmod, seed, login):
        login(seed['student_email']).post('/mark_attendance', json=scan_body(appmod, seed['session_id']))
        assert attendance_rows(appmod) == [(seed['student_id'], seed['session_id'], 'qr')]


# ============================================================================
# End Class
# ============================================================================

class TestEndClass:

    def test_end_class_that_cannot_get_the_lock_asks_to_try_again(self, appmod, seed, login,
                                                                  monkeypatch):
        from sqlalchemy.exc import OperationalError

        def busy(_row, reason='ended'):
            raise OperationalError('SELECT', {}, Exception('lock timeout'))

        monkeypatch.setattr(appmod, 'end_class_session', busy)
        ada = login(seed['coordinator_email'])
        response = ada.post(f"/session/{seed['session_id']}/end")
        assert response.status_code == 302
        assert f"/session/{seed['session_id']}/qr" in response.headers['Location']
        from models import db, ClassSession
        with appmod.app.app_context():
            assert db.session.get(ClassSession, seed['session_id']).is_open

    def test_ending_the_class_stops_the_code_at_once(self, appmod, seed, login):
        code = current_code(appmod, seed['session_id'])
        login(seed['coordinator_email']).post(f"/session/{seed['session_id']}/end")
        kemi = login(seed['student_email'])
        assert post_manual(kemi, manual_body(appmod, seed['session_id'], code=code)) \
            .get_json()['outcome'] == 'session_ended'


def _postgres(appmod):
    with appmod.app.app_context():
        return appmod.db.engine.dialect.name == 'postgresql'


class TestTheEndClassRaceOnPostgres:
    """
    The rule: an attendance is accepted iff it commits before End Class does.
    Only PostgreSQL has the row locks this relies on (SQLite serialises every
    writer, so the rule holds there trivially); CI's Postgres job runs these.
    """

    @pytest.fixture(autouse=True)
    def _postgres_only(self, appmod):
        if not _postgres(appmod):
            pytest.skip('PostgreSQL row-lock semantics')

    def test_an_insert_waiting_on_end_class_records_nothing(self, appmod, seed):
        from sqlalchemy import text
        sid = seed['session_id']
        with appmod.app.app_context():
            engine = appmod.db.engine
            closer = engine.connect()
            closer_tx = closer.begin()
            closer.execute(text('SELECT id FROM class_session WHERE id = :id FOR UPDATE'), {'id': sid})
            closer.execute(text('UPDATE class_session SET active = false, ended_at = now() '
                                'WHERE id = :id'), {'id': sid})
        result = {}

        def insert():
            with appmod.app.app_context():
                result['id'] = appmod._insert_attendance_once(
                    seed['student_id'], seed['course_id'], sid, 'race', appmod._utcnow(),
                    submission_method='manual_code')

        worker = threading.Thread(target=insert)
        worker.start()
        worker.join(0.5)
        assert worker.is_alive(), 'the insert should wait for End Class'
        closer_tx.commit()
        closer.close()
        worker.join(5)
        assert result['id'] is None
        assert attendance_rows(appmod) == []

    def test_end_class_waits_for_an_insert_already_in_flight(self, appmod, seed):
        from sqlalchemy import text
        sid = seed['session_id']
        with appmod.app.app_context():
            engine = appmod.db.engine
            inserter = engine.connect()
            insert_tx = inserter.begin()
            inserter.execute(text(
                "INSERT INTO attendance (student_id, course_id, session_id, device_id, "
                "timestamp, campos_state, campos_attempts, submission_method) "
                "SELECT :student, :course, id, 'race', now(), 'skipped', 0, 'manual_code' "
                "FROM class_session WHERE id = :sid AND active AND ended_at IS NULL FOR KEY SHARE"),
                {'student': seed['student_id'], 'course': seed['course_id'], 'sid': sid})
        ended = {}

        def end():
            with appmod.app.app_context():
                from models import db, ClassSession
                with appmod.app.test_request_context():
                    row = db.session.get(ClassSession, sid)
                    started = time.perf_counter()
                    appmod.end_class_session(row)
                    ended['waited'] = time.perf_counter() - started

        worker = threading.Thread(target=end)
        worker.start()
        worker.join(0.5)
        assert worker.is_alive(), 'End Class should wait for the in-flight insert'
        insert_tx.commit()
        inserter.close()
        worker.join(5)
        assert ended['waited'] >= 0.4
        # The insert committed first, so it is on the register; the class is
        # closed after it, and nothing can follow.
        assert attendance_rows(appmod) == [(seed['student_id'], sid, 'manual_code')]
        with appmod.app.app_context():
            assert appmod._insert_attendance_once(
                seed['other_student_id'], seed['course_id'], sid, 'late',
                appmod._utcnow()) is None

    def test_many_submissions_racing_end_class_obey_the_rule(self, appmod, seed):
        """Every row that exists committed before the close; none after."""
        from models import db, User, enrollments, ClassSession, Attendance
        sid = seed['session_id']
        with appmod.app.app_context():
            students = [User(full_name=f'Racer {n}', email=f'racer{n}@student.funaab.edu.ng',
                             password='!', role='student', email_verified=True,
                             institution='funaab.edu.ng') for n in range(60)]
            db.session.add_all(students)
            db.session.flush()
            db.session.execute(enrollments.insert(), [
                {'user_id': s.id, 'course_id': seed['course_id']} for s in students])
            db.session.commit()
            ids = [s.id for s in students]
        barrier = threading.Barrier(61)
        results = {}

        def submit(student_id):
            with appmod.app.app_context():
                barrier.wait()
                time.sleep(0.002 * (student_id % 20))
                results[student_id] = appmod._insert_attendance_once(
                    student_id, seed['course_id'], sid, 'race', appmod._utcnow(),
                    submission_method='manual_code')
                appmod.db.session.remove()

        def close():
            with appmod.app.test_request_context():
                barrier.wait()
                time.sleep(0.015)
                appmod.end_class_session(db.session.get(ClassSession, sid))
                db.session.remove()

        threads = [threading.Thread(target=submit, args=(i,)) for i in ids]
        threads.append(threading.Thread(target=close))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        with appmod.app.app_context():
            ended_at = db.session.get(ClassSession, sid).ended_at
            rows = Attendance.query.filter_by(session_id=sid).all()
            inserted = {r.student_id for r in rows}
        accepted = {student for student, record in results.items() if record is not None}
        assert accepted == inserted
        assert ended_at is not None
        assert all(row.timestamp <= ended_at for row in rows)
        # A submission after the close is refused.
        with appmod.app.app_context():
            assert appmod._insert_attendance_once(
                seed['student_id'], seed['course_id'], sid, 'after', appmod._utcnow()) is None


# ============================================================================
# The schema upgrade
# ============================================================================

class TestSubmissionMethodMigration:
    """
    A database from before this release has no submission_method column.
    Booting must add it without touching a row, call every existing record a
    QR scan (which is what they all were), and be a no-op the second time.
    """

    def _boot(self, database_url):
        import os
        import subprocess
        import sys
        env = {key: value for key, value in os.environ.items()
               if key not in ('REDIS_URL', 'SCANMARK_TEST_REDIS_URL')}
        env.update(SECRET_KEY='migration-test', DATABASE_URL=database_url,
                   FLASK_ENV='testing', SCANMARK_DISABLE_SCHEDULER='1')
        result = subprocess.run([sys.executable, '-c', 'import app'], cwd=os.path.dirname(__file__),
                                env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
        return result.stdout

    def test_an_existing_database_is_upgraded_in_place(self, tmp_path):
        import sqlite3
        path = tmp_path / 'legacy.db'
        url = f'sqlite:///{path}'
        self._boot(url)                         # today's schema...
        with sqlite3.connect(path) as conn:     # ...rolled back to last release's
            conn.execute('ALTER TABLE attendance DROP COLUMN submission_method')
            conn.execute("INSERT INTO user (id, full_name, email, password, role, institution) "
                         "VALUES (1, 'Coord', 'c@staff.x.edu', '!', 'course coordinator', ''),"
                         "       (2, 'Stu', 's@x.edu', '!', 'student', '')")
            conn.execute("INSERT INTO course (id, code, title, academic_year, semester, section, "
                         "archived, institution, coordinator_id) "
                         "VALUES (1, 'CSC1', 'T', '2025/2026', 'First', '', 0, '', 1)")
            conn.execute("INSERT INTO class_session (id, course_id, title, active, kind, sequence) "
                         "VALUES (1, 1, 'Week 1', 0, 'Lecture', 1)")
            conn.execute("INSERT INTO attendance (id, student_id, course_id, session_id, timestamp, "
                         "device_id, campos_state, campos_attempts) "
                         "VALUES (7, 2, 1, 1, '2025-10-01 09:00:00', 'old-phone', 'sent', 1)")
            columns = {row[1] for row in conn.execute('PRAGMA table_info(attendance)')}
            assert 'submission_method' not in columns

        output = self._boot(url)
        assert '[MIGRATION] Added attendance.submission_method' in output
        with sqlite3.connect(path) as conn:
            rows = conn.execute('SELECT id, student_id, session_id, device_id, campos_state, '
                                'submission_method FROM attendance').fetchall()
            assert rows == [(7, 2, 1, 'old-phone', 'sent', 'qr')]
            column = [row for row in conn.execute('PRAGMA table_info(attendance)')
                      if row[1] == 'submission_method'][0]
            assert column[3] == 1                       # NOT NULL
            # The uniqueness rule is untouched.
            indexes = {row[1]: row[2] for row in conn.execute('PRAGMA index_list(attendance)')}
            assert indexes.get('uq_attendance_student_session') == 1

        again = self._boot(url)
        assert 'submission_method' not in again
        with sqlite3.connect(path) as conn:
            assert conn.execute('SELECT count(*) FROM attendance').fetchone()[0] == 1
