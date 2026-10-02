import os
import threading
import time

import pytest
import redis
from sqlalchemy import event

import app as scanmark
from models import Attendance, ClassSession, Course, User, db
from performance import BoundedExecutor, RuntimeMetrics


class _RecordingExecutor:
    def __init__(self):
        self.calls = []

    def submit(self, function, *args, **kwargs):
        self.calls.append((function, args, kwargs))
        return object()


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch):
    scanmark.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
    )
    monkeypatch.setattr(scanmark, 'redis_client', None)
    monkeypatch.setattr(scanmark, 'campos_executor', _RecordingExecutor())
    monkeypatch.setattr(scanmark, 'account_email_executor', _RecordingExecutor())
    # Explicit, because inheriting it was a bug waiting to be noticed. This
    # file used to pass only when it ran AFTER test_app.py, whose `appmod`
    # fixture assigns scanmark.GEOFENCE_REQUIRED = False on the module and
    # never puts it back — so running test_performance.py on its own refused
    # every unpinned scan with 422 and the query-budget tests failed. Tests
    # that are about the geofence pin a location of their own.
    monkeypatch.setattr(scanmark, 'GEOFENCE_REQUIRED', False)
    # Likewise explicit. Flask-Limiter keeps its counters in module-level
    # storage keyed by user id, and only test_app.py's `flask_app` fixture
    # sets limiter.enabled = False — so running this file on its own let one
    # test's scans exhaust the 10/minute budget of the next one's, and the
    # failure surfaced as an unrelated 429.
    monkeypatch.setattr(scanmark.limiter, 'enabled', False)
    scanmark._local_locations.clear()
    with scanmark.app.app_context():
        # Start from an empty schema as well as ending on one. Cleaning up
        # only on the way out meant this file inherited whatever rows the
        # previously-run test file happened to leave behind, so the very
        # first test here could see somebody else's attendance row.
        db.session.remove()
        db.drop_all()
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


def _seed(session_count=1):
    coordinator = User(
        full_name='Lecturer One', email='lecturer@example.edu', password='x',
        role='course coordinator', department='CS', faculty='Science',
    )
    student = User(
        full_name='Student One', email='student@example.edu', password='x',
        role='student', matric_no='ST001', level='300',
    )
    db.session.add_all([coordinator, student])
    db.session.flush()
    course = Course(
        code='CSC301', title='Systems', coordinator_id=coordinator.id,
        department='CS', faculty='Science',
    )
    db.session.add(course)
    db.session.flush()
    student.enrolled_courses.append(course)
    sessions = []
    for number in range(session_count):
        row = ClassSession(course_id=course.id, title=f'Class {number + 1}')
        db.session.add(row)
        sessions.append(row)
    db.session.commit()
    return coordinator, student, course, sessions


def _login(client, user):
    with client.session_transaction() as browser_session:
        browser_session['_user_id'] = str(user.id)
        browser_session['_fresh'] = True


def _point_north(latitude, longitude, metres):
    return latitude + metres / 111_194.9266, longitude


@pytest.mark.parametrize('distance_m,expected_status', [
    (78, 200),
    (99, 200),
    (101, 422),
])
def test_authoritative_geofence_boundary(distance_m, expected_status):
    coordinator, student, course, sessions = _seed()
    origin = (7.227, 3.438)
    scanmark.set_class_location(sessions[0].id, *origin)
    latitude, longitude = _point_north(*origin, distance_m)
    client = scanmark.app.test_client()
    _login(client, student)

    response = client.post('/mark_attendance', json={
        'qr_data': scanmark.generate_signed_qr(sessions[0].id),
        'lat': latitude,
        'lon': longitude,
        'location_age_ms': 100,
        'accuracy_m': 5,
        'captured_at': time.time() * 1000,
        'user_marker': str(student.id),
    })

    assert response.status_code == expected_status
    assert response.get_json()['status'] == ('success' if expected_status == 200 else 'error')
    assert Attendance.query.count() == (1 if expected_status == 200 else 0)


def test_atomic_duplicate_guard_keeps_exactly_one_row():
    _coordinator, student, course, sessions = _seed()
    inserted = [
        scanmark._insert_attendance_once(
            student.id, course.id, sessions[0].id, 'test', scanmark._utcnow()
        )
        for _ in range(20)
    ]
    assert sum(record_id is not None for record_id in inserted) == 1
    assert Attendance.query.filter_by(
        student_id=student.id, session_id=sessions[0].id
    ).count() == 1


def test_repeated_starts_resume_the_one_open_session():
    """A refresh of the projector page must land back on the same meeting."""
    _coordinator, _student, course, _sessions = _seed(session_count=0)
    ids = [scanmark.resume_or_start_session(course).id for _ in range(20)]
    assert len(set(ids)) == 1
    assert ClassSession.query.filter_by(course_id=course.id).count() == 1


def test_qr_verifier_round_trip_tamper_expiry_and_future(monkeypatch):
    monkeypatch.setattr(scanmark.time, 'time', lambda: 10_000)
    token = scanmark.generate_signed_qr(42)
    for _ in range(1000):
        assert scanmark.verify_signed_qr(token) == (42, 10_000)
    with pytest.raises(ValueError, match='signature'):
        scanmark.verify_signed_qr(token[:-1] + ('0' if token[-1] != '0' else '1'))
    monkeypatch.setattr(scanmark.time, 'time', lambda: 10_046)
    with pytest.raises(ValueError, match='expired'):
        scanmark.verify_signed_qr(token)
    monkeypatch.setattr(scanmark.time, 'time', lambda: 9_990)
    with pytest.raises(ValueError, match='timestamp'):
        scanmark.verify_signed_qr(token)


def test_mark_attendance_query_budget():
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    statements = []

    def count_query(*_args):
        statements.append(1)

    event.listen(db.engine, 'before_cursor_execute', count_query)
    try:
        response = client.post('/mark_attendance', json={
            'qr_data': scanmark.generate_signed_qr(sessions[0].id),
            'captured_at': time.time() * 1000,
            'user_marker': str(student.id),
        })
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_query)
    assert response.status_code == 200
    # Three: load the signed-in user, one join for session+course+room+
    # enrolment, and the insert. The budget was 5 while the enrolment check
    # was its own statement and the post-commit expiry forced a second full
    # `SELECT "user".*` to re-read matric_no/email for the CampOS hand-off.
    assert len(statements) <= 3, (
        f'{len(statements)} statements per scan; the hot path budget is 3')


def test_enrolment_refusal_is_still_told_apart_from_a_missing_session():
    """Folding the enrolment check into the join must not blur 404 and 403."""
    _coordinator, _student, _course, sessions = _seed()
    outsider = User(full_name='Not Enrolled', email='outsider@example.edu',
                    password='x', role='student', matric_no='ST999',
                    level='300')
    db.session.add(outsider)
    db.session.commit()

    client = scanmark.app.test_client()
    _login(client, outsider)
    body = {
        'qr_data': scanmark.generate_signed_qr(sessions[0].id),
        'captured_at': time.time() * 1000,
        'user_marker': str(outsider.id),
    }
    # A real session the student is not on: the outer join returns a row
    # whose enrolment column is NULL.
    denied = client.post('/mark_attendance', json=body)
    assert denied.status_code == 403
    assert denied.get_json()['outcome'] == 'not_enrolled'

    # A session that does not exist: the outer join returns NO row. The two
    # must stay distinguishable, or probing session ids would be free.
    absent = client.post('/mark_attendance', json={
        **body,
        'qr_data': scanmark.generate_signed_qr(sessions[0].id + 10_000)})
    assert absent.status_code == 404
    assert absent.get_json()['outcome'] == 'missing_session'
    assert Attendance.query.count() == 0


def test_enrolled_student_still_scans_through_the_merged_join():
    """The other half of the join: an enrolled student is still admitted.

    Deliberately its own test rather than a third request in the one above.
    Flask-Login caches the resolved user on `g`, and `g` belongs to the
    application context — which the fixture pushes once for the whole test —
    so a second test client in the same test is served the FIRST client's
    user and the scan is refused as `wrong_user_queue`.
    """
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    response = client.post('/mark_attendance', json={
        'qr_data': scanmark.generate_signed_qr(sessions[0].id),
        'captured_at': time.time() * 1000,
        'user_marker': str(student.id),
    })
    assert response.status_code == 200, response.get_json()
    assert Attendance.query.count() == 1


def test_successful_scan_reads_no_user_row_after_the_commit():
    """
    The CampOS hand-off must not trigger a post-commit refresh SELECT.

    SQLAlchemy expires every instance on commit, so reading
    `current_user.matric_no` after the attendance insert silently issued a
    second full `SELECT "user".*`. Asserting on ORDER rather than on a count
    is what makes this independent of the test harness: the fixture's session
    already holds the User in its identity map, so a count would be zero here
    and non-zero in production for the same code.
    """
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    statements = []

    def record(_conn, _cursor, statement, *_rest):
        statements.append(' '.join(statement.split()))

    event.listen(db.engine, 'before_cursor_execute', record)
    try:
        response = client.post('/mark_attendance', json={
            'qr_data': scanmark.generate_signed_qr(sessions[0].id),
            'captured_at': time.time() * 1000,
            'user_marker': str(student.id),
        })
    finally:
        event.remove(db.engine, 'before_cursor_execute', record)

    assert response.status_code == 200
    insert_positions = [index for index, statement in enumerate(statements)
                        if statement.upper().startswith('INSERT INTO ATTENDANCE')]
    assert insert_positions, statements
    after_insert = statements[insert_positions[0] + 1:]
    user_reads = [statement for statement in after_insert
                  if statement.upper().startswith('SELECT')
                  and ' FROM "USER"' in statement.upper()]
    assert not user_reads, f'user row re-read after commit: {user_reads}'


def test_incremental_attendee_feed_is_bounded_and_cursor_based():
    coordinator, _student, course, sessions = _seed()
    students = []
    for number in range(300):
        students.append(User(
            full_name=f'Student {number:03}', email=f's{number}@example.edu',
            password='x', role='student', matric_no=f'M{number:04}', level='300',
        ))
    db.session.add_all(students)
    db.session.flush()
    db.session.add_all([
        Attendance(student_id=student.id, course_id=course.id, session_id=sessions[0].id)
        for student in students
    ])
    db.session.commit()
    cursor = Attendance.query.order_by(Attendance.id.asc()).offset(249).first().id
    client = scanmark.app.test_client()
    _login(client, coordinator)
    statements = []

    def count_query(*_args):
        statements.append(1)

    event.listen(db.engine, 'before_cursor_execute', count_query)
    try:
        response = client.get(f'/api/session/{sessions[0].id}/attendees?after={cursor}&limit=100')
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_query)
    payload = response.get_json()
    assert response.status_code == 200
    assert set(payload) == {
        'status', 'present', 'enrolled', 'new_attendees', 'last_id', 'has_more'
    }
    assert payload['present'] == 300
    assert len(payload['new_attendees']) == 50
    assert all(item['id'] > cursor for item in payload['new_attendees'])
    assert len(response.data) < 15_000
    assert len(statements) <= 7


def test_student_dashboard_query_budget_is_constant():
    coordinator, student, _course, _sessions = _seed()
    for number in range(20):
        course = Course(
            code=f'C{number:03}', title=f'Course {number}',
            coordinator_id=coordinator.id,
        )
        db.session.add(course)
        student.enrolled_courses.append(course)
    db.session.commit()
    client = scanmark.app.test_client()
    _login(client, student)
    statements = []

    def count_query(*_args):
        statements.append(1)

    event.listen(db.engine, 'before_cursor_execute', count_query)
    try:
        response = client.get('/student_dashboard')
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_query)
    assert response.status_code == 200
    assert len(statements) <= 6


def test_livez_bypasses_flask_and_database():
    """
    The liveness probe answers from the WSGI layer, before Flask opens a
    session or an extension — that is what lets a cold start overlap with a
    CampOS SSO round trip.
    """
    statements = []

    def count_query(*_args):
        statements.append(1)

    event.listen(db.engine, 'before_cursor_execute', count_query)
    try:
        response = scanmark.app.test_client().get('/livez')
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_query)
    assert response.status_code == 204
    assert response.data == b''
    assert statements == []


def test_healthz_actually_checks_the_database():
    """
    Readiness has to touch what a real request touches. Answering 204 from the
    WSGI layer without reaching anything is how a deployment stays 'healthy'
    while every request 500s on a dead database.
    """
    statements = []

    def count_query(*_args):
        statements.append(1)

    # The result is cached for a few seconds; clear it so this probe is real.
    scanmark._readiness_cache['report'] = None
    event.listen(db.engine, 'before_cursor_execute', count_query)
    try:
        response = scanmark.app.test_client().get('/healthz')
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_query)
    assert response.status_code == 204
    assert statements, 'readiness answered without querying the database'


def test_scanner_page_uses_optimized_self_hosted_bundle():
    _coordinator, student, _course, _sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    response = client.get('/scan_page')
    html = response.get_data(as_text=True)
    assert '/static/scanner.js' in html
    assert '/static/vendor/jsQR.min.js' in html
    assert 'ideal: 1920' not in html
    assert 'setInterval(triggerFocus, 2000)' not in html


def test_csv_export_is_streamed():
    coordinator, student, course, sessions = _seed()
    db.session.add(Attendance(
        student_id=student.id, course_id=course.id, session_id=sessions[0].id
    ))
    db.session.commit()
    client = scanmark.app.test_client()
    _login(client, coordinator)
    response = client.get(
        f'/course/{course.id}/download_csv?session_id={sessions[0].id}',
        buffered=False,
    )
    assert response.status_code == 200
    assert response.is_streamed
    assert b'Student One' in b''.join(response.response)


def test_all_jinja_templates_compile():
    for template_name in scanmark.app.jinja_env.list_templates():
        scanmark.app.jinja_env.get_template(template_name)


def test_bounded_executor_rejects_excess_work():
    metrics = RuntimeMetrics()
    executor = BoundedExecutor(name='test_queue', max_workers=1, max_queue=0, metrics=metrics)
    release = scanmark.threading.Event()
    first = executor.submit(release.wait, 2)
    try:
        assert first is not None
        assert executor.submit(lambda: None) is None
        assert metrics.snapshot()['counters']['test_queue.rejected'] == 1
    finally:
        release.set()
        executor.shutdown()


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='needs os.fork')
def test_bounded_executor_still_runs_work_in_a_forked_worker():
    """
    gunicorn's preload_app imports the app in the master and then forks the
    workers, and that import already runs a job on the account-email pool (the
    Brevo sender check). Threads do not survive fork, but the pool's note that
    one was idle did, so in every worker the first password-reset or signup
    email waited in the queue for a thread that did not exist — until a second
    email came along and started one.
    """
    executor = BoundedExecutor(name='test_fork', max_workers=2, max_queue=4,
                               metrics=RuntimeMetrics())
    executor.submit(lambda: None).result(timeout=5)   # the boot-time job

    pid = os.fork()
    if pid == 0:   # the worker: must leave via os._exit, never back into pytest
        try:
            executor.submit(lambda: None).result(timeout=3)
            os._exit(0)
        except BaseException:
            os._exit(1)

    try:
        deadline = time.monotonic() + 15
        while (finished := os.waitpid(pid, os.WNOHANG))[0] == 0:
            assert time.monotonic() < deadline, 'forked worker hung'
            time.sleep(0.05)
        assert os.waitstatus_to_exitcode(finished[1]) == 0, \
            'the first job submitted after fork never ran'
    finally:
        if not finished[0]:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        executor.shutdown()


# ---------------------------------------------------------------------------
# The CampOS outbox
# ---------------------------------------------------------------------------

def _scan_once(client, student, session_row):
    return client.post('/mark_attendance', json={
        'qr_data': scanmark.generate_signed_qr(session_row.id),
        'captured_at': time.time() * 1000,
        'user_marker': str(student.id),
    })


def test_scan_records_campos_intent_in_the_same_insert(monkeypatch):
    """Durability must cost the request nothing: no second statement."""
    monkeypatch.setenv('CAMPOS_API_KEY', 'k')
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    statements = []

    def record(_conn, _cursor, statement, *_rest):
        statements.append(' '.join(statement.split()))

    event.listen(db.engine, 'before_cursor_execute', record)
    try:
        assert _scan_once(client, student, sessions[0]).status_code == 200
    finally:
        event.remove(db.engine, 'before_cursor_execute', record)

    # The outbox intent is part of the attendance INSERT, not a second write.
    inserts = [statement for statement in statements
               if statement.upper().startswith('INSERT INTO ATTENDANCE')]
    assert len(inserts) == 1
    assert 'campos_state' in inserts[0]
    updates = [statement for statement in statements
               if statement.upper().startswith('UPDATE ATTENDANCE')]
    assert not updates, f'the request wrote the outbox separately: {updates}'

    row = Attendance.query.one()
    assert row.campos_state == 'pending'
    assert row.campos_attempts == 0
    # The sweeper's earliest interest is in the future, so the in-process
    # attempt gets a clear run at it first.
    assert row.campos_next_attempt_at > scanmark._utcnow()


def test_scan_marks_campos_skipped_when_campos_is_not_configured(monkeypatch):
    """No CampOS means nothing is owed — the outbox must not fill up."""
    monkeypatch.delenv('CAMPOS_API_KEY', raising=False)
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    assert _scan_once(client, student, sessions[0]).status_code == 200
    row = Attendance.query.one()
    assert row.campos_state == 'skipped'
    assert row.campos_next_attempt_at is None


def test_a_full_delivery_queue_no_longer_loses_the_record(monkeypatch):
    """
    The case the outbox exists for.

    A full in-process queue used to mean the delivery was dropped with a log
    line and nothing anywhere remembered it was owed. Now the row itself is
    the queue, so a rejected submit is a deferral.
    """
    monkeypatch.setenv('CAMPOS_API_KEY', 'k')

    class _FullExecutor:
        def submit(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr(scanmark, 'campos_executor', _FullExecutor())
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    assert _scan_once(client, student, sessions[0]).status_code == 200
    row = Attendance.query.one()
    assert row.campos_state == 'pending', 'a full queue must defer, not drop'


def test_outbox_retries_with_backoff_then_dead_letters(monkeypatch):
    monkeypatch.setenv('CAMPOS_API_KEY', 'k')
    monkeypatch.setattr(scanmark, 'CAMPOS_MAX_ATTEMPTS', 3)
    monkeypatch.setattr(scanmark, 'CAMPOS_RETRY_BASE_SECONDS', 0.001)
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    assert _scan_once(client, student, sessions[0]).status_code == 200

    failures = []

    def always_fails(_payload, **_kwargs):
        failures.append(1)
        raise scanmark.CamposIntegrationError('CampOS is down')

    monkeypatch.setattr(scanmark, 'report_attendance_event', always_fails)

    seen_delays = []
    for _ in range(3):
        # Make the row due, exactly as the passage of time would.
        db.session.execute(
            db.text('UPDATE attendance SET campos_next_attempt_at = :now'),
            {'now': scanmark._utcnow()})
        db.session.commit()
        rows = scanmark._claim_campos_batch(10)
        assert len(rows) == 1
        scanmark._deliver_campos_row(rows[0])
        row = Attendance.query.one()
        if row.campos_next_attempt_at:
            seen_delays.append(
                (row.campos_next_attempt_at - scanmark._utcnow()).total_seconds())

    assert len(failures) == 3
    row = Attendance.query.one()
    assert row.campos_state == 'failed', 'must dead-letter, not retry forever'
    assert row.campos_attempts == 3
    assert row.campos_next_attempt_at is None
    # Backoff grows. Jitter means it is not exactly doubling, so compare the
    # first and last rather than each consecutive pair.
    assert seen_delays and seen_delays[-1] >= seen_delays[0]
    # The attendance itself is untouched by any of this.
    assert Attendance.query.count() == 1


def test_outbox_delivery_marks_sent_and_stops_being_claimable(monkeypatch):
    monkeypatch.setenv('CAMPOS_API_KEY', 'k')
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)
    assert _scan_once(client, student, sessions[0]).status_code == 200
    monkeypatch.setattr(scanmark, 'report_attendance_event',
                        lambda _payload, **_kwargs: None)

    db.session.execute(db.text('UPDATE attendance SET campos_next_attempt_at = :now'),
                       {'now': scanmark._utcnow()})
    db.session.commit()
    rows = scanmark._claim_campos_batch(10)
    assert len(rows) == 1
    assert scanmark._deliver_campos_row(rows[0]) is True
    assert Attendance.query.one().campos_state == 'sent'
    assert scanmark._claim_campos_batch(10) == []


def test_outbox_payload_carries_a_stable_idempotency_key():
    """Redelivery must be recognisable as the same event, not a new one."""
    row = {
        'attendance_id': 4242, 'session_id': 7, 'campos_attempts': 2,
        'matric_no': 'ST1', 'email': 'a@b.edu', 'course_code': 'CSC301',
        'course_title': 'Systems', 'session_title': 'Week 1',
        'scanned_at_iso': '2026-01-01T00:00:00Z',
    }
    first = scanmark._campos_payload(row)
    second = scanmark._campos_payload(dict(row, campos_attempts=5))
    assert first['externalId'] == 'scanmark-attendance:4242'
    assert first['externalId'] == second['externalId']


def test_campos_backoff_is_bounded_and_jittered(monkeypatch):
    monkeypatch.setattr(scanmark, 'CAMPOS_RETRY_BASE_SECONDS', 30)
    monkeypatch.setattr(scanmark, 'CAMPOS_RETRY_CAP_SECONDS', 3600)
    for attempts in range(1, 12):
        delays = {scanmark._campos_backoff_seconds(attempts) for _ in range(40)}
        assert all(0 < delay <= 3600 for delay in delays), attempts
        # Full jitter: repeated calls must not agree, or a whole class's
        # retries land in the same instant.
        assert len(delays) > 1, attempts


# ---------------------------------------------------------------------------
# Password hashing capacity
# ---------------------------------------------------------------------------

def test_password_hashing_is_bounded_and_sheds_rather_than_queues(monkeypatch):
    """
    Verifying a password costs ~100 ms of CPU and ~32 MB of RAM, and scrypt
    stops going faster past a handful of concurrent hashes. Unbounded, a login
    rush is an out-of-memory risk and takes every request slot a scan needs.
    """
    gate = threading.BoundedSemaphore(1)
    monkeypatch.setattr(scanmark, '_password_hash_gate', gate)
    monkeypatch.setattr(scanmark, 'PASSWORD_HASH_MAX_WAIT_SECONDS', 0.05)

    held = threading.Event()
    release = threading.Event()

    def hold_the_slot():
        with scanmark._PasswordHashSlot():
            held.set()
            release.wait(5)

    holder = threading.Thread(target=hold_the_slot)
    holder.start()
    assert held.wait(5)
    try:
        with pytest.raises(scanmark.PasswordHashingOverloaded):
            scanmark.verify_password('scrypt:32768:8:1$x$y', 'anything')
    finally:
        release.set()
        holder.join(5)

    # And the slot is given back, so the next login is served normally.
    with scanmark._PasswordHashSlot():
        pass


def test_shed_login_is_a_retryable_503_not_a_credential_answer(monkeypatch):
    """A shed login must never look like 'wrong password'."""
    monkeypatch.setattr(scanmark, 'PASSWORD_HASH_MAX_WAIT_SECONDS', 0.01)
    gate = threading.BoundedSemaphore(1)
    gate.acquire()
    monkeypatch.setattr(scanmark, '_password_hash_gate', gate)

    _coordinator, student, _course, _sessions = _seed()
    student.password = scanmark.generate_password_hash('correct-horse-9',
                                                       method='scrypt')
    db.session.commit()

    client = scanmark.app.test_client()
    response = client.post('/login', data={'email': 'student@example.edu',
                                           'password': 'correct-horse-9'})
    assert response.status_code == 503
    assert response.headers['Retry-After']
    assert b'wrong' not in response.data.lower()
    assert b'invalid' not in response.data.lower()


def test_identity_provider_accounts_carry_no_password_to_verify():
    """
    An SSO account's password is 32 random bytes nobody will ever guess, so
    the ~100 ms of scrypt spent hashing it defended nothing and landed on the
    SSO login path — which is exactly where a launch burst arrives.
    """
    assert scanmark.is_password_usable(scanmark.UNUSABLE_PASSWORD) is False
    assert scanmark.is_password_usable('') is False
    assert scanmark.is_password_usable(
        scanmark.generate_password_hash('x', method='scrypt')) is True
    # And nothing can be made to match it.
    from werkzeug.security import check_password_hash
    for guess in ('', '!', 'password', scanmark.UNUSABLE_PASSWORD):
        assert check_password_hash(scanmark.UNUSABLE_PASSWORD, guess) is False


def test_sso_placeholder_account_cannot_sign_in_with_a_password():
    _coordinator, student, _course, _sessions = _seed()
    student.password = scanmark.UNUSABLE_PASSWORD
    db.session.commit()
    client = scanmark.app.test_client()
    response = client.post('/login', data={'email': 'student@example.edu',
                                           'password': 'anything at all'},
                           follow_redirects=True)
    assert b'Invalid email or password' in response.data


# ---------------------------------------------------------------------------
# Deployment shape
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('uri,expected', [
    ('postgresql://u@h/db', True),
    ('postgresql+psycopg2://u@h/db', True),
    ('postgresql+psycopg://u@h/db', True),
    ('POSTGRESQL://u@h/db', True),
    ('sqlite:///x.db', False),
    ('mysql+pymysql://u@h/db', False),
])
def test_every_postgres_url_spelling_gets_the_pool_configuration(uri, expected):
    """
    `postgresql+psycopg2://` is an ordinary, documented form. Missing it did
    not just refuse the boot: it also skipped the engine-options block, so the
    pool ran on SQLAlchemy's defaults with no InstrumentedQueuePool, no
    pool_timeout and no pool_pre_ping — and the pool-wait metric that exists
    to tell saturation from slowness silently measured nothing.
    """
    assert scanmark._is_postgres_uri(uri) is expected


def test_client_address_is_taken_from_the_proxy_hop_count():
    """
    Behind a load balancer without ProxyFix every per-IP limit collapses into
    a single global bucket, because every request appears to come from the
    router. Trusting the header blindly is the opposite mistake: it is
    client-supplied, so only the configured number of hops counts.
    """
    from werkzeug.middleware.proxy_fix import ProxyFix
    from werkzeug.test import EnvironBuilder

    seen = {}

    def probe(environ, start_response):
        seen['addr'] = environ.get('REMOTE_ADDR')
        seen['scheme'] = environ.get('wsgi.url_scheme')
        start_response('200 OK', [])
        return [b'']

    fixed = ProxyFix(probe, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)
    environ = EnvironBuilder(headers={
        # A client claiming to be 10.9.9.9, one real router hop appending
        # its own view of the peer.
        'X-Forwarded-For': '10.9.9.9, 203.0.113.7',
        'X-Forwarded-Proto': 'https',
    }).get_environ()
    environ['REMOTE_ADDR'] = '172.16.0.1'
    fixed(environ, lambda *_args: None)
    # One trusted hop: the rightmost entry, which the router wrote. The
    # client's own claim is ignored.
    assert seen['addr'] == '203.0.113.7'
    # And the scheme, so WTF_CSRF_SSL_STRICT's referrer check actually runs.
    assert seen['scheme'] == 'https'


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

def test_latency_buckets_are_mergeable_across_workers():
    """
    Percentiles cannot be added up, and every deployment of this application
    is many processes. Bucket counts can, which is what makes one dashboard
    for the whole service possible.
    """
    from performance import LATENCY_BUCKETS_MS

    worker_a = RuntimeMetrics()
    worker_b = RuntimeMetrics()
    for value in (5, 5, 20, 400):
        worker_a.observe_ms('scan.response', value)
    for value in (7, 800, 900):
        worker_b.observe_ms('scan.response', value)

    def buckets(metrics):
        found = {}
        for line in metrics.prometheus().splitlines():
            if line.startswith('scanmark_scan_response_ms_bucket'):
                edge = line.split('le="', 1)[1].split('"', 1)[0]
                found[edge] = int(line.rsplit(' ', 1)[1])
        return found

    a, b = buckets(worker_a), buckets(worker_b)
    # Cumulative and monotonic, as histogram_quantile() requires.
    for one in (a, b):
        counts = [one[str(edge)] for edge in LATENCY_BUCKETS_MS]
        assert counts == sorted(counts)
    assert a['+Inf'] == 4 and b['+Inf'] == 3
    # The merged view: 4 of the 7 observations (5, 5, 20 and 7 ms) were at
    # or under 25 ms — a number neither worker's own percentiles can give.
    assert a['25'] + b['25'] == 4
    assert a['+Inf'] + b['+Inf'] == 7
    # The sum survives the merge too, so an average is computable.
    def total(metrics):
        return next(float(line.rsplit(' ', 1)[1])
                    for line in metrics.prometheus().splitlines()
                    if line.startswith('scanmark_scan_response_ms_sum'))
    assert total(worker_a) + total(worker_b) == pytest.approx(2137.0)


# ---------------------------------------------------------------------------
# Retry-storm prevention
# ---------------------------------------------------------------------------

def test_every_shed_response_tells_the_client_when_to_come_back(monkeypatch):
    """
    A shed scan without Retry-After is 2,000 phones each inventing their own
    interval, which is the burst again at the exact moment the server has
    said it cannot take one.
    """
    monkeypatch.setattr(scanmark.limiter, 'enabled', True)
    monkeypatch.setattr(scanmark, 'SCAN_ADMISSION_RATE', 0)
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)

    # The route's own limit is 10/minute; the eleventh is shed.
    last = None
    for _ in range(12):
        last = client.post('/mark_attendance', json={
            'qr_data': scanmark.generate_signed_qr(sessions[0].id),
            'captured_at': time.time() * 1000,
            'user_marker': str(student.id),
        })
    assert last.status_code == 429
    assert last.headers.get('Retry-After'), 'a 429 must say when to return'
    assert 1 <= int(last.headers['Retry-After']) <= 60
    # And it must be classifiable the same way every other refusal is.
    assert last.get_json()['outcome'] == 'rate_limited'


def test_database_saturation_is_a_retryable_503_not_a_500(monkeypatch):
    """
    Saturation is not a fault. A 500 tells the scanner to give up; a 503 with
    Retry-After tells it to come back, which is the difference between a
    student being marked late and not at all.
    """
    _coordinator, student, _course, sessions = _seed()
    client = scanmark.app.test_client()
    _login(client, student)

    def exhausted(*_args, **_kwargs):
        raise scanmark.PoolTimeoutError('pool exhausted')

    monkeypatch.setattr(scanmark, '_insert_attendance_once', exhausted)
    response = client.post('/mark_attendance', json={
        'qr_data': scanmark.generate_signed_qr(sessions[0].id),
        'captured_at': time.time() * 1000,
        'user_marker': str(student.id),
    })
    assert response.status_code == 503
    assert response.headers.get('Retry-After')
    assert response.get_json()['outcome'] == 'database_saturated'


# ---------------------------------------------------------------------------
# Surviving a Redis outage
# ---------------------------------------------------------------------------

class _DeadRedisSessionInterface:
    """A session store that is down, in the two ways Redis is actually down."""

    def __init__(self, mode):
        self.mode = mode
        self.opened = 0

    def open_session(self, _app, _request):
        self.opened += 1
        if self.mode == 'raises':
            raise redis.ConnectionError('Connection refused')
        # The quieter failure: Flask-Session unsigns the cookie to find the
        # session id, fails, and hands back a fresh empty session without
        # touching Redis and without raising.
        return None

    def save_session(self, _app, _session, _response):
        raise redis.ConnectionError('Connection refused')

    def is_null_session(self, _obj):
        return False

    def make_null_session(self, _app):
        raise AssertionError('should not be reached')

    def get_cookie_name(self, _app):
        return 'session'


def _resilient_interface(mode):
    from flask.sessions import SecureCookieSessionInterface
    return scanmark.ResilientSessionInterface(
        _DeadRedisSessionInterface(mode), SecureCookieSessionInterface())


@pytest.mark.parametrize('mode', ['raises', 'silent'])
def test_a_redis_outage_does_not_500_every_request(mode):
    """
    Flask-Session reads the session inside ctx.push(), BEFORE the request
    context exists — so an uncaught error there is a bare WSGI 500 that no
    Flask error handler can shape. Measured before this guard: 19 of 19 scans
    during a Redis outage returned 500 and none were recorded.
    """
    interface = _resilient_interface(mode)
    with scanmark.app.test_request_context('/'):
        from flask import request as flask_request
        session_state = interface.open_session(scanmark.app, flask_request)
    assert session_state is not None
    # And it is the cookie store, so the CSRF token it mints is one the next
    # request can actually verify.
    assert getattr(session_state, '_scanmark_cookie_fallback', False) is True
    session_state['csrf_token'] = 'abc'
    assert session_state['csrf_token'] == 'abc'


def test_the_session_store_breaker_stops_paying_the_redis_timeout():
    """
    Without a breaker, every request during an outage waits out
    REDIS_CONNECT_TIMEOUT to rediscover that Redis is still down — 2 s added
    to every scan in the room, which is worse than the outage itself.
    """
    dead = _DeadRedisSessionInterface('raises')
    interface = _resilient_interface('raises')
    interface.primary = dead
    with scanmark.app.test_request_context('/'):
        from flask import request as flask_request
        for _ in range(25):
            interface.open_session(scanmark.app, flask_request)
    # One probe trips the breaker; the remaining 24 never touch the store.
    assert dead.opened == 1, (
        f'the store was probed {dead.opened} times during one outage window')


def test_classroom_pin_falls_back_to_the_saved_room_when_redis_is_down(monkeypatch):
    """
    The pin's durable home is class_session.classroom_id. A cache outage must
    cost a database read, not refuse every scan in the room.
    """
    class _DeadRedis:
        def get(self, *_args, **_kwargs):
            raise redis.ConnectionError('Connection refused')

        def setex(self, *_args, **_kwargs):
            raise redis.ConnectionError('Connection refused')

    monkeypatch.setattr(scanmark, 'redis_client', _DeadRedis())
    found = scanmark.get_class_location(1, course_id=1, saved_room=(7.2, 3.4))
    assert found == {'lat': 7.2, 'lon': 3.4}
    # And writing the pin does not fail the request that starts the class.
    scanmark.set_class_location(1, 7.2, 3.4)


def test_qr_generation_survives_a_redis_outage(monkeypatch):
    """The projector screen dying takes the whole room's scanning with it."""
    class _DeadRedis:
        def get(self, *_args, **_kwargs):
            raise redis.ConnectionError('Connection refused')

        def setex(self, *_args, **_kwargs):
            raise redis.ConnectionError('Connection refused')

    monkeypatch.setattr(scanmark, 'redis_client', _DeadRedis())
    token = scanmark.generate_signed_qr(1)
    # Still a valid, verifiable token for the right session.
    assert scanmark.verify_signed_qr(token)[0] == 1


def test_the_immediate_attempt_does_not_retry_inline(monkeypatch):
    """
    Retries belong to the sweeper, which runs off the burst. Retrying inside
    the immediate attempt spends a thread ~10 s of connect timeouts per scan
    while a class is still arriving — measured at a third of scan throughput
    during a CampOS outage.
    """
    monkeypatch.setenv('CAMPOS_API_KEY', 'k')
    seen = []

    def record(_payload, **kwargs):
        seen.append(kwargs.get('attempts'))

    monkeypatch.setattr(scanmark, 'report_attendance_event', record)
    row = {'attendance_id': 1, 'session_id': 1, 'campos_attempts': 0,
           'matric_no': 'ST1', 'email': 'a@b.edu', 'course_code': 'C',
           'course_title': 'T', 'session_title': 'W1',
           'scanned_at_iso': '2026-01-01T00:00:00Z'}
    scanmark._deliver_campos_row(row, inline_retries=1)
    scanmark._deliver_campos_row(row)          # the sweeper's default
    assert seen == [1, 3]


def test_alertable_metrics_exist_before_anything_goes_wrong():
    """
    Prometheus cannot alert on a series that does not exist. A counter that
    first appears when the bad thing happens makes "no dead letters" and "the
    exporter is not being scraped" indistinguishable.
    """
    exported = scanmark.runtime_metrics.prometheus()
    for name in (
        'scanmark_campos_outbox_pending',
        'scanmark_campos_outbox_failed',
        'scanmark_campos_outbox_oldest_seconds',
        'scanmark_campos_dead_lettered_total',
        'scanmark_password_shed_total',
        'scanmark_db_pool_exhausted_total',
        'scanmark_session_store_up',
    ):
        assert any(line.startswith(name) for line in exported.splitlines()), name
