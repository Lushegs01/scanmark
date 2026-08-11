import pytest
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
    scanmark.set_class_location(course.id, *origin)
    latitude, longitude = _point_north(*origin, distance_m)
    client = scanmark.app.test_client()
    _login(client, student)

    response = client.post('/mark_attendance', json={
        'qr_data': scanmark.generate_signed_qr(sessions[0].id),
        'lat': latitude,
        'lon': longitude,
        'location_age_ms': 100,
        'accuracy_m': 5,
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
            'user_marker': str(student.id),
        })
    finally:
        event.remove(db.engine, 'before_cursor_execute', count_query)
    assert response.status_code == 200
    assert len(statements) <= 5


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
