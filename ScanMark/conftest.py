"""
Shared pytest fixtures for the ScanMark route tests.

`app.py` does its schema work at import time (db.create_all(), the idempotent
column migrations, the legacy-attendance backfill), so the environment has to
be in place BEFORE the module is imported. Everything here therefore configures
os.environ first and imports the app lazily inside a session fixture.

The suite runs on a throwaway SQLite file and no Redis, so CI needs no services.
"""
import os
import tempfile

import pytest

_TMPDIR = tempfile.mkdtemp(prefix='scanmark-tests-')

# Must be set before `import app`.
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-the-suite')
os.environ.setdefault('DATABASE_URL', f'sqlite:///{_TMPDIR}/test.db')
os.environ.setdefault('FLASK_ENV', 'testing')
os.environ.pop('REDIS_URL', None)
# Point mail at a closed port: sends fail instantly instead of reaching out.
os.environ.setdefault('MAIL_SERVER', '127.0.0.1')
os.environ.setdefault('MAIL_PORT', '2525')
os.environ.setdefault('MAIL_DEFAULT_SENDER', 'scanmark@example.test')
os.environ.setdefault('GEOFENCE_RADIUS_M', '100')
os.environ.setdefault('MIN_PASSWORD_LENGTH', '10')

VALID_PASSWORD = 'correct-horse-9'


@pytest.fixture(scope='session')
def flask_app():
    import app as app_module

    app_module.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,      # individual tests re-enable it
        SERVER_NAME='localhost.localdomain',
    )
    app_module.limiter.enabled = False
    return app_module


@pytest.fixture()
def appmod(flask_app):
    """The imported app module with a clean database for this test."""
    from models import db

    with flask_app.app.app_context():
        db.session.remove()
        # Another test file may have dropped the schema on its way out, so
        # make sure it exists before emptying it — the suite has to pass in
        # any collection order.
        db.create_all()
        # Delete rather than drop_all/create_all: the association tables are
        # plain Table objects and this keeps the schema (and its indexes,
        # including the duplicate-scan unique index) exactly as booted.
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        db.session.commit()

    flask_app.limiter.enabled = False
    flask_app.app.config['WTF_CSRF_ENABLED'] = False
    flask_app.REQUIRE_EMAIL_VERIFICATION = False
    # ScanMark ships with GEOFENCE_REQUIRED on, so an unpinned class refuses
    # every scan. Most tests here are about something else entirely and would
    # all have to pin a classroom first; they opt out, and the shipped default
    # has its own tests in TestGeofenceRequiredMode.
    flask_app.GEOFENCE_REQUIRED = False
    if flask_app.redis_client is None:
        flask_app._local_locations.clear()

    yield flask_app

    with flask_app.app.app_context():
        from models import db as _db
        _db.session.remove()


@pytest.fixture()
def client(appmod):
    return appmod.app.test_client()


@pytest.fixture()
def seed(appmod):
    """
    A coordinator, a second unrelated coordinator, a lecturer, two students,
    one course (coordinated by the first) and one open class session.
    """
    from models import db, User, Course, ClassSession
    from werkzeug.security import generate_password_hash

    def _hash(pw):
        return generate_password_hash(pw, method='scrypt')

    with appmod.app.app_context():
        coordinator = User(full_name='Ada Coordinator',
                           email='ada@staff.funaab.edu.ng', password=_hash(VALID_PASSWORD),
                           role='Course Coordinator', department='Computer Science',
                           faculty='Physical Sciences', email_verified=True)
        outsider = User(full_name='Eve Outsider',
                        email='eve@staff.funaab.edu.ng', password=_hash(VALID_PASSWORD),
                        role='Course Coordinator', department='Computer Science',
                        faculty='Physical Sciences', email_verified=True)
        lecturer = User(full_name='Grace Lecturer',
                        email='grace@staff.funaab.edu.ng', password=_hash(VALID_PASSWORD),
                        role='Lecturer', department='Computer Science',
                        faculty='Physical Sciences', email_verified=True)
        student = User(full_name='Kemi Student', email='kemi@student.funaab.edu.ng',
                       password=_hash(VALID_PASSWORD), role='student',
                       matric_no='20200001', level='300', email_verified=True)
        other_student = User(full_name='Tayo Student', email='tayo@student.funaab.edu.ng',
                             password=_hash(VALID_PASSWORD), role='student',
                             matric_no='20200002', level='300', email_verified=True)
        db.session.add_all([coordinator, outsider, lecturer, student, other_student])
        db.session.commit()

        course = Course(code='CSC201', title='Data Structures',
                        coordinator_id=coordinator.id, department='Computer Science',
                        faculty='Physical Sciences')
        db.session.add(course)
        db.session.commit()

        student.enrolled_courses.append(course)
        db.session.commit()

        # Opened the way the application opens one, so it carries the roster
        # snapshot every percentage is computed against.
        class_session = ClassSession(course_id=course.id, title='Week 1')
        db.session.add(class_session)
        db.session.flush()
        appmod._snapshot_roster(class_session)
        db.session.commit()

        return {
            'coordinator_id': coordinator.id,
            'outsider_id': outsider.id,
            'lecturer_id': lecturer.id,
            'student_id': student.id,
            'other_student_id': other_student.id,
            'course_id': course.id,
            'session_id': class_session.id,
            'coordinator_email': coordinator.email,
            'outsider_email': outsider.email,
            'lecturer_email': lecturer.email,
            'student_email': student.email,
            'other_student_email': other_student.email,
        }


@pytest.fixture()
def login(appmod):
    """Sign a seeded user in on a fresh test client."""
    def _login(email, password=VALID_PASSWORD):
        c = appmod.app.test_client()
        response = c.post('/login', data={'email': email, 'password': password},
                          follow_redirects=False)
        assert response.status_code in (302, 200), response.status_code
        return c
    return _login


def qr_token(appmod, session_id, age_seconds=0):
    """Mint a QR payload the server will accept, using its own algorithm."""
    import time
    with appmod.app.app_context():
        ts = int(time.time()) - age_seconds
        message = f"S{session_id}|{ts}"
        return f"{message}|{appmod._make_signature(message)}"
