"""Scan allowance isolation and recovery, with the real route limiter on."""
import time

import pytest


@pytest.fixture(autouse=True)
def scan_limits(appmod, monkeypatch):
    appmod.limiter.enabled = True
    appmod.limiter.reset()
    monkeypatch.setattr(appmod, 'SCAN_ADMISSION_RATE', 0)
    yield
    appmod.limiter.reset()
    appmod.limiter.enabled = False


def scan(appmod, client, session_id, student_id):
    return client.post('/mark_attendance', json={
        'qr_data': appmod.generate_signed_qr(session_id),
        'captured_at': time.time() * 1000,
        'user_marker': str(student_id),
    })


def test_2000_students_have_independent_scan_allowances(appmod, seed):
    # A sequential regression for limiter isolation, NOT a capacity test.
    from models import Attendance, User, db, enrollments
    with appmod.app.app_context():
        students = [User(full_name=f'Student {n}', email=f'scan{n}@example.edu',
                         password='!', role='student', email_verified=True)
                    for n in range(2000)]
        db.session.add_all(students)
        db.session.flush()
        ids = [student.id for student in students]
        db.session.execute(enrollments.insert(), [
            {'user_id': user_id, 'course_id': seed['course_id']} for user_id in ids])
        db.session.commit()
    for user_id in ids:
        client = appmod.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True
        # All clients deliberately share one IP, like a carrier gateway.
        response = scan(appmod, client, seed['session_id'], user_id)
        assert response.status_code == 200, (user_id, response.json)
    with appmod.app.app_context():
        assert Attendance.query.filter_by(session_id=seed['session_id']).count() == 2000


@pytest.mark.parametrize('overload', ['admission', 'database'])
def test_overload_does_not_spend_student_allowance(appmod, seed, login, monkeypatch, overload):
    from sqlalchemy.exc import TimeoutError
    client = login(seed['student_email'])
    original_insert = appmod._insert_attendance_once

    def busy(*args, **kwargs):
        raise TimeoutError('Pool is full')

    if overload == 'admission':
        monkeypatch.setattr(appmod, 'admit_scan', lambda session_id: False)
        expected_status = 429
    else:
        monkeypatch.setattr(appmod, '_insert_attendance_once', busy)
        expected_status = 503
    for _ in range(12):
        response = scan(appmod, client, seed['session_id'], seed['student_id'])
        assert response.status_code == expected_status
        assert response.json['outcome'] != 'rate_limited'
    monkeypatch.setattr(appmod, 'admit_scan', lambda session_id: True)
    monkeypatch.setattr(appmod, '_insert_attendance_once', original_insert)
    assert scan(appmod, client, seed['session_id'], seed['student_id']).status_code == 200


def test_one_students_limit_does_not_block_another(appmod, seed, login):
    from models import User, Course, db
    with appmod.app.app_context():
        other_student = db.session.get(User, seed['other_student_id'])
        other_student.enrolled_courses.append(db.session.get(Course, seed['course_id']))
        db.session.commit()
    first = login(seed['student_email'])
    for _ in range(10):
        response = scan(appmod, first, seed['session_id'], seed['student_id'])
        assert response.status_code in (200, 409)
    assert scan(appmod, first, seed['session_id'], seed['student_id']).status_code == 429
    other = login(seed['other_student_email'])
    assert scan(appmod, other, seed['session_id'], seed['other_student_id']).status_code == 200
