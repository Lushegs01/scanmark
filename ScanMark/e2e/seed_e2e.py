"""
Seed the manual-attendance-code browser test, and print what it needs.

    python e2e/seed_e2e.py > /tmp/e2e-seed.json

Run with the SAME environment as the server under test (DATABASE_URL,
REDIS_URL, SECRET_KEY): importing the application creates the schema, and the
classroom pin goes to the Redis the server reads. Idempotent on the accounts;
every run opens fresh class sessions, so earlier attendance never leaks in.

The accounts' password is random for every run (or E2E_PASSWORD, if set) and
is printed in the JSON the browser test reads. It is never written in the
repository: one of these accounts is a course coordinator, and a published
password would be a working credential on any database this was run against.
"""

import json
import os
import pathlib
import secrets
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')

import app as scanmark  # noqa: E402
from models import Classroom, Course, User, db, enrollments  # noqa: E402

PASSWORD = os.environ.get('E2E_PASSWORD') or secrets.token_urlsafe(18)
ROOM = {'lat': 7.226000, 'lon': 3.441000}
INSTITUTION = 'funaab.edu.ng'


def _user(email, name, role, password_hash, **extra):
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(full_name=name, email=email, password=password_hash,
                    role=role, email_verified=True, institution=INSTITUTION, **extra)
        db.session.add(user)
        db.session.flush()
    else:
        # A re-run brings a new password; the accounts follow it.
        user.password = password_hash
    return user


def _course(code, title, coordinator):
    course = Course.query.filter_by(code=code, institution=INSTITUTION).first()
    if course is None:
        course = Course(code=code, title=title, coordinator_id=coordinator.id,
                        institution=INSTITUTION)
        db.session.add(course)
        db.session.flush()
    return course


def _enrol(student, course):
    exists = db.session.execute(
        enrollments.select().where(enrollments.c.user_id == student.id,
                                   enrollments.c.course_id == course.id)).first()
    if not exists:
        db.session.execute(enrollments.insert(), {'user_id': student.id, 'course_id': course.id})


def main():
    with scanmark.app.test_request_context():
        password_hash = scanmark.hash_password(PASSWORD)
        lecturer = _user('e2e-lecturer@staff.funaab.edu.ng', 'E2E Lecturer',
                         'course coordinator', password_hash)
        students = [_user(f'e2e{n}@student.funaab.edu.ng', f'E2E Student {n}', 'student',
                          password_hash, matric_no=f'E2E{n:05}', level='300')
                    for n in range(8)]
        main_course = _course('CSC301', 'Operating Systems', lecturer)
        other_course = _course('MTH201', 'Linear Algebra', lecturer)
        # A class the QR test really ends, so it never ends the one above.
        ending_course = _course('CSC399', 'End Class Check', lecturer)
        for student in students:
            _enrol(student, main_course)
        # One student has two classes running at once: the "choose your class" case.
        _enrol(students[5], other_course)
        room = Classroom.query.filter_by(name='E2E Hall', institution=INSTITUTION).first()
        if room is None:
            room = Classroom(name='E2E Hall', latitude=ROOM['lat'], longitude=ROOM['lon'],
                             accuracy_m=8, created_by_id=lecturer.id, institution=INSTITUTION)
            db.session.add(room)
        db.session.commit()

        sessions = {}
        for course in (main_course, other_course, ending_course):
            session_row = scanmark.resume_or_start_session(course, force_new=True)
            scanmark.pin_session_to_classroom(session_row, room)
            sessions[course.code] = session_row.id
        print(json.dumps({
            'password': PASSWORD,
            'lecturer': lecturer.email,
            'students': [student.email for student in students],
            'session_id': sessions['CSC301'],
            'other_session_id': sessions['MTH201'],
            'ending_session_id': sessions['CSC399'],
            'course_code': 'CSC301',
            'room': ROOM,
        }))


if __name__ == '__main__':
    main()
