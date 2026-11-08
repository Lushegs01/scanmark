"""
Seed a cohort for scan_burst.py on a DISPOSABLE staging database.

    python loadtest/seed_burst.py students --count 2000     # once
    python loadtest/seed_burst.py session                    # before every run

Run with the SAME environment as the server under test (DATABASE_URL,
REDIS_URL, SECRET_KEY): importing the application creates the schema, and the
classroom pin goes to the Redis the server reads.

`students` creates st1..stN@student.funaab.edu.ng, enrolled on BURST101,
idempotently, with the password in STUDENT_PASSWORD (required: there is no
default, because the cohort includes a course coordinator and a password
written in the repository would be a known credential wherever this ran).
Their password hash uses a deliberately cheap scrypt cost: the
burst harness signs every student in before the timed phase, and spending
minutes of memory-hard hashing on test accounts measures nothing. Real
accounts are untouched. NEVER run this against production.

`session` opens a FRESH class session for BURST101 in the saved classroom and
prints its id: the harness refuses a cohort that already has attendance for
the session, so every run gets its own.
"""

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')

from werkzeug.security import generate_password_hash  # noqa: E402

import app as scanmark  # noqa: E402
from models import Classroom, Course, User, db, enrollments  # noqa: E402

INSTITUTION = 'funaab.edu.ng'
ROOM = {'name': 'Burst Hall', 'lat': 7.2257, 'lon': 3.4372}
LECTURER = 'lect@staff.funaab.edu.ng'


def _password():
    password = os.environ.get('STUDENT_PASSWORD', '')
    if len(password) < 10:
        raise SystemExit('Set STUDENT_PASSWORD (10+ characters) for the seeded accounts; '
                         'scan_burst.py reads the same variable.')
    return password


def _course():
    lecturer = User.query.filter_by(email=LECTURER).first()
    if lecturer is None:
        lecturer = User(full_name='Burst Lecturer', email=LECTURER,
                        password=generate_password_hash(_password(), method='scrypt:1024:8:1'),
                        role='course coordinator', email_verified=True, institution=INSTITUTION)
        db.session.add(lecturer)
        db.session.flush()
    course = Course.query.filter_by(code='BURST101', institution=INSTITUTION).first()
    if course is None:
        course = Course(code='BURST101', title='Load Rehearsal', coordinator_id=lecturer.id,
                        institution=INSTITUTION)
        db.session.add(course)
        db.session.flush()
    room = Classroom.query.filter_by(name=ROOM['name'], institution=INSTITUTION).first()
    if room is None:
        room = Classroom(name=ROOM['name'], latitude=ROOM['lat'], longitude=ROOM['lon'],
                         accuracy_m=8, created_by_id=lecturer.id, institution=INSTITUTION)
        db.session.add(room)
    db.session.commit()
    return course, room


def seed_students(count, password):
    with scanmark.app.test_request_context():
        course, _room = _course()
        cheap = generate_password_hash(password, method='scrypt:1024:8:1')
        existing = {email for (email,) in db.session.query(User.email)
                    .filter(User.email.like('st%@student.funaab.edu.ng'))}
        rows = [{'full_name': f'Burst Student {n}', 'email': f'st{n}@student.funaab.edu.ng',
                 'password': cheap, 'role': 'student', 'matric_no': f'BURST{n:06}',
                 'level': '300', 'email_verified': True, 'institution': INSTITUTION}
                for n in range(1, count + 1)
                if f'st{n}@student.funaab.edu.ng' not in existing]
        for start in range(0, len(rows), 1000):
            db.session.execute(User.__table__.insert(), rows[start:start + 1000])
        db.session.commit()
        ids = [user_id for (user_id,) in db.session.query(User.id)
               .filter(User.email.like('st%@student.funaab.edu.ng'))]
        enrolled = {user_id for (user_id,) in db.session.query(enrollments.c.user_id)
                    .filter(enrollments.c.course_id == course.id)}
        missing = [{'user_id': user_id, 'course_id': course.id}
                   for user_id in ids if user_id not in enrolled]
        if missing:
            db.session.execute(enrollments.insert(), missing)
        db.session.commit()
        print(json.dumps({'students': len(ids), 'course_id': course.id}))


def open_session():
    with scanmark.app.test_request_context():
        course, room = _course()
        session_row = scanmark.resume_or_start_session(course, force_new=True)
        scanmark.pin_session_to_classroom(session_row, room)
        print(json.dumps({'session_id': session_row.id, 'lat': room.latitude,
                          'lon': room.longitude}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    students = sub.add_parser('students')
    students.add_argument('--count', type=int, default=2000)
    sub.add_parser('session')
    arguments = parser.parse_args()
    if arguments.command == 'students':
        seed_students(arguments.count, _password())
    else:
        open_session()
