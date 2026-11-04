"""
Seed one lecture for the student-journey harness, or report on it.

    python seed_journey.py seed --students 40      # prints JSON
    python seed_journey.py count                   # attendance rows, JSON

Run it with the SAME environment as the server under test (DATABASE_URL,
REDIS_URL, SECRET_KEY): importing the application is what creates the schema,
and the classroom pin is written to the same Redis the server reads.

The lecture is held in a saved Classroom, which is the path the application
recommends, so the geofence the browser is judged against is the real one.
"""

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')

import app as scanmark  # noqa: E402
from models import Attendance, Classroom, Course, User, db, enrollments  # noqa: E402

PASSWORD = 'Journey-Passw0rd!'
ROOM = {'lat': 7.226000, 'lon': 3.441000}


def seed(students):
    with scanmark.app.app_context():
        password_hash = scanmark.hash_password(PASSWORD)
        lecturer = User.query.filter_by(email='journey-lecturer@staff.funaab.edu.ng').first()
        if lecturer is None:
            lecturer = User(full_name='Journey Lecturer',
                            email='journey-lecturer@staff.funaab.edu.ng',
                            password=password_hash, role='course coordinator',
                            email_verified=True)
            db.session.add(lecturer)
            db.session.flush()
        course = Course.query.filter_by(code='JRN101').first()
        if course is None:
            course = Course(code='JRN101', title='Student Journey',
                            coordinator_id=lecturer.id)
            db.session.add(course)
            db.session.flush()
        room = Classroom.query.filter_by(name='Journey Hall').first()
        if room is None:
            room = Classroom(name='Journey Hall', latitude=ROOM['lat'],
                             longitude=ROOM['lon'], accuracy_m=8,
                             created_by_id=lecturer.id,
                             institution=scanmark.institution_of(lecturer) or '')
            db.session.add(room)
            db.session.flush()
        emails = []
        for number in range(students):
            email = f'journey{number:04}@student.funaab.edu.ng'
            emails.append(email)
            if User.query.filter_by(email=email).first():
                continue
            student = User(full_name=f'Journey Student {number}', email=email,
                           password=password_hash, role='student',
                           matric_no=f'2026{number:05}', level='300',
                           email_verified=True)
            db.session.add(student)
            db.session.flush()
            db.session.execute(enrollments.insert(),
                               {'user_id': student.id, 'course_id': course.id})
        db.session.commit()
        session_row = scanmark.open_session_for(course.id)
        if session_row is None:
            session_row = scanmark.create_class_session(course)
        scanmark.pin_session_to_classroom(session_row, room)
        print(json.dumps({'session_id': session_row.id, 'course_id': course.id,
                          'students': emails, 'password': PASSWORD,
                          'room': ROOM}))


def count():
    with scanmark.app.app_context():
        rows = (db.session.query(User.email)
                .join(Attendance, Attendance.student_id == User.id).all())
        print(json.dumps({'rows': len(rows), 'emails': sorted(r[0] for r in rows)}))


if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else 'seed'
    if command == 'seed':
        total = int(sys.argv[sys.argv.index('--students') + 1]) if '--students' in sys.argv else 40
        seed(total)
    elif command == 'count':
        count()
    else:
        raise SystemExit(f'unknown command {command}')
