"""
Seed an ISOLATED ScanMark database with a fictional demo dataset.

Everything here is synthetic and labelled as such:

* the institution is ``demo-university.example`` -- ``.example`` is reserved by
  RFC 2606 and can never be a real university's domain;
* every matric number starts with ``DEMO``;
* every course offering is section ``DEMO``.

Only HISTORY is written directly: past class meetings (already ended), their
roster snapshots and the scans recorded at them. Those cannot be produced
through the live workflow without time travel. Today's meeting is NOT created
here -- the capture script opens it through the real lecturer UI, and every
check-in in it goes through the real ``/mark_attendance`` endpoint.

The app's own helpers do the work wherever one exists (``hash_password``,
``_snapshot_roster``, ``_clean_course_code``, ``normalize_matric``,
``validate_password_strength``), so seeded rows are shaped exactly like rows
the application writes itself.

Safety: refuses to run unless the environment declares itself development,
``DATABASE_URL`` is a local SQLite file, and the database holds no users yet.
It never touches Postgres, and so never a deployed database.

Usage (from run_demo.sh, which sets every variable):

    SCANMARK_ENV=development DATABASE_URL=sqlite:////abs/path/demo.db \\
    SECRET_KEY=... DEMO_PASSWORD=... python seed_demo.py --out seed.json
"""
import argparse
import datetime as dt
import json
import os
import random
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[3] / 'ScanMark'

DEMO_DOMAIN = 'demo-university.example'
STAFF_DOMAIN = f'staff.{DEMO_DOMAIN}'
STUDENT_DOMAIN = f'student.{DEMO_DOMAIN}'
SECTION = 'DEMO'

# A fixed, arbitrary point. It is the centre of the demo classroom's geofence
# and the capture script places the student's phone 18 m from it.
CLASSROOM = {'name': 'Lecture Theatre 2', 'lat': 6.51520, 'lon': 3.38940,
             'accuracy_m': 6.0, 'radius_m': 60.0}

LECTURER = {'full_name': 'Dr. Amara Okafor', 'email': f'amara.okafor@{STAFF_DOMAIN}',
            'role': 'Course Coordinator', 'department': 'Computer Science',
            'faculty': 'Physical Sciences'}
CO_INSTRUCTOR = {'full_name': 'Mr. Kunle Bakare', 'email': f'kunle.bakare@{STAFF_DOMAIN}',
                 'role': 'Lecturer', 'department': 'Computer Science',
                 'faculty': 'Physical Sciences'}

# (full name, attendance propensity). The featured student's history is fixed
# below rather than drawn, so the numbers in the footage are predictable.
STUDENTS = [
    ('Tolu Adeyemi', None), ('Chiamaka Nwosu', 0.95), ('Ibrahim Musa', 0.90),
    ('Funke Adebayo', 0.92), ('Emeka Eze', 0.88), ('Aisha Bello', 0.97),
    ('Daniel Okon', 0.85), ('Ngozi Okeke', 0.93), ('Samuel Ojo', 0.80),
    ('Halima Abubakar', 0.94), ('Kelechi Obi', 0.55), ('Bisi Ogunleye', 0.90),
    ('Yusuf Lawal', 0.86), ('Grace Etim', 0.96), ('Chidi Anyanwu', 0.82),
    ('Zainab Sani', 0.91), ('Femi Akinola', 0.87), ('Precious Udo', 0.89),
    ('Tunde Alabi', 0.84), ('Ifeoma Chukwu', 0.95), ('Musa Garba', 0.60),
    ('Blessing Effiong', 0.62), ('Seun Oladipo', 0.90), ('Amina Yusuf', 0.93),
]
FEATURED = 'Tolu Adeyemi'
# Present at every past CSC 201 lecture except the fourth.
FEATURED_MISSED = {3}

# code, title, local meeting weekdays (Mon=0), local start hour, number of
# past meetings, which students (by index into STUDENTS) are enrolled.
COURSES = [
    ('CSC 201', 'Data Structures and Algorithms', (0, 2), 10, 8, range(0, 24)),
    ('CSC 205', 'Database Systems', (1, 3), 12, 6, range(4, 22)),
    ('CSC 211', 'Computer Architecture', (4,), 14, 4, range(2, 22)),
]
MAIN_COURSE = 'CSC 201'


def refuse(message):
    sys.exit(f'seed_demo: refusing to run: {message}')


def check_environment():
    env = (os.environ.get('SCANMARK_ENV') or os.environ.get('FLASK_ENV') or '').lower()
    if env not in ('development', 'dev', 'local', 'test', 'testing'):
        refuse('SCANMARK_ENV must declare a development environment.')
    url = os.environ.get('DATABASE_URL', '')
    if not url.startswith('sqlite:///'):
        refuse('DATABASE_URL must be a local SQLite file; this script never '
               'writes to Postgres.')
    if not os.environ.get('DEMO_PASSWORD'):
        refuse('DEMO_PASSWORD is not set (run_demo.sh generates one per run).')


def slug(name):
    return '.'.join(part.lower() for part in name.replace('.', '').split()
                    if part not in ('Dr', 'Mr', 'Mrs', 'Ms'))


def past_meetings(today_local, weekdays, hour, count):
    """The `count` most recent local meeting starts strictly before today."""
    day = today_local - dt.timedelta(days=1)
    starts = []
    while len(starts) < count:
        if day.weekday() in weekdays:
            starts.append(dt.datetime.combine(day, dt.time(hour, 0)))
        day -= dt.timedelta(days=1)
    return sorted(starts)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--out', required=True,
                        help='Where to write the seed summary JSON (no secrets).')
    args = parser.parse_args()

    check_environment()
    sys.path.insert(0, str(APP_DIR))
    os.chdir(APP_DIR)
    import app as scanmark                              # noqa: E402  (env first)
    from localtime import LOCAL_TIMEZONE, local_today, format_local
    from models import (db, User, Course, Classroom, ClassSession, Attendance,
                        enrollments, course_instructors)

    if scanmark.IS_PRODUCTION:
        refuse('the app reports a production environment.')

    password = os.environ['DEMO_PASSWORD']
    problem = scanmark.validate_password_strength(password)
    if problem:
        refuse(f'DEMO_PASSWORD does not meet the app policy: {problem}')

    def to_utc_naive(local_naive):
        """A local wall-clock time as the naive UTC the columns store."""
        return (local_naive.replace(tzinfo=LOCAL_TIMEZONE)
                .astimezone(dt.timezone.utc).replace(tzinfo=None))

    rng = random.Random(2026)
    summary = {'institution': DEMO_DOMAIN, 'courses': {}, 'students': []}

    with scanmark.app.app_context():
        if db.session.query(User.id).first() is not None:
            refuse('the database already holds users. Point DATABASE_URL at a '
                   'fresh file (run_demo.sh deletes its own before seeding).')

        hashed = scanmark.hash_password(password)
        term_year, term_semester = scanmark.academic_term_of()

        def staff(spec):
            user = User(full_name=spec['full_name'], email=spec['email'],
                        password=hashed, role=spec['role'],
                        department=spec['department'], faculty=spec['faculty'],
                        institution=DEMO_DOMAIN, email_verified=True)
            db.session.add(user)
            return user

        lecturer = staff(LECTURER)
        co_instructor = staff(CO_INSTRUCTOR)

        students = []
        for number, (name, _propensity) in enumerate(STUDENTS, start=1):
            matric = scanmark.normalize_matric(f'DEMO/23/{number:04d}')
            assert matric, 'demo matric number fails the app pattern'
            student = User(full_name=name, email=f'{slug(name)}@{STUDENT_DOMAIN}',
                           password=hashed, role='Student', matric_no=matric,
                           level='200', department='Computer Science',
                           faculty='Physical Sciences', institution=DEMO_DOMAIN,
                           email_verified=True)
            db.session.add(student)
            students.append(student)
        db.session.flush()

        room = Classroom(institution=DEMO_DOMAIN, name=CLASSROOM['name'],
                         latitude=CLASSROOM['lat'], longitude=CLASSROOM['lon'],
                         accuracy_m=CLASSROOM['accuracy_m'],
                         radius_m=CLASSROOM['radius_m'], created_by_id=lecturer.id)
        db.session.add(room)

        today = local_today()
        # Enrolment opens before the first meeting of any course.
        enrolled_local = dt.datetime.combine(today - dt.timedelta(days=40), dt.time(9, 0))

        for code, title, weekdays, hour, meetings, members in COURSES:
            course = Course(code=scanmark._clean_course_code(code),
                            title=scanmark._clean_text(title, 100),
                            academic_year=term_year, semester=term_semester,
                            section=SECTION, coordinator_id=lecturer.id,
                            institution=DEMO_DOMAIN, department=lecturer.department,
                            faculty=lecturer.faculty)
            db.session.add(course)
            db.session.flush()
            if code == MAIN_COURSE:
                db.session.execute(course_instructors.insert().values(
                    user_id=co_instructor.id, course_id=course.id))

            roster = [students[i] for i in members]
            db.session.execute(enrollments.insert(), [
                {'user_id': s.id, 'course_id': course.id,
                 'enrolled_at': to_utc_naive(enrolled_local)} for s in roster])

            sessions_out = []
            for index, start_local in enumerate(past_meetings(today, weekdays, hour, meetings)):
                start_utc = to_utc_naive(start_local)
                meeting = ClassSession(course_id=course.id, kind='Lecture', sequence=1,
                                       title=f'Lecture on {format_local(start_utc, "%d %b %Y")}',
                                       date_created=start_utc, active=False,
                                       ended_at=start_utc + dt.timedelta(minutes=55),
                                       ended_by_id=lecturer.id, classroom_id=None)
                db.session.add(meeting)
                db.session.flush()
                expected = scanmark._snapshot_roster(meeting)

                present = 0
                for student in roster:
                    name = student.full_name
                    if name == FEATURED and code == MAIN_COURSE:
                        attended = index not in FEATURED_MISSED
                    else:
                        propensity = dict(STUDENTS)[name] or 0.9
                        attended = rng.random() < propensity
                    if not attended:
                        continue
                    # Most arrive in the first ten minutes; a few drift in late.
                    minutes = rng.choice([1, 2, 2, 3, 3, 4, 5, 6, 7, 9, 12, 16])
                    db.session.add(Attendance(
                        student_id=student.id, course_id=course.id,
                        session_id=meeting.id,
                        timestamp=start_utc + dt.timedelta(minutes=minutes,
                                                           seconds=rng.randint(0, 59)),
                        device_id=f'demo-seed-{student.id}', campos_state='skipped'))
                    present += 1
                sessions_out.append({'title': meeting.title, 'expected': expected,
                                     'present': present})

            summary['courses'][code] = {'id': course.id, 'title': title,
                                        'enrolled': len(roster),
                                        'past_sessions': sessions_out}
        db.session.commit()

        for student in students:
            summary['students'].append({'id': student.id, 'name': student.full_name,
                                        'email': student.email,
                                        'matric_no': student.matric_no})
        summary.update({
            'lecturer': {'id': lecturer.id, 'name': lecturer.full_name,
                         'email': lecturer.email},
            'co_instructor': {'id': co_instructor.id, 'name': co_instructor.full_name},
            'featured_student': next(s for s in summary['students']
                                     if s['name'] == FEATURED),
            'classroom': {'id': room.id, **CLASSROOM},
            'term': {'academic_year': term_year, 'semester': term_semester,
                     'section': SECTION},
            'main_course': MAIN_COURSE,
        })

    Path(args.out).write_text(json.dumps(summary, indent=2))
    main_course = summary['courses'][MAIN_COURSE]
    held = len(main_course['past_sessions'])
    scans = sum(s['present'] for s in main_course['past_sessions'])
    print(f'seed_demo: {len(STUDENTS)} students, {len(COURSES)} courses; '
          f'{MAIN_COURSE}: {held} past lectures, {scans} scans '
          f'({scans / (held * main_course["enrolled"]):.0%} average attendance)')


if __name__ == '__main__':
    main()
