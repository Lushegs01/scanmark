"""
Seed a STAGING deployment for the scan-burst load test.

Creates N students, one coordinator, one course, enrols everyone, opens a class
session, and prints the TARGET_SESSION_ID the locustfile needs.

⚠️  STAGING ONLY. It writes real users and a real class session. It refuses to
run against a database whose URL looks like production unless you pass --force.

Run it where the DATABASE_URL is reachable — a staging shell
(`render ssh` / `heroku run`), or your laptop with DATABASE_URL pointed at the
staging database. This is the opposite of locust, which runs on your laptop
against the staging URL.

    python loadtest/seed_staging.py --students 2000

Then, on your laptop:

    export TARGET_SESSION_ID=<printed below>
    export TARGET_SECRET_KEY=<staging SECRET_KEY>
    export STUDENT_PASSWORD=<printed below>
    locust -f loadtest/locustfile.py --host https://staging.example \
           --users 2000 --spawn-rate 50 --headless --run-time 5m --processes -1

Clean up afterwards with --teardown.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_PASSWORD = 'loadtest-pass-9'
EMAIL_PATTERN = os.environ.get('EMAIL_PATTERN', 'st{n}@student.funaab.edu.ng')
COORDINATOR_EMAIL = 'loadtest-coordinator@staff.funaab.edu.ng'
COURSE_CODE = 'LOAD101'


def looks_like_production(url):
    lowered = (url or '').lower()
    return any(marker in lowered for marker in ('prod', 'live', 'scanmark-db'))


# EMAIL_PATTERN with {n} replaced by "one or more digits, nothing else". A
# prefix LIKE 'st%' is NOT good enough to identify what this script created:
# it also matches stella@, stephen@, steve@ — real students, deleted by a
# teardown that was only ever meant to remove st1@, st2@, st3@.
_SEEDED_EMAIL_RE = re.compile(
    '^' + re.escape(EMAIL_PATTERN).replace(re.escape('{n}'), r'\d+') + '$'
)


def seeded_student_ids(User):
    """IDs of accounts this script created — matched exactly, never by prefix."""
    prefix = EMAIL_PATTERN.split('{n}')[0]
    candidates = User.query.filter(User.email.like(f'{prefix}%')).all()
    return [u.id for u in candidates if _SEEDED_EMAIL_RE.match(u.email or '')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--students', type=int, default=2000)
    parser.add_argument('--password', default=DEFAULT_PASSWORD)
    parser.add_argument('--teardown', action='store_true',
                        help='Delete everything this script created, then exit.')
    parser.add_argument('--force', action='store_true',
                        help='Proceed even if DATABASE_URL looks like production.')
    parser.add_argument('--yes', action='store_true',
                        help='Skip the teardown confirmation prompt.')
    args = parser.parse_args()

    db_url = os.environ.get('DATABASE_URL', '')
    if not db_url:
        sys.exit("DATABASE_URL is not set. Point it at STAGING and try again.")
    if looks_like_production(db_url) and not args.force:
        sys.exit(f"DATABASE_URL looks like production ({db_url.split('@')[-1]}). "
                 "Refusing. Pass --force only if you are certain.")

    import app  # noqa: F401  — importing runs create_all + migrations
    from models import db, User, Course, ClassSession, Attendance
    from werkzeug.security import generate_password_hash

    with app.app.app_context():
        if args.teardown:
            student_ids = seeded_student_ids(User)
            course = Course.query.filter_by(code=COURSE_CODE).first()
            coordinator = User.query.filter_by(email=COORDINATOR_EMAIL).first()

            print(f"\nWill delete from {db_url.split('@')[-1]}:")
            print(f"  {len(student_ids)} seeded students "
                  f"(matching {EMAIL_PATTERN.replace('{n}', '<digits>')})")
            print(f"  course {COURSE_CODE}: {'yes' if course else 'not found'}"
                  f" (+ its sessions and attendance)")
            print(f"  coordinator {COORDINATOR_EMAIL}: "
                  f"{'yes' if coordinator else 'not found'}")
            if not (student_ids or course or coordinator):
                print("\nNothing to remove.")
                return
            if not args.yes:
                if input("\nType 'delete' to confirm: ").strip().lower() != 'delete':
                    sys.exit("Aborted. Nothing was deleted.")

            if course:
                Attendance.query.filter_by(course_id=course.id).delete(
                    synchronize_session=False)
                ClassSession.query.filter_by(course_id=course.id).delete(
                    synchronize_session=False)
            if student_ids:
                # Attendance and enrolments elsewhere, so a seeded student
                # never leaves an orphan row behind.
                Attendance.query.filter(
                    Attendance.student_id.in_(student_ids)).delete(
                        synchronize_session=False)
                for student in User.query.filter(User.id.in_(student_ids)).all():
                    student.enrolled_courses.clear()
                db.session.flush()
            if course:
                db.session.delete(course)
            if student_ids:
                User.query.filter(User.id.in_(student_ids)).delete(
                    synchronize_session=False)
            if coordinator:
                db.session.delete(coordinator)
            db.session.commit()
            print(f"\nRemoved {len(student_ids)} load-test students"
                  f"{' and course ' + COURSE_CODE if course else ''}.")
            return

        # All students share one password, so hash it ONCE. scrypt is
        # deliberately slow; hashing it 2000 times would take minutes.
        shared_hash = generate_password_hash(args.password, method='scrypt')

        coordinator = User.query.filter_by(email=COORDINATOR_EMAIL).first()
        if not coordinator:
            coordinator = User(full_name='Load Test Coordinator',
                               email=COORDINATOR_EMAIL, password=shared_hash,
                               role='Course Coordinator',
                               department='Computer Science',
                               faculty='Physical Sciences',
                               # Without this the account cannot sign in.
                               email_verified=True)
            db.session.add(coordinator)
            db.session.commit()

        course = Course.query.filter_by(code=COURSE_CODE).first()
        if not course:
            course = Course(code=COURSE_CODE, title='Load Test Course',
                            coordinator_id=coordinator.id,
                            department='Computer Science',
                            faculty='Physical Sciences')
            db.session.add(course)
            db.session.commit()

        existing = {
            email for (email,) in db.session.query(User.email).filter(
                User.email.like('st%@student.funaab.edu.ng')).all()
        }
        created = []
        for n in range(1, args.students + 1):
            email = EMAIL_PATTERN.format(n=n)
            if email in existing:
                continue
            created.append(User(
                full_name=f'Load Student {n}', email=email, password=shared_hash,
                role='student', matric_no=f'LT{n:06d}', level='300',
                # The load test signs in with a password. An unverified account
                # is refused at login, so every scan would fail before it
                # started and the run would measure nothing.
                email_verified=True))
            if len(created) >= 500:
                db.session.bulk_save_objects(created)
                db.session.commit()
                created = []
        if created:
            db.session.bulk_save_objects(created)
            db.session.commit()

        students = User.query.filter(
            User.email.like('st%@student.funaab.edu.ng')).all()
        enrolled_ids = {s.id for s in course.students}
        for student in students:
            if student.id not in enrolled_ids:
                course.students.append(student)
        db.session.commit()

        session_row = ClassSession(course_id=course.id, title='Load Test Burst')
        db.session.add(session_row)
        db.session.commit()

        print("\n" + "=" * 58)
        print(f"  Students enrolled : {len(students)}")
        print(f"  Course            : {COURSE_CODE}")
        print(f"  TARGET_SESSION_ID : {session_row.id}")
        print(f"  STUDENT_PASSWORD  : {args.password}")
        print("=" * 58)
        print("\nNo class location is pinned for this course, so the geofence")
        print("stays out of the way. If you pin one, the locustfile's null")
        print("lat/lon make every scan fail with 'Location required'.\n")


if __name__ == '__main__':
    main()
