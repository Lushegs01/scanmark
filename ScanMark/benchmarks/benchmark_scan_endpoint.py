"""
REGRESSION MICROBENCHMARK — NOT a capacity measurement.

Runs sequentially, in-process, against SQLite, with no CSRF, no rate limiter,
no Redis, no network and no concurrency. It exists to catch a change that
makes a code path dramatically slower, and it is good at that.

It says NOTHING about how many students can scan at once. Do not quote a
number from this file as user capacity: use loadtest/ against staging, where
the geofence, CSRF, rate limiting, Redis, Postgres and real concurrency are
all in play. See loadtest/README.md.
"""

import argparse
from collections import Counter
import os
import pathlib
import statistics
import sys
import time

os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('SECRET_KEY', 'benchmark-only-secret')
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')
os.environ.setdefault('SCAN_CONFIRMATION_EMAILS', 'false')
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import app as scanmark  # noqa: E402
from flask import g  # noqa: E402
from models import ClassSession, Course, User, db, enrollments  # noqa: E402


class NullExecutor:
    def submit(self, *_args, **_kwargs):
        return object()

    def shutdown(self, **_kwargs):
        return None


def percentile(ordered, ratio):
    return ordered[min(len(ordered) - 1, int(len(ordered) * ratio))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--students', type=int, default=600)
    parser.add_argument('--max-p99-ms', type=float, default=50.0)
    arguments = parser.parse_args()
    scanmark.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
    scanmark.limiter.enabled = False
    scanmark.campos_executor = NullExecutor()
    scanmark.notification_work_executor = NullExecutor()

    with scanmark.app.app_context():
        db.create_all()
        lecturer = User(
            full_name='Load Lecturer', email='load-lecturer@example.edu',
            password='x', role='course coordinator',
        )
        students = [User(
            full_name=f'Load Student {number}', email=f'load-{number}@example.edu',
            password='x', role='student', matric_no=f'L{number:05}', level='300',
        ) for number in range(arguments.students)]
        db.session.add_all([lecturer, *students])
        db.session.flush()
        course = Course(code='LOAD01', title='Load Test', coordinator_id=lecturer.id)
        db.session.add(course)
        db.session.flush()
        class_session = ClassSession(course_id=course.id, title='Burst')
        db.session.add(class_session)
        db.session.flush()
        db.session.execute(enrollments.insert(), [
            {'user_id': student.id, 'course_id': course.id} for student in students
        ])
        db.session.commit()
        student_ids = [student.id for student in students]
        token = scanmark.generate_signed_qr(class_session.id)

        samples = []
        started = time.perf_counter()
        failures = 0
        outcomes = Counter()
        for student_id in student_ids:
            g.pop('_login_user', None)
            client = scanmark.app.test_client()
            with client.session_transaction() as browser_session:
                browser_session['_user_id'] = str(student_id)
                browser_session['_fresh'] = True
            request_started = time.perf_counter()
            response = client.post('/mark_attendance', json={
                'qr_data': token,
                'user_marker': str(student_id),
                'device_id': 'local-benchmark',
            })
            samples.append((time.perf_counter() - request_started) * 1000)
            failures += response.status_code != 200
            payload = response.get_json(silent=True) or {}
            outcomes[(response.status_code, payload.get('message', 'non-JSON'))] += 1
        elapsed = time.perf_counter() - started

    samples.sort()
    result = {
        'scope': 'local sequential SQLite and cookie sessions; not concurrency capacity',
        'students': arguments.students,
        'failures': failures,
        'outcomes': dict(outcomes),
        'elapsed_s': round(elapsed, 3),
        'requests_per_s': round(arguments.students / elapsed, 1),
        'mean_ms': round(statistics.fmean(samples), 3),
        'p50_ms': round(percentile(samples, .50), 3),
        'p95_ms': round(percentile(samples, .95), 3),
        'p99_ms': round(percentile(samples, .99), 3),
        'max_ms': round(samples[-1], 3),
    }
    print(result)
    if failures or result['p99_ms'] > arguments.max_p99_ms:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
