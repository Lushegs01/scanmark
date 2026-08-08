"""Measure bounded incremental projector payloads with a local SQLite fixture."""

import argparse
import json
import os
import pathlib
import sys
import time

os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('SECRET_KEY', 'benchmark-only-secret')
os.environ.setdefault('SCANMARK_DISABLE_SCHEDULER', '1')
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import app as scanmark  # noqa: E402
from models import Attendance, ClassSession, Course, User, db  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--attendees', type=int, choices=(600, 2000), default=600)
    arguments = parser.parse_args()
    scanmark.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    scanmark.limiter.enabled = False
    with scanmark.app.app_context():
        db.create_all()
        lecturer = User(
            full_name='Projector Lecturer', email='projector@example.edu',
            password='x', role='course coordinator',
        )
        students = [User(
            full_name=f'Attendee {number:04}', email=f'attendee-{number}@example.edu',
            password='x', role='student', matric_no=f'A{number:05}', level='300',
        ) for number in range(arguments.attendees)]
        db.session.add_all([lecturer, *students])
        db.session.flush()
        course = Course(code='FEED01', title='Feed Test', coordinator_id=lecturer.id)
        db.session.add(course)
        db.session.flush()
        class_session = ClassSession(course_id=course.id, title='Feed Burst')
        db.session.add(class_session)
        db.session.flush()
        db.session.add_all([
            Attendance(student_id=student.id, course_id=course.id, session_id=class_session.id)
            for student in students
        ])
        db.session.commit()
        lecturer_id = lecturer.id
        session_id = class_session.id

        client = scanmark.app.test_client()
        with client.session_transaction() as browser_session:
            browser_session['_user_id'] = str(lecturer_id)
            browser_session['_fresh'] = True

        cursor = 0
        payload_sizes = []
        request_times = []
        total_rows = 0
        while True:
            started = time.perf_counter()
            response = client.get(
                f'/api/session/{session_id}/attendees?after={cursor}&limit=250'
            )
            request_times.append((time.perf_counter() - started) * 1000)
            payload_sizes.append(len(response.data))
            payload = response.get_json()
            total_rows += len(payload['new_attendees'])
            cursor = payload['last_id']
            if not payload['has_more']:
                break

        empty_started = time.perf_counter()
        empty = client.get(f'/api/session/{session_id}/attendees?after={cursor}&limit=250')
        empty_ms = (time.perf_counter() - empty_started) * 1000
        legacy_rows = (db.session.query(Attendance.timestamp, User.full_name,
                                        User.matric_no, User.level)
                       .join(User, User.id == Attendance.student_id)
                       .filter(Attendance.session_id == session_id)
                       .order_by(Attendance.timestamp.desc())
                       .all())
        legacy_payload = json.dumps({
            'status': 'success',
            'present': len(legacy_rows),
            'enrolled': 0,
            'attendees': [{
                'name': name,
                'matric_no': matric_no,
                'level': level,
                'time': timestamp.strftime('%I:%M %p'),
            } for timestamp, name, matric_no, level in legacy_rows],
        }).encode()
        print({
            'attendees': arguments.attendees,
            'rows_received': total_rows,
            'initial_batches': len(payload_sizes),
            'largest_batch_bytes': max(payload_sizes),
            'initial_total_bytes': sum(payload_sizes),
            'empty_poll_bytes': len(empty.data),
            'legacy_full_poll_bytes': len(legacy_payload),
            'max_batch_ms': round(max(request_times), 3),
            'empty_poll_ms': round(empty_ms, 3),
        })


if __name__ == '__main__':
    main()
