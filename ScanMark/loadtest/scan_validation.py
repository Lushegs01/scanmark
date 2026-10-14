"""Database and acceptance checks for scan_burst; no app or network at import."""
from collections import Counter

from sqlalchemy import bindparam, text


def validate_sessions(engine, expected):
    """Check real, open sessions and verified enrolled students before HTTP writes."""
    query = text(
        'SELECT u.id, s.id FROM "user" u '
        'JOIN enrollments e ON e.user_id = u.id '
        'JOIN class_session s ON s.course_id = e.course_id '
        'WHERE u.email_verified = true AND s.active = true AND s.ended_at IS NULL '
        'AND u.id IN :students AND s.id IN :sessions'
    ).bindparams(bindparam('students', expanding=True), bindparam('sessions', expanding=True))
    with engine.connect() as connection:
        eligible = {tuple(row) for row in connection.execute(query, {
            'students': sorted({student for student, _ in expected}),
            'sessions': sorted({session for _, session in expected}),
        })}
    if not expected <= eligible:
        raise ValueError('Cohort requires verified enrollment and open sessions')


def expected_attendance(engine, emails, session_ids):
    """Resolve the exact cohort, refusing missing or reused student identities."""
    if not emails or len(set(emails)) != len(emails):
        raise ValueError('The cohort must contain distinct student emails')
    query = text('SELECT id, email FROM "user" WHERE email IN :emails '
                 'AND lower(role) = :role').bindparams(bindparam('emails', expanding=True))
    with engine.connect() as connection:
        users = dict((email, user_id) for user_id, email in connection.execute(
            query, {'emails': emails, 'role': 'student'}))
    if len(users) != len(emails):
        raise ValueError('Not every requested student exists in the staging database')
    return {(users[email], session_ids[index % len(session_ids)])
            for index, email in enumerate(emails)}


def attendance_counts(engine, expected):
    """Ignore unrelated classes, but count each expected student/session pair."""
    query = text('SELECT student_id, session_id FROM attendance '
                 'WHERE student_id IN :students AND session_id IN :sessions').bindparams(
                     bindparam('students', expanding=True),
                     bindparam('sessions', expanding=True))
    with engine.connect() as connection:
        rows = connection.execute(query, {
            'students': sorted({student for student, _ in expected}),
            'sessions': sorted({session for _, session in expected}),
        })
        return Counter(tuple(row) for row in rows if tuple(row) in expected)


def verify_attendance(engine, expected):
    counts = attendance_counts(engine, expected)
    return {'rows': sum(counts.values()),
            'distinct_students': len({student for student, _ in counts}),
            'duplicate_rows': sum(count - 1 for count in counts.values()),
            'missing_pairs': len(expected - counts.keys())}


def acceptance_errors(students, authenticated, outcomes, statuses, verified,
                      client_ms, feed_failures):
    """A partial cohort or an unverifiable register is never a passing run."""
    errors = []
    if authenticated != students:
        errors.append('not_all_students_authenticated')
    # This harness uses a fresh cohort and sends one request per phone. A
    # duplicate is not evidence of a new write and must fail this rehearsal.
    if outcomes.get('success', 0) != students or sum(outcomes.values()) != students:
        errors.append('not_all_scans_succeeded')
    if statuses.get(200, 0) != students or sum(statuses.values()) != students:
        errors.append('unexpected_http_or_transport_result')
    if (not verified or verified.get('rows') != students
            or verified.get('distinct_students') != students
            or verified.get('duplicate_rows') != 0
            or verified.get('missing_pairs') != 0):
        errors.append('attendance_not_verified_exactly_once')
    if len(client_ms) != students or any(ms >= 20_000 for ms in client_ms):
        errors.append('browser_deadline_exceeded_or_missing_results')
    if feed_failures:
        errors.append('projector_failed')
    return errors
