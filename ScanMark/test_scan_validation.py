"""Prevent false capacity claims from partial or incorrectly verified bursts."""
import pytest
from sqlalchemy import create_engine, text

from loadtest.scan_validation import (
    acceptance_errors, attendance_counts, expected_attendance, verify_attendance,
)


@pytest.fixture()
def engine():
    database = create_engine('sqlite://')
    with database.begin() as connection:
        connection.execute(text('CREATE TABLE "user" (id INTEGER, email TEXT, role TEXT)'))
        # No unique constraint here: deliberately exercise the verifier's
        # detection of duplicate rows as well as the production index tests.
        connection.execute(text('CREATE TABLE attendance (student_id INTEGER, session_id INTEGER)'))
        connection.execute(text('INSERT INTO "user" VALUES '
                                "(1, 'one@example.edu', 'Student'), "
                                "(2, 'two@example.edu', 'student')"))
    yield database
    database.dispose()


def test_verification_scopes_the_exact_student_session_pairs(engine):
    expected = expected_attendance(engine, ['one@example.edu', 'two@example.edu'], [10, 20])
    with engine.begin() as connection:
        connection.execute(text('INSERT INTO attendance VALUES (1,10), (2,20), '
                                '(1,20), (2,10), (99,10), (1,99)'))
    assert verify_attendance(engine, expected) == {
        'rows': 2, 'distinct_students': 2, 'duplicate_rows': 0, 'missing_pairs': 0}
    assert attendance_counts(engine, expected)  # reused cohort fails preflight


def test_equal_row_count_cannot_hide_missing_and_duplicate_students(engine):
    expected = expected_attendance(engine, ['one@example.edu', 'two@example.edu'], [10])
    with engine.begin() as connection:
        connection.execute(text('INSERT INTO attendance VALUES (1,10), (1,10)'))
    assert verify_attendance(engine, expected) == {
        'rows': 2, 'distinct_students': 1, 'duplicate_rows': 1, 'missing_pairs': 1}


@pytest.mark.parametrize('emails', [[], ['absent@example.edu'],
                                   ['one@example.edu', 'one@example.edu']])
def test_preflight_refuses_missing_or_reused_identities(engine, emails):
    with pytest.raises(ValueError):
        expected_attendance(engine, emails, [10])


def passing_result():
    return dict(students=2, authenticated=2, outcomes={'success': 2}, statuses={200: 2},
                verified={'rows': 2, 'distinct_students': 2, 'duplicate_rows': 0,
                          'missing_pairs': 0}, client_ms=[100, 200], feed_failures={})


def test_complete_burst_passes():
    assert acceptance_errors(**passing_result()) == []


@pytest.mark.parametrize('changes,expected_error', [
    ({'authenticated': 1}, 'not_all_students_authenticated'),
    ({'outcomes': {'success': 1, 'duplicate': 1}}, 'not_all_scans_succeeded'),
    ({'outcomes': {'success': 1}}, 'not_all_scans_succeeded'),
    ({'statuses': {200: 1, 503: 1}}, 'unexpected_http_or_transport_result'),
    ({'statuses': {200: 1, 'transport_error': 1}}, 'unexpected_http_or_transport_result'),
    ({'verified': {}}, 'attendance_not_verified_exactly_once'),
    ({'verified': {'rows': 2, 'distinct_students': 1, 'duplicate_rows': 1,
                   'missing_pairs': 1}}, 'attendance_not_verified_exactly_once'),
    ({'client_ms': [100, 20000]}, 'browser_deadline_exceeded_or_missing_results'),
    ({'client_ms': []}, 'browser_deadline_exceeded_or_missing_results'),
    ({'feed_failures': {403: 1}}, 'projector_failed'),
])
def test_partial_or_unverified_burst_fails(changes, expected_error):
    result = passing_result() | changes
    assert expected_error in acceptance_errors(**result)
