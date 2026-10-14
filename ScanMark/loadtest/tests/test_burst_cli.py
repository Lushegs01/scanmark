"""Exercise actual CLI, concurrency, report and database verification together."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('mode,error', [
    ('success', None),
    ('missing-write', 'attendance_not_verified_exactly_once'),
    ('duplicate-write', 'attendance_not_verified_exactly_once'),
    ('partial-login', 'not_all_students_authenticated'),
    ('bad-projector', 'projector_failed'),
    ('capped', 'not_a_simultaneous_full_cohort_burst'),
    ('redirect', 'not_all_students_authenticated'),
])
def test_cli(tmp_path, mode, error):
    students = int(os.environ.get('HARNESS_FIXTURE_STUDENTS', '20'))
    db_path = tmp_path / 'fixture.db'
    with sqlite3.connect(db_path) as conn:
        conn.executescript('''
            CREATE TABLE "user" (id INTEGER, email TEXT, role TEXT, email_verified BOOLEAN);
            CREATE TABLE attendance (student_id INTEGER, session_id INTEGER);
            CREATE TABLE enrollments (user_id INTEGER, course_id INTEGER);
            CREATE TABLE class_session (id INTEGER, course_id INTEGER, active BOOLEAN, ended_at TEXT);
            INSERT INTO class_session VALUES (10,1,1,NULL);
        ''')
        conn.executemany('INSERT INTO "user" VALUES (?, ?, "student", 1)',
                         [(n, f'st{n}@example.test') for n in range(1, students + 1)])
        conn.executemany('INSERT INTO enrollments VALUES (?,1)',
                         [(n,) for n in range(1, students + 1)])
    port_file = tmp_path / 'port'
    server = subprocess.Popen([sys.executable, str(Path(__file__).with_name('http_fixture.py')),
                               str(db_path), mode, str(port_file)])
    try:
        deadline = time.monotonic() + 10
        while not port_file.exists() and time.monotonic() < deadline and server.poll() is None:
            time.sleep(.02)
        host = f'http://127.0.0.1:{port_file.read_text()}'
        manifest = tmp_path / 'manifest.json'
        manifest.write_text(json.dumps({'mode': 'local-harness-check', 'origin': host,
            'database': {'host': None, 'port': None, 'database': str(db_path)}}))
        report = tmp_path / 'result.json'
        command = [sys.executable, str(ROOT / 'loadtest/scan_burst.py'),
                   '--host', host, '--students', str(students), '--session-id', '10',
                   '--login-concurrency', '32',  # fixture has no password hashing
                   '--secret', 'fixture-only', '--email-pattern', 'st{n}@example.test',
                   '--database-url', f'sqlite:///{db_path}', '--staging-manifest', str(manifest),
                   '--confirm-staging-writes', '--json-out', str(report)]
        if mode == 'capped':
            command += ['--burst-concurrency', '2']
        if mode == 'bad-projector':
            command += ['--projector-watchers', '1']
        run = subprocess.run(command, capture_output=True, text=True, timeout=120)
        assert report.exists(), run.stderr
        result = json.loads(report.read_text())
        assert result['capacity_accepted'] is False
        assert result['students'] == students, run.stderr
        if error:
            assert run.returncode != 0
            assert error in result['acceptance_errors'], result
        else:
            assert result['correctness_passed'], (result, run.stderr)
            assert result['verified']['rows'] == students
            # Fixture timing is not a deterministic SLO test.
            assert run.returncode == (1 if result['slo_errors'] else 0)
        evidence = os.environ.get('HARNESS_EVIDENCE_DIR')
        if evidence:
            destination = Path(evidence)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / f'{mode}-{students}.json').write_text(json.dumps(result, indent=2))
        # A reused output must fail before login or scanning and preserve evidence.
        before = report.read_bytes()
        rerun = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert rerun.returncode == 2
        assert report.read_bytes() == before
        if mode == 'success':
            # Fresh output cannot make a reused cohort acceptable.
            second_report = tmp_path / 'reused.json'
            repeated = command.copy()
            repeated[repeated.index('--json-out') + 1] = str(second_report)
            refused = subprocess.run(repeated, capture_output=True, text=True, timeout=10)
            assert refused.returncode == 2
            assert not json.loads(second_report.read_text())['passed']
            with sqlite3.connect(db_path) as conn:
                assert conn.execute('SELECT count(*) FROM attendance').fetchone()[0] == students
    finally:
        server.terminate()
        server.wait(timeout=5)
