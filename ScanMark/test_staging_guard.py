import json

import pytest

from loadtest.staging_guard import latency_errors, validate_target
from loadtest.scan_validation import validate_sessions
from sqlalchemy import create_engine, text


@pytest.fixture
def target(tmp_path):
    data = {
        'mode': 'staging', 'origin': 'https://staging.example',
        'database': {'host': 'staging-db', 'port': 5432, 'database': 'scanmark'},
        **{key: 'recorded' for key in (
            'deployed_commit', 'web_plan', 'region', 'postgres_version_plan',
            'redis_version_plan', 'worker_settings', 'database_connection_limit', 'generator')},
        **{key: True for key in ('isolated_services', 'synthetic_accounts', 'mail_sink',
                                'campos_disabled', 'security_controls_enabled')},
    }
    path = tmp_path / 'target.json'
    path.write_text(json.dumps(data))
    return path, data


def test_reviewed_target(target):
    path, data = target
    assert validate_target(path, 'https://staging.example',
                           'postgresql://reader:secret@staging-db:5432/scanmark') == data


@pytest.mark.parametrize('host,db', [
    ('https://production.example', 'postgresql://staging-db:5432/scanmark'),
    ('https://staging.example', 'postgresql://production-db:5432/scanmark'),
    ('https://staging.example', 'postgresql://staging-db:5432/live'),
    ('https://user:password@staging.example', 'postgresql://staging-db:5432/scanmark'),
    ('https://staging.example/path', 'postgresql://staging-db:5432/scanmark'),
])
def test_mismatched_target_rejected(target, host, db):
    with pytest.raises(ValueError):
        validate_target(target[0], host, db)


@pytest.mark.parametrize('field', ['isolated_services', 'security_controls_enabled', 'deployed_commit'])
def test_missing_prerequisite_rejected(target, field):
    path, data = target
    data.pop(field)
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        validate_target(path, data['origin'], 'postgresql://staging-db:5432/scanmark')


def test_slo_is_strict_and_rejects_invalid_samples():
    assert latency_errors([99]) == []
    assert 'scan_p50_slo_exceeded' in latency_errors([100])
    assert latency_errors([])
    assert latency_errors([float('nan')])
    assert latency_errors([float('inf')])


@pytest.mark.parametrize('verified,active,ended,enrolled', [
    (False, True, None, True), (True, False, None, True),
    (True, True, '2026-01-01', True), (True, True, None, False),
])
def test_session_preflight_rejects_ineligible_pairs(verified, active, ended, enrolled):
    engine = create_engine('sqlite://')
    with engine.begin() as conn:
        for sql in (
            'CREATE TABLE "user" (id INTEGER, email_verified BOOLEAN)',
            'CREATE TABLE enrollments (user_id INTEGER, course_id INTEGER)',
            'CREATE TABLE class_session (id INTEGER, course_id INTEGER, active BOOLEAN, ended_at TEXT)',
        ):
            conn.execute(text(sql))
        conn.execute(text('INSERT INTO "user" VALUES (1,:verified)'), {'verified': verified})
        conn.execute(text('INSERT INTO class_session VALUES (10,1,:active,:ended)'),
                     {'active': active, 'ended': ended})
        if enrolled:
            conn.execute(text('INSERT INTO enrollments VALUES (1,1)'))
    with pytest.raises(ValueError):
        validate_sessions(engine, {(1, 10)})
    engine.dispose()
