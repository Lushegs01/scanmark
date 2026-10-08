"""Shared-carrier auth limits and browser retry contracts, with the limiter on."""
import re
import threading

import pytest

from conftest import VALID_PASSWORD


JSON = {'Accept': 'application/json'}


@pytest.fixture(autouse=True)
def auth_limits(appmod, monkeypatch):
    appmod.limiter.enabled = True
    appmod.limiter.reset()
    monkeypatch.setattr(appmod, 'send_verification_email', lambda *args: None)
    monkeypatch.setattr(appmod, 'send_welcome_email', lambda *args: None)
    yield
    appmod.limiter.reset()
    appmod.limiter.enabled = False


def signup_data(n=0):
    return {'full_name': f'Student {n}', 'email': f'auth{n}@student.funaab.edu.ng',
            'password': VALID_PASSWORD, 'matric_no': f'202099{n:04d}', 'level': '300'}


def test_distinct_students_can_create_accounts_from_one_carrier(appmod):
    from models import User
    for n in range(8):
        response = appmod.app.test_client().post('/signup', data=signup_data(n), headers=JSON)
        assert response.status_code == 200
        assert response.json == {'outcome': 'success', 'redirect': '/login', 'created': True}
    with appmod.app.app_context():
        assert User.query.count() == 8


@pytest.mark.parametrize('path', ['/signup', '/login'])
def test_2000_distinct_emails_do_not_share_a_tiny_limit(appmod, path):
    # Isolate admission policy from hashing capacity: signup validation fails
    # and login uses nonexistent accounts. The staging harness measures real
    # hashes, database writes and mail; this is NOT a throughput benchmark.
    for n in range(2000):
        response = appmod.app.test_client().post(path, data={
            'email': f'cohort{n}@student.funaab.edu.ng'
        }, headers=JSON)
        assert response.status_code == 200, (n, response.json)
        assert response.json['outcome'] == 'form_error'


def test_email_limit_survives_case_whitespace_and_ip_changes(appmod):
    for n in range(6):
        response = appmod.app.test_client().post('/signup', data={
            'email': ' Student@Example.edu ' if n % 2 else 'student@example.edu'
        }, headers=JSON, environ_overrides={'REMOTE_ADDR': f'203.0.113.{n + 1}'})
        assert response.status_code == (429 if n == 5 else 200)
    assert response.json['outcome'] == 'rate_limited'
    assert 3500 < int(response.headers['Retry-After']) <= 3601
    assert response.json['retry_after'] == int(response.headers['Retry-After'])
    assert response.headers['Cache-Control'] == 'no-store'
    # Viewing the form must remain possible after POSTs have been blocked.
    assert appmod.app.test_client().get('/signup').status_code == 200


@pytest.mark.parametrize('path', ['/signup', '/login'])
def test_network_ceiling_still_bounds_bulk_attempts(appmod, monkeypatch, path):
    monkeypatch.setattr(appmod, 'AUTH_NETWORK_RATE_LIMIT', '3 per minute')
    for n in range(4):
        response = appmod.app.test_client().post(path, data={
            'email': f'student{n}@example.edu'
        }, headers=JSON)
        assert response.status_code == (429 if n == 3 else 200)
    assert appmod.app.test_client().post(path, data={'email': 'other@example.edu'},
        headers=JSON, environ_overrides={'REMOTE_ADDR': '203.0.113.9'}).status_code == 200


def test_login_bruteforce_limit_remains(appmod):
    client = appmod.app.test_client()
    for n in range(11):
        response = client.post('/login', data={'email': 'absent@example.edu'}, headers=JSON)
        assert response.status_code == (429 if n == 10 else 200)
    assert 1 <= int(response.headers['Retry-After']) <= 61


@pytest.mark.parametrize('path', ['/signup', '/login'])
def test_overload_retries_do_not_exhaust_email_allowance(appmod, monkeypatch, path):
    client = appmod.app.test_client()
    if path == '/login':
        assert client.post('/signup', data=signup_data()).status_code == 302
    gate = threading.BoundedSemaphore(1)
    gate.acquire()
    monkeypatch.setattr(appmod, '_password_hash_gate', gate)
    monkeypatch.setattr(appmod, 'PASSWORD_HASH_MAX_WAIT_SECONDS', 0.001)
    # Include the network allowance: failed capacity checks must not consume it.
    monkeypatch.setattr(appmod, 'AUTH_NETWORK_RATE_LIMIT', '3 per minute')
    for _ in range(12):
        response = client.post(path, data=signup_data(), headers=JSON)
        assert response.status_code == 503
        assert response.json['outcome'] == 'auth_overloaded'
    gate.release()
    response = client.post(path, data=signup_data(), headers=JSON)
    assert response.status_code == 200
    assert response.json['outcome'] == 'success'
    if path == '/login':
        with client.session_transaction() as session:
            assert session['_user_id']


def test_csrf_is_required_for_enhanced_forms(appmod):
    appmod.app.config['WTF_CSRF_ENABLED'] = True
    client = appmod.app.test_client()
    rejected = client.post('/signup', data=signup_data(), headers=JSON)
    assert rejected.status_code == 400
    assert rejected.json['outcome'] == 'csrf_expired'
    page = client.get('/signup')
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
    response = client.post('/signup', data={**signup_data(), 'csrf_token': token}, headers=JSON)
    assert response.json['outcome'] == 'success'


def test_unverified_account_keeps_resend_available(appmod):
    appmod.REQUIRE_EMAIL_VERIFICATION = True
    client = appmod.app.test_client()
    client.post('/signup', data=signup_data(), headers=JSON)
    response = client.post('/login', data=signup_data(), headers=JSON)
    assert response.json['outcome'] == 'form_error'
    assert response.json['unverified_email'] == signup_data()['email']
    with client.session_transaction() as session:
        assert '_user_id' not in session


def test_plain_html_retry_advice_matches_actual_hourly_limit(appmod):
    client = appmod.app.test_client()
    for _ in range(6):
        response = client.post('/signup', data={'email': 'one@example.edu'})
    assert response.status_code == 429
    assert f"wait {response.headers['Retry-After']} seconds".encode() in response.data
    assert b"href='/signup'" in response.data


def test_signup_overload_keeps_the_signup_page_without_javascript(appmod, monkeypatch):
    def overloaded(_password):
        raise appmod.PasswordHashingOverloaded()
    monkeypatch.setattr(appmod, 'hash_password', overloaded)
    response = appmod.app.test_client().post('/signup', data=signup_data())
    assert response.status_code == 503
    assert b'id="signupForm"' in response.data
