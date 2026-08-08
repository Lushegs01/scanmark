"""Authenticated ScanMark staging scenarios.

Select with ``SCENARIO=scan|login|double_scan``.  ``TARGET_SESSION_IDS`` may
contain one id or a comma-separated set for simultaneous-class rehearsals.
Never point this at production: successful runs create attendance rows.
"""

import hashlib
import hmac
import itertools
import os
import re
import time

from gevent.pool import Pool
from locust import HttpUser, between, task
from locust.exception import StopUser


SECRET_KEY = os.environ.get('TARGET_SECRET_KEY', '')
SESSION_IDS = [
    int(value) for value in os.environ.get('TARGET_SESSION_IDS', '1').split(',')
    if value.strip()
]
PASSWORD = os.environ.get('STUDENT_PASSWORD', 'pass1234')
EMAIL_PATTERN = os.environ.get('EMAIL_PATTERN', 'st{n}@student.funaab.edu.ng')
SCENARIO = os.environ.get('SCENARIO', 'scan').strip().lower()
DOUBLE_SCAN_CONCURRENCY = int(os.environ.get('DOUBLE_SCAN_CONCURRENCY', '20'))
_user_counter = itertools.count(1)


def make_qr_token(session_id):
    message = f"S{session_id}|{int(time.time())}"
    signature = hmac.new(
        SECRET_KEY.encode(), message.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"{message}|{signature}"


class AuthenticatedUser(HttpUser):
    abstract = True
    wait_time = between(0.2, 1.0)

    def login(self):
        number = next(_user_counter)
        self.session_id = SESSION_IDS[(number - 1) % len(SESSION_IDS)]
        email = EMAIL_PATTERN.format(n=number)
        page = self.client.get('/login', name='/login [form]')
        match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        if not match:
            raise StopUser()
        response = self.client.post('/login', data={
            'csrf_token': match.group(1),
            'email': email,
            'password': PASSWORD,
        }, name='/login [authenticate]')
        if response.status_code >= 400 or '/login' in response.url:
            raise StopUser()
        scan_page = self.client.get('/scan_page', name='/scan_page [preload]')
        match = re.search(r'csrfToken:\s*"([^"]+)"', scan_page.text)
        if not match:
            raise StopUser()
        self.csrf = match.group(1)

    def scan(self, name='/mark_attendance [scan]'):
        return self.client.post(
            '/mark_attendance',
            json={
                'qr_data': make_qr_token(self.session_id),
                'lat': None,
                'lon': None,
                'device_id': 'locust',
            },
            headers={'X-CSRFToken': self.csrf},
            name=name,
            catch_response=True,
        )


class ScanningStudent(AuthenticatedUser):
    abstract = SCENARIO != 'scan'

    def on_start(self):
        self.login()

    @task
    def scan_once(self):
        with self.scan() as response:
            try:
                payload = response.json()
            except ValueError:
                response.failure(f'non-JSON HTTP {response.status_code}')
                raise StopUser()
            message = payload.get('message', '')
            if payload.get('status') == 'success' or 'already marked' in message:
                response.success()
            elif 'expired' in message:
                response.failure('token expired while queued')
            else:
                response.failure(message or f'HTTP {response.status_code}')
        raise StopUser()


class LoginStampedeStudent(AuthenticatedUser):
    abstract = SCENARIO != 'login'

    @task
    def login_once(self):
        self.login()
        raise StopUser()


class ConcurrentDoubleScanner(AuthenticatedUser):
    abstract = SCENARIO != 'double_scan'

    def on_start(self):
        self.login()

    @task
    def race_duplicate_requests(self):
        pool = Pool(DOUBLE_SCAN_CONCURRENCY)
        jobs = [pool.spawn(self.scan, '/mark_attendance [duplicate race]')
                for _ in range(DOUBLE_SCAN_CONCURRENCY)]
        pool.join()
        successes = 0
        for job in jobs:
            response = job.value
            try:
                payload = response.json()
            except ValueError:
                response.failure('non-JSON duplicate-race response')
                continue
            if payload.get('status') == 'success':
                successes += 1
                response.success()
            elif response.status_code == 409 and 'already marked' in payload.get('message', ''):
                response.success()
            else:
                response.failure(payload.get('message', 'unexpected duplicate-race result'))
        if successes != 1:
            raise RuntimeError(f'duplicate guard failed: expected one insert, got {successes}')
        raise StopUser()
