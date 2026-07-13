"""Shared test setup: isolated sqlite DB, CSRF/rate-limits off, one app import."""
import os
import sys
import tempfile

# Must be configured BEFORE importing app (it reads env and builds the DB at import)
_db_fd, _db_path = tempfile.mkstemp(prefix="scanmark_test_", suffix=".db")
os.close(_db_fd)
os.environ['DATABASE_URL'] = f"sqlite:///{_db_path}"
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
# Emails are sent from a background executor; point at a dead local port so
# sends fail instantly instead of hanging the interpreter at exit.
os.environ['MAIL_SERVER'] = '127.0.0.1'
os.environ['MAIL_PORT'] = '1'

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app import app as flask_app, db, limiter, serializer  # noqa: E402


flask_app.config['WTF_CSRF_ENABLED'] = False
flask_app.config['TESTING'] = True
limiter.enabled = False


@pytest.fixture(scope='session')
def app():
    return flask_app


@pytest.fixture(scope='session')
def verify_token():
    """Build the email-verification token exactly like the app does."""
    def _make(email):
        return serializer.dumps(email, salt='email-verify-salt')
    return _make


# NOTE: deliberately no fixture that holds an app context open during tests —
# an active outer app context is reused by test-client requests, which makes
# Flask-Login's per-request current_user cache leak between requests.
