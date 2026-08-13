import os
import io
import atexit
import hmac
import hashlib
import json
import secrets
import sys
import threading
import tempfile
import time
import math
import re
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
load_dotenv()
from authlib.integrations.flask_client import OAuth
from flask import (Flask, render_template, redirect, url_for,
                   flash, request, send_file, jsonify, Response, session)
from markupsafe import escape
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import event, func, inspect, literal, select
from sqlalchemy.exc import (
    IntegrityError, OperationalError, ProgrammingError,
    # NOT the builtin of the same name: SQLAlchemy raises its own class when a
    # request waits out pool_timeout for a connection.
    TimeoutError as PoolTimeoutError,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import joinedload
from sqlalchemy.pool import Pool
import redis
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_compress import Compress
from whitenoise import WhiteNoise
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

from academic import (
    academic_term_of,
    describe_term,
    normalize_academic_year,
    normalize_semester,
)
from localtime import (
    LOCAL_TIMEZONE_NAME,
    format_local,
    iso_utc,
    local_date,
    local_date_only,
    local_day_bounds_utc,
    local_now,
    local_time_only,
    utcnow_naive,
)
from models import (
    db, User, Course, Attendance, AuditLog, ClassSession, SessionRoster,
    course_instructors, enrollments,
)
from performance import BoundedExecutor, InstrumentedQueuePool, runtime_metrics
from campos_integration import (
    CamposIntegrationError,
    declared_environment,
    detected_platform,
    exchange_campos_sso_code,
    is_production_environment,
    map_campos_launch_identity,
    protect_sso_response,
    report_attendance_event,
    rotate_flask_session,
    sanitize_next_path,
    validate_account_binding,
    verify_campos_sso_token,
)

# Windows' legacy console encoding cannot represent some existing log text.
# Keep startup diagnostic output from crashing the process on local machines.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")


def _utcnow():
    return utcnow_naive()


def _env_flag(name, default=False):
    """Read a boolean environment variable without guessing at typos."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in ('true', '1', 'yes', 'on'):
        return True
    if value in ('false', '0', 'no', 'off'):
        return False
    raise RuntimeError(
        f"CRITICAL: {name} must be true or false, got {raw!r}. "
        "Refusing to guess at a security setting."
    )


IS_PRODUCTION = is_production_environment()
DECLARED_ENVIRONMENT = declared_environment() or '(undeclared)'
DETECTED_PLATFORM = detected_platform()


class StartupError(RuntimeError):
    """A misconfiguration that must stop the process rather than degrade it."""


def _require_in_production(condition, message, override_env=None):
    """
    Refuse to boot a production process that is missing something load-bearing.

    Every one of these used to be a printed warning the platform swallowed,
    which is how a deployment ends up 'healthy' on SQLite with no Redis.
    """
    if condition:
        return True
    if not IS_PRODUCTION:
        print(f"[WARN] {message}")
        return False
    if override_env and _env_flag(override_env, False):
        print(f"[WARN] {message} (allowed by {override_env}=true)")
        return False
    raise StartupError(
        f"CRITICAL: {message} "
        + (f"Set {override_env}=true to override deliberately. " if override_env else "")
        + f"(environment={DECLARED_ENVIRONMENT}, platform={DETECTED_PLATFORM or 'unknown'})"
    )


# ============================================================
# SENTRY ERROR MONITORING
# ============================================================
sentry_dsn = os.environ.get('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        
        # Sample a fraction of transactions: tracing/profiling every request
        # adds per-request overhead and burns the Sentry quota during a
        # 2000-scan burst. Raise via env if you need a deep-dive.
        traces_sample_rate=float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '0.1')),

        # Profiles sample rate helps you find CPU bottlenecks (like slow DB queries)
        profiles_sample_rate=float(os.environ.get('SENTRY_PROFILES_SAMPLE_RATE', '0.1')),
        
        environment=os.environ.get('FLASK_ENV', 'production')
    )
    print("🚁 Sentry Monitoring Active")

# ============================================================
# APP INITIALIZATION
# ============================================================

app = Flask(__name__)

print(f"🌍 Environment: {DECLARED_ENVIRONMENT} "
      f"({'PRODUCTION' if IS_PRODUCTION else 'development'})"
      + (f" · platform marker: {DETECTED_PLATFORM}" if DETECTED_PLATFORM else ""))

# --- FIX #14: Crash loudly if SECRET_KEY is missing in production ---
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    if IS_PRODUCTION:
        raise StartupError(
            "CRITICAL: SECRET_KEY environment variable is not set! Refusing to start. "
            f"(environment={DECLARED_ENVIRONMENT}, platform={DETECTED_PLATFORM or 'unknown'}). "
            "Declare SCANMARK_ENV=development if this really is a local machine."
        )
    _secret = 'local_dev_fallback_key_do_not_use_in_prod'
    print("⚠️  WARNING: SECRET_KEY not set. Using insecure fallback for local dev only.")

app.config['SECRET_KEY'] = _secret
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = IS_PRODUCTION
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 🚨 FIX: Silence SQLAlchemy warnings


# ============================================================
# CANONICAL PUBLIC ORIGIN
# ============================================================
# Flask builds `_external=True` URLs from the incoming Host header unless it is
# told otherwise. Verification and password-reset mails are built that way, so
# a request carrying `Host: evil.example` produced an emailed link on
# evil.example — handing the signed token to whoever sent the request. Links
# that leave the process are built from a configured origin instead, and hosts
# nobody configured are refused outright.

def _parse_origin(raw):
    """Split a configured origin into (scheme, host[:port]), or (None, None)."""
    from urllib.parse import urlsplit

    text = (raw or '').strip().rstrip('/')
    if not text:
        return None, None
    if '://' not in text:
        text = 'https://' + text
    parsed = urlsplit(text)
    if not parsed.hostname or parsed.scheme not in ('http', 'https'):
        raise StartupError(
            f"CRITICAL: PUBLIC_ORIGIN must be a full origin such as "
            f"https://scanmark.example, got {raw!r}"
        )
    if parsed.path or parsed.query or parsed.fragment:
        raise StartupError(
            "CRITICAL: PUBLIC_ORIGIN must be an origin without a path"
        )
    return parsed.scheme, parsed.netloc


PUBLIC_ORIGIN_SCHEME, PUBLIC_ORIGIN_HOST = _parse_origin(
    os.environ.get('PUBLIC_ORIGIN')
    # Render exports the deployment's own hostname, which is exactly the
    # canonical origin — use it rather than making every Render deploy
    # duplicate the value by hand.
    or (f"https://{os.environ['RENDER_EXTERNAL_HOSTNAME']}"
        if os.environ.get('RENDER_EXTERNAL_HOSTNAME') else '')
)

_require_in_production(
    bool(PUBLIC_ORIGIN_HOST),
    "PUBLIC_ORIGIN is not set, so emailed links are built from whatever Host "
    "header the request carried.",
    override_env='ALLOW_HOST_HEADER_URLS',
)

#: Hosts this deployment answers to. Anything else is refused before routing.
TRUSTED_HOSTS = {
    host.strip().lower()
    for host in os.environ.get('TRUSTED_HOSTS', '').split(',')
    if host.strip()
}
if PUBLIC_ORIGIN_HOST:
    TRUSTED_HOSTS.add(PUBLIC_ORIGIN_HOST.lower())

if PUBLIC_ORIGIN_HOST:
    # SERVER_NAME would also restrict routing to that host, which breaks
    # health probes that connect by IP, so only the URL-building halves are
    # set here and host filtering is done explicitly below.
    app.config['PREFERRED_URL_SCHEME'] = PUBLIC_ORIGIN_SCHEME


def external_url_for(endpoint, **values):
    """
    Build an absolute URL from the CONFIGURED origin, never from the request.

    Use this for anything that leaves the process — emails above all. Falls
    back to the request-derived URL only where no origin is configured, which
    production refuses to boot without.
    """
    values.pop('_external', None)
    if not PUBLIC_ORIGIN_HOST:
        return url_for(endpoint, _external=True, **values)
    # Build the path with Flask and prefix the configured origin by hand:
    # url_for's absolute form takes its host from SERVER_NAME or the request,
    # which is exactly the input we are refusing to trust here.
    return f"{PUBLIC_ORIGIN_SCHEME}://{PUBLIC_ORIGIN_HOST}{url_for(endpoint, **values)}"


# Probes reach an instance by pod IP or private hostname, not by the public
# name — a platform health check has no reason to know it. They return no user
# data and build no URLs, so there is nothing here for a Host header to
# poison, and refusing them would leave the instance permanently unhealthy in
# exactly the deployments the readiness check exists for.
HOST_CHECK_EXEMPT_PATHS = frozenset({'/healthz', '/livez'})


@app.before_request
def reject_untrusted_host():
    """
    Refuse a request whose Host header names a site we do not serve.

    Without this the header is attacker-controlled input that reaches password
    reset links, absolute redirects and cached responses.
    """
    if not TRUSTED_HOSTS or request.path in HOST_CHECK_EXEMPT_PATHS:
        return None
    host = (request.host or '').lower()
    if host in TRUSTED_HOSTS:
        return None
    # Compare without the port too: a platform may forward :443 explicitly.
    if host.rsplit(':', 1)[0] in {h.rsplit(':', 1)[0] for h in TRUSTED_HOSTS}:
        return None
    app.logger.warning('Refused request for untrusted host %r', host[:100])
    return Response('Unrecognised host.', status=421, mimetype='text/plain')

# FIX #2: Enable CSRF protection globally
csrf = CSRFProtect(app)

# ============================================================
# STATIC FILES & COMPRESSION
# ============================================================

# WhiteNoise serves /static at the WSGI layer (before Flask routing) with
# Cache-Control headers and pre-compressed gzip/brotli variants, so a class
# of phones pulling CSS/logo doesn't occupy Flask request handlers.
_static_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')


def _compute_asset_version():
    """
    A short hash of everything under static/, recomputed at boot.

    Filenames are not content-hashed, so a deploy that changes style.css
    leaves every returning browser — and every installed service worker —
    holding the previous copy at the same URL. That shipped: the signup page
    went out with new markup and the old stylesheet, so the redesigned rows
    rendered as bare list bullets. Templates hang this hash off the URL as
    ?v=, which makes a changed asset a different URL and retires the old one
    everywhere at once.
    """
    digest = hashlib.md5(usedforsecurity=False)
    for directory, _subdirs, filenames in sorted(os.walk(_static_root)):
        for filename in sorted(filenames):
            if filename.endswith(('.gz', '.br')):
                continue        # generated below from these same bytes
            path = os.path.join(directory, filename)
            try:
                with open(path, 'rb') as handle:
                    digest.update(os.path.relpath(path, _static_root).encode())
                    digest.update(handle.read())
            except OSError:
                continue
    return digest.hexdigest()[:12]


#: Bumped implicitly by any change to a static file. Never edit by hand.
ASSET_VERSION = _compute_asset_version()


@app.context_processor
def inject_static_url():
    """`static_url('style.css')` -> '/static/style.css?v=<hash>'."""
    def static_url(filename):
        return f"{url_for('static', filename=filename)}?v={ASSET_VERSION}"
    return {'static_url': static_url, 'asset_version': ASSET_VERSION}


# Generate .gz/.br siblings at boot so WhiteNoise can serve them (it only
# serves compressed variants that already exist on disk). Best-effort: on a
# read-only filesystem the originals are served instead.
try:
    from whitenoise.compress import Compressor
    _compressor = Compressor(quiet=True)
    for _fname in os.listdir(_static_root):
        _fpath = os.path.join(_static_root, _fname)
        if os.path.isfile(_fpath) and _compressor.should_compress(_fname):
            _compressor.compress(_fpath)
except Exception as _e:
    print(f"⚠️ Static pre-compression skipped: {_e}")

class HealthcheckMiddleware:
    """Answer the process probe before Flask opens a session or extension."""

    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __call__(self, environ, start_response):
        # /livez only. /healthz is a readiness check now and has to reach the
        # database and Redis to mean anything, so it goes through Flask.
        if environ.get('PATH_INFO') == '/livez' and environ.get('REQUEST_METHOD') in ('GET', 'HEAD'):
            start_response('204 No Content', [
                ('Content-Length', '0'),
                ('Cache-Control', 'no-store'),
            ])
            return [b'']
        return self.wrapped(environ, start_response)


app.wsgi_app = HealthcheckMiddleware(WhiteNoise(
    app.wsgi_app,
    root=_static_root,
    prefix='static/',
    max_age=int(os.environ.get('STATIC_MAX_AGE', 86400)),
))

# Gzip/brotli-compress dynamic responses (HTML/JSON) — big win on campus
# mobile connections; compressible responses shrink ~70-85%.
Compress(app)


# ============================================================
# SECURITY HEADERS
# ============================================================

# Inline <script>/<style> blocks are used throughout the templates, and the
# dashboards pull Chart.js from a CDN, so the policy has to permit both. It
# still shuts the door on plugins, framing and form posts to other origins.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com "
    "https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

HSTS_MAX_AGE = int(os.environ.get('HSTS_MAX_AGE', 31536000))   # one year


@app.after_request
def set_security_headers(response):
    """
    Baseline hardening on every response. The platform terminates TLS but does
    not add any of these, so without them the app shipped with no HSTS, no
    clickjacking defence and no MIME-sniffing protection.
    """
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)
    response.headers.setdefault(
        'Permissions-Policy',
        # The scan page legitimately needs the camera and GPS; nothing else does.
        'camera=(self), geolocation=(self), microphone=(), payment=()'
    )
    if is_production_environment():
        response.headers.setdefault(
            'Strict-Transport-Security',
            f'max-age={HSTS_MAX_AGE}; includeSubDomains'
        )
    return response


def user_based_rate_limit_key():
    """
    If the user is logged in, use their unique database ID.
    If they are not logged in (e.g., on the signup page), fallback to their IP address.
    """
    if current_user.is_authenticated:
        return f"user_{current_user.id}"
    return get_remote_address()

# ============================================================
# REDIS SESSION CONFIGURATION
# ============================================================

# A copied .env commonly contains REDIS_URL="", which is not a Redis URL.
redis_url = (os.environ.get('REDIS_URL') or '').strip()
redis_client = None
redis_pool = None

# Without Redis the deployment keeps working in a way that looks fine and is
# not: sessions live in cookies, rate limits count per worker process, and the
# lecturer's pinned classroom location sits in one worker's memory — so a
# student's scan is geofenced against it only if it happens to land on the
# same worker.
_require_in_production(
    bool(redis_url),
    "REDIS_URL is not set. Sessions, rate limits and classroom locations "
    "would be per-process and inconsistent across workers.",
    override_env='ALLOW_MISSING_REDIS',
)

if redis_url:
    # An explicit, bounded pool. Left implicit, every gunicorn thread opens
    # connections on demand with no ceiling and no health checking, so a
    # burst multiplies connections against the Redis plan at exactly the
    # moment the class needs them. Sized from the request-slot ceiling
    # (workers x threads) plus headroom for the background executors.
    REDIS_MAX_CONNECTIONS = int(os.environ.get(
        'REDIS_MAX_CONNECTIONS',
        int(os.environ.get('WEB_CONCURRENCY', 4))
        * int(os.environ.get('GUNICORN_THREADS', 8)) + 8,
    ))
    redis_pool = redis.ConnectionPool.from_url(
        redis_url,
        max_connections=REDIS_MAX_CONNECTIONS,
        # A scan must not sit behind a Redis command that will never answer:
        # these are well inside the platform router timeout on purpose.
        socket_connect_timeout=float(os.environ.get('REDIS_CONNECT_TIMEOUT', 2)),
        socket_timeout=float(os.environ.get('REDIS_SOCKET_TIMEOUT', 2)),
        socket_keepalive=True,
        # Recycle a connection that has been idle across a proxy's idle cut.
        health_check_interval=int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 30)),
        retry_on_timeout=True,
    )
    redis_client = redis.Redis(connection_pool=redis_pool)

    # A broken REDIS_URL used to look like a successful boot: nothing touched
    # the connection until the first request needed it.
    try:
        redis_client.ping()
        print("🟢 Redis reachable")
    except redis.RedisError as exc:
        if IS_PRODUCTION and not _env_flag('ALLOW_MISSING_REDIS', False):
            raise StartupError(
                f"CRITICAL: REDIS_URL is configured but unreachable: {exc}"
            ) from exc
        print(f"⚠️  WARNING: Redis is configured but unreachable ({exc}). "
              "Falling back to cookie sessions.")
        redis_client = None
        redis_pool = None
        redis_url = ''

if redis_client is not None:
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REDIS'] = redis_client
    Session(app)
    print("🟢 Redis Sessions Enabled")
else:
    print("🟡 No usable REDIS_URL. Using default cookie sessions (local dev only).")


# ============================================================
# RATE LIMITER
# ============================================================

# Falls back to the documented in-memory store when Redis is absent or turned
# out to be unreachable at boot, instead of handing Flask-Limiter a storage URI
# that will fail on first use.
limiter_storage = redis_url or 'memory://'

# Anonymous requests are keyed by IP, and a whole campus sits behind a handful
# of NAT addresses — so at 5000 students the default per-user allowance is the
# wrong shape for them. One bucket per (IP, endpoint) shared by 5000 phones
# opening /login before a 9am lecture would 429 the login page itself. The
# endpoints where a per-IP cap actually protects something (login POST, signup,
# password reset, verification resend) each carry their own tight limit, which
# applies on top of this, so the shared default can afford to be generous.
ANON_DEFAULT_PER_MINUTE = int(os.environ.get('ANON_RATE_LIMIT_PER_MINUTE', 20000))
ANON_DEFAULT_PER_DAY = int(os.environ.get('ANON_RATE_LIMIT_PER_DAY', 500000))


def _default_rate_limits():
    """Per-user when we know who it is; per-shared-NAT when we don't."""
    if current_user.is_authenticated:
        return "5000 per day;1000 per minute"
    return f"{ANON_DEFAULT_PER_DAY} per day;{ANON_DEFAULT_PER_MINUTE} per minute"


limiter = Limiter(
    app=app,
    key_func=user_based_rate_limit_key,
    storage_uri=limiter_storage,
    default_limits=[_default_rate_limits],
)
print(f"🛡️ Rate Limiter Active (Storage: {limiter_storage.split(':')[0]})")

# ============================================================
# FLASK-MAIL CONFIGURATION
# ============================================================

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME'))
mail = Mail(app)


# ============================================================
# EMAIL UTILITY FUNCTIONS
# ============================================================

# 🚨 THE FIX: Create a bounded pool of workers to handle all emails safely.
# 10 workers: this pool also runs the post-scan notification tasks, and a
# full class marking attendance queues one task per student.
# ScanMark sends exactly two kinds of email: the signup confirmation link and
# a password reset. Both are account access, both are one per person per
# lifetime, and neither happens during a class. Everything else that used to
# send — a confirmation per scan, WhatsApp copies, guardian copies, an
# attendance-threshold warning — is gone, so this pool is small on purpose.
BACKGROUND_QUEUE_MAXSIZE = int(os.environ.get('BACKGROUND_QUEUE_MAXSIZE', 500))

account_email_executor = BoundedExecutor(
    name='account_email',
    max_workers=int(os.environ.get('ACCOUNT_EMAIL_WORKERS')
                    or os.environ.get('BACKGROUND_WORKERS') or 4),
    max_queue=BACKGROUND_QUEUE_MAXSIZE,
    metrics=runtime_metrics,
)

# CampOS attendance delivery is an integration, not a courtesy message: it
# carries the scan into the student's CampOS record. It stays off the request
# path but it is not email, so it is unaffected by the above.
campos_executor = BoundedExecutor(
    name='campos_delivery',
    max_workers=int(os.environ.get('CAMPOS_WORKERS')
                    or os.environ.get('BACKGROUND_WORKERS') or 4),
    max_queue=int(os.environ.get('CAMPOS_QUEUE_SIZE', 2000)),
    metrics=runtime_metrics,
)


@atexit.register
def _shutdown_background_executors():
    # Do not hold process shutdown open for optional outbound work.
    account_email_executor.shutdown(wait=False)
    campos_executor.shutdown(wait=False)


# Percentage a student is expected to reach. Used only to colour the figure
# on their dashboard — nothing is sent when they fall below it.
ATTENDANCE_TARGET_PERCENT = int(os.environ.get('ATTENDANCE_TARGET_PERCENT', 75))

# How many names each class session shows inline on the attendance page. The
# full sheet is a page of its own; rendering every scan of every session in
# one document is what turned a ten-session, 2000-student course into 20,000
# table rows nobody could open.
ATTENDANCE_PREVIEW_ROWS = max(1, int(os.environ.get('ATTENDANCE_PREVIEW_ROWS', 25)))

# How long the lecturer's headcount is cached. This is the ONLY thing that
# bounds how stale the live counter is — nothing invalidates it per scan any
# more, because doing so put a Redis round trip inside all 2,000 requests to
# save at most this many seconds on a number that is visibly moving anyway.
ATTENDEE_SUMMARY_TTL = max(1, int(os.environ.get('ATTENDEE_SUMMARY_TTL', 2)))

# Rows the live projector screen keeps in the DOM. The screen answers "how
# many are in, and who just scanned"; the full sheet is its own paginated
# page. Without a bound, a 2,000-student class ends with 2,000 <li> nodes on
# a laptop that is also driving a projector.
PROJECTOR_RECENT_ROWS = max(5, int(os.environ.get('PROJECTOR_RECENT_ROWS', 50)))


def send_async_email(app_instance, msg):
    """Send email asynchronously to avoid blocking"""
    with app_instance.app_context():
        try:
            mail.send(msg)
            # Recipients are student addresses — count them, don't print them.
            app_instance.logger.info('Email sent to %d recipient(s)', len(msg.recipients))
        except Exception as e:
            app_instance.logger.warning('Failed to send email: %s', e)


def send_email(subject, recipients, text_body, html_body, sender=None):
    msg = Message(
        subject=subject,
        recipients=recipients if isinstance(recipients, list) else [recipients],
        sender=sender or app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = text_body
    msg.html = html_body
    
    # 🚨 THE FIX: Hand the email to the bouncer instead of spawning an infinite thread
    if account_email_executor.submit(send_async_email, app, msg) is None:
        app.logger.warning('notification queue full; email dropped')

def send_welcome_email(user_email, user_name, user_role='student'):
    """
    🚨 SECURITY FIX: Send welcome email WITHOUT password
    Send welcome email to new FUNAAB user
    """
    subject = "Welcome to ScanMark!"

    # Format role for display
    role_display_map = {
        'student': 'Student',
        'lecturer': 'Lecturer',
        'course coordinator': 'Course Coordinator',
        'hod': 'Head of Department',
        'dean': 'Dean',
        'dap': 'Director of Academic Planning'
    }
    role_display = role_display_map.get(
        normalize_role(user_role),
        user_role.title() if user_role else 'Student'
    )

    # Local time: a Nigerian student reading "signed up at 11pm yesterday"
    # because the server thinks in UTC is a support ticket.
    signup_date = local_now().strftime('%d %B %Y at %I:%M %p')

    # Everything below is interpolated into an HTML document. A full name is
    # whatever the person typed into the signup form, so it is attacker-chosen
    # markup until it is escaped — and this message goes to their inbox and,
    # for a guardian copy, to somebody else's.
    safe_name = escape(user_name or '')
    safe_email = escape(user_email or '')
    safe_role = escape(role_display)
    login_link = escape(external_url_for('login'))

    # Plain text version
    text_body = f"""
Hello {user_name},

Welcome to ScanMark! Your account has been created successfully.

Here are your account details:

  Name:        {user_name}
  Email:       {user_email}
  Role:        {role_display}
  Signed up:   {signup_date}

You can now log in to ScanMark using your FUNAAB email and the password you created during signup.

If you didn't create this account, contact IT support immediately.

— The ScanMark Team
Federal University of Agriculture, Abeokuta (FUNAAB)
    """.strip()

    # HTML version
    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Welcome to ScanMark</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
          style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#006838 0%,#198754 100%);padding:36px 40px;text-align:center;">
              <p style="margin:0 0 8px;font-size:36px;">🎓</p>
              <h1 style="margin:0;color:#ffffff;font-size:26px;font-weight:800;letter-spacing:-0.5px;">
                Welcome to ScanMark!
              </h1>
              <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">
                Federal University of Agriculture, Abeokuta
              </p>
            </td>
          </tr>

          <!-- Greeting -->
          <tr>
            <td style="padding:32px 40px 0;">
              <p style="font-size:16px;color:#1a1a1a;margin:0 0 8px;font-weight:700;">
                Hello {safe_name}! 👋
              </p>
              <p style="font-size:14px;color:#555;margin:0 0 28px;line-height:1.6;">
                Your ScanMark account is ready! You can now log in and start marking attendance.
              </p>
            </td>
          </tr>

          <!-- Account Details Table -->
          <tr>
            <td style="padding:0 40px;">
              <table width="100%" cellpadding="0" cellspacing="0"
                style="border:1px solid #e2e8e2;border-radius:8px;overflow:hidden;">
                <tr style="background:#f7faf7;">
                  <td style="padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:1px;color:#006838;text-transform:uppercase;width:130px;border-bottom:1px solid #e2e8e2;">
                    NAME
                  </td>
                  <td style="padding:12px 16px;font-size:14px;color:#1a1a1a;border-bottom:1px solid #e2e8e2;border-left:1px solid #e2e8e2;">
                    {safe_name}
                  </td>
                </tr>
                <tr>
                  <td style="padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:1px;color:#006838;text-transform:uppercase;border-bottom:1px solid #e2e8e2;">
                    EMAIL
                  </td>
                  <td style="padding:12px 16px;font-size:14px;color:#1a1a1a;font-family:'Courier New',monospace;border-bottom:1px solid #e2e8e2;border-left:1px solid #e2e8e2;">
                    {safe_email}
                  </td>
                </tr>
                <tr style="background:#f7faf7;">
                  <td style="padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:1px;color:#006838;text-transform:uppercase;border-bottom:1px solid #e2e8e2;">
                    ROLE
                  </td>
                  <td style="padding:12px 16px;border-bottom:1px solid #e2e8e2;border-left:1px solid #e2e8e2;">
                    <span style="display:inline-block;padding:3px 12px;background:#ffc107;color:#000;border-radius:20px;font-size:12px;font-weight:700;">
                      {safe_role}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:1px;color:#006838;text-transform:uppercase;">
                    SIGNED UP
                  </td>
                  <td style="padding:12px 16px;font-size:14px;color:#1a1a1a;border-left:1px solid #e2e8e2;">
                    {signup_date}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA Button -->
          <tr>
            <td style="padding:28px 40px;text-align:center;">
              <a href="{login_link}"
                style="display:inline-block;padding:14px 36px;background:#006838;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:700;font-size:15px;">
                Login to ScanMark →
              </a>
            </td>
          </tr>

          <!-- Security Notice -->
          <tr>
            <td style="padding:0 40px 28px;">
              <div style="background:#fff8e1;border-left:4px solid #ffc107;padding:14px 16px;border-radius:4px;">
                <p style="margin:0;font-size:13px;color:#555;line-height:1.5;">
                  <strong>⚠️ Security reminder:</strong> Never share your password with anyone.
                  If you didn't create this account, contact IT support immediately.
                </p>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px 40px;border-top:1px solid #e2e8e2;text-align:center;">
              <p style="margin:0;font-size:12px;color:#999;">
                <strong>Federal University of Agriculture, Abeokuta (FUNAAB)</strong><br/>
                © {local_now().year} ScanMark Attendance System · This is an automated message.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    """.strip()
    
    send_email(subject, user_email, text_body, html_body)


# ============================================================
# DATABASE & OAUTH CONFIGURATION
# ============================================================

# 🚨 THE POSTGRES UPGRADE
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

_db_uri = db_url or 'sqlite:///scanmark_v2.db'
app.config['SQLALCHEMY_DATABASE_URI'] = _db_uri

# SQLite is single-writer and, on most PaaS hosts, sits on a disk that is
# wiped on every restart — so "it booted" and "attendance is being kept" are
# different statements. The old warning printed only when FLASK_ENV was
# literally 'production', so on Render it never printed at all.
_require_in_production(
    _db_uri.startswith('postgresql://'),
    "DATABASE_URL is not a PostgreSQL URL. SQLite cannot handle concurrent "
    "scan load and its data is lost on restart.",
    override_env='ALLOW_SQLITE_IN_PRODUCTION',
)

if _db_uri.startswith("postgresql://"):
    # Pool sizing is PER gunicorn worker: the server sees up to
    # workers × (pool_size + max_overflow) connections. With the default
    # 4 workers this is 4 × (5 + 5) = 40 — make sure the Postgres plan
    # allows at least that many, or tune these env vars down.
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "poolclass": InstrumentedQueuePool,
        "pool_size": int(os.environ.get('DB_POOL_SIZE', 5)),
        "max_overflow": int(os.environ.get('DB_MAX_OVERFLOW', 5)),
        "pool_recycle": 1800,
        "pool_timeout": 30,
        "pool_pre_ping": True     # 🚨 THE FIX: Silently tests the connection before running a query
    }
else:
    # SQLite fallback. Fine for local dev, NOT for a real class load:
    # it allows one writer at a time and (on most PaaS hosts) sits on an
    # ephemeral disk that is wiped on every restart/deploy.

    # WAL mode + a generous busy timeout so the multi-worker/multi-thread
    # gunicorn setup doesn't instantly hit "database is locked" in dev.
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_pre_ping": True,
        "connect_args": {"timeout": 30, "check_same_thread": False},
    }

    from sqlalchemy.engine import Engine as _SAEngine

    @event.listens_for(_SAEngine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            # SQLite ignores every FOREIGN KEY it was handed unless asked to
            # enforce them, per connection. With them off, development and CI
            # happily delete a row half of production's constraints forbid —
            # so a referential bug is only ever discovered by students.
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        except Exception:
            pass  # Non-SQLite connection or pragma unsupported — ignore
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', '')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db.init_app(app)

_pool_lock = threading.Lock()
_pool_checked_out = 0


@event.listens_for(Pool, 'connect')
def _pool_connect(_dbapi_connection, _connection_record):
    runtime_metrics.increment('db.pool.connections_opened')


@event.listens_for(Pool, 'checkout')
def _pool_checkout(_dbapi_connection, _connection_record, _connection_proxy):
    """
    Pool DEPTH. How long a request waited for its connection is recorded
    separately by InstrumentedQueuePool as `db.pool.wait` — depth alone cannot
    tell "busy and fine" apart from "every request is queueing", which is the
    difference between raising the worker count and lowering it.
    """
    global _pool_checked_out
    with _pool_lock:
        _pool_checked_out += 1
        depth = _pool_checked_out
    runtime_metrics.gauge('db.pool.checked_out', depth)
    runtime_metrics.increment('db.pool.checkouts')


@event.listens_for(Pool, 'checkin')
def _pool_checkin(_dbapi_connection, _connection_record):
    global _pool_checked_out
    with _pool_lock:
        _pool_checked_out = max(0, _pool_checked_out - 1)
        runtime_metrics.gauge('db.pool.checked_out', _pool_checked_out)


@event.listens_for(Engine, 'before_cursor_execute')
def _query_started(connection, _cursor, _statement, _parameters, _context, _many):
    connection.info.setdefault('scanmark_query_started', []).append(time.perf_counter())


@event.listens_for(Engine, 'after_cursor_execute')
def _query_finished(connection, _cursor, _statement, _parameters, _context, _many):
    starts = connection.info.get('scanmark_query_started')
    if starts:
        runtime_metrics.observe_ms('db.query', (time.perf_counter() - starts.pop()) * 1000)
        runtime_metrics.increment('db.queries')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Keep students signed in across browser restarts (remember-me cookie).
# Without this every closed browser meant a fresh login — which is what
# created the before-class login stampede and its scrypt-hashing CPU cost.
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(
    days=int(os.environ.get('REMEMBER_COOKIE_DAYS', 30))
)
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
# REMEMBER_COOKIE_SECURE is set once, with the session cookie, from the same
# decision. It used to be re-assigned here from a raw FLASK_ENV comparison,
# which on Render (RENDER=true, FLASK_ENV unset) silently downgraded a
# 30-day credential to a cookie that travels over plain HTTP.


# ============================================================
# FUNAAB EMAIL VALIDATION
# ============================================================

FUNAAB_DOMAIN = 'funaab.edu.ng'
STAFF_DOMAIN = '@staff.' + FUNAAB_DOMAIN

# Roles a stranger may hand themselves by filling in the public signup form.
# The keys are the normalised form the form may submit; the values are the
# canonical spelling stored on the User row. Privileged posts (hod, dean, dap)
# are deliberately absent: they carry cross-course and institution-wide read
# access, so they only ever arrive from a signed CampOS launch identity or a
# deliberate change by someone who already holds the database.
SELF_SERVICE_STAFF_ROLES = {
    'lecturer': 'Lecturer',
    'course coordinator': 'Course Coordinator',
}

# Minimum password length for accounts ScanMark itself authenticates.
MIN_PASSWORD_LENGTH = int(os.environ.get('MIN_PASSWORD_LENGTH', 10))

# Self-service STUDENT accounts must confirm their address before the password
# works; staff sign-ups are usable immediately (see VERIFICATION_REQUIRED_ROLES).
# Defaults on in production and off elsewhere, so a local checkout without SMTP
# still logs in. Never disable it in production: the signup form accepts any
# address, and the link is the only thing standing between a stranger and an
# account in somebody else's name.
REQUIRE_EMAIL_VERIFICATION = (
    os.environ.get('REQUIRE_EMAIL_VERIFICATION', '').strip().lower()
    or ('true' if IS_PRODUCTION else 'false')
) not in ('false', '0', 'no', 'off')

#: The rule, in the words the forms show the user. Server and page cannot
#: drift apart because both render this string.
PASSWORD_POLICY_TEXT = (
    f"At least {MIN_PASSWORD_LENGTH} characters, including at least one "
    "letter and one number."
)


def validate_password_strength(password):
    """Return None when acceptable, else a message explaining what's missing.

    The old rule refused a password only when it was ENTIRELY digits or
    ENTIRELY letters, so 'aaaaaaaaa!' passed with no number in it and
    '!!!!!!!!!!' passed with neither letter nor number — while the signup page
    promised letters and numbers. Check for what is actually required.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if not any(character.isalpha() for character in password):
        return "Password must contain at least one letter."
    if not any(character.isdigit() for character in password):
        return "Password must contain at least one number."
    return None


@app.context_processor
def inject_password_policy():
    """So the signup/reset forms advertise the same rule the server enforces."""
    return {'min_password_length': MIN_PASSWORD_LENGTH,
            'password_policy_text': PASSWORD_POLICY_TEXT}


@app.context_processor
def inject_display_helpers():
    """Local-time formatting for every template (the columns are naive UTC)."""
    return {
        'local_dt': format_local,
        'local_time': local_time_only,
        'local_date': local_date_only,
        'local_timezone_name': LOCAL_TIMEZONE_NAME,
    }


app.jinja_env.filters['local_dt'] = format_local
app.jinja_env.filters['local_time'] = local_time_only
app.jinja_env.filters['local_date'] = local_date_only


def is_valid_funaab_email(email):
    """
    Check if email is a valid FUNAAB email address OR a standard Gmail.

    Returns (is_valid, message, default_role). The role here is only the
    STARTING point for a self-service signup: a staff address defaults to
    'lecturer' and may narrow to another self-service role, but no address
    can ever mint a privileged role on its own — see SELF_SERVICE_STAFF_ROLES.
    """
    if not email:
        return False, "Email is required", None

    # Basic email format validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format", None

    email = email.lower().strip()

    domain = email.rsplit('@', 1)[-1]

    if email.endswith(STAFF_DOMAIN):
        return True, "Valid email", 'lecturer'
    # The bare domain AND its subdomains — student.funaab.edu.ng is what most
    # undergraduates actually hold. Matching on the parsed domain (not a bare
    # endswith on the whole address) keeps a lookalike like
    # "evilfunaab.edu.ng" out.
    if domain == FUNAAB_DOMAIN or domain.endswith('.' + FUNAAB_DOMAIN):
        return True, "Valid email", 'student'
    # Gmail is allowed, but strictly as a student.
    if domain == 'gmail.com':
        return True, "Valid email", 'student'

    return False, "Only FUNAAB (@funaab.edu.ng) or Gmail (@gmail.com) addresses are allowed.", None

def extract_name_from_funaab_email(email):
    """
    Extract name from FUNAAB email (optional helper)
    Example: john.doe@student.funaab.edu.ng -> John Doe
    """
    try:
        username = email.split('@')[0]
        # Replace dots and underscores with spaces
        name_parts = username.replace('.', ' ').replace('_', ' ').split()
        # Capitalize each part
        return ' '.join(word.capitalize() for word in name_parts)
    except Exception:
        return ""


# ============================================================
# INPUT SANITISATION
# ============================================================

#: Anything in the C0/C1 control ranges. A newline inside a course code ends
#: up in a Content-Disposition header, where werkzeug refuses it and the
#: export 500s; the rest are invisible characters that make two codes that
#: look identical compare unequal.
_CONTROL_CHARACTERS = re.compile(r'[\x00-\x1f\x7f-\x9f]')

#: What a course code may contain, once trimmed.
_COURSE_CODE_ALLOWED = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 \-]*$')


def _clean_text(value, max_length):
    """Strip control characters and collapse whitespace, then truncate."""
    text = _CONTROL_CHARACTERS.sub(' ', str(value or ''))
    return ' '.join(text.split())[:max_length]


def _clean_course_code(value):
    """
    Normalise a course code, or return '' when it is not one.

    Codes are printed into filenames and HTTP headers, so they are validated
    on the way in rather than escaped at every point of use.
    """
    code = _clean_text(value, 10).upper()
    return code if code and _COURSE_CODE_ALLOWED.fullmatch(code) else ''


def _safe_filename(value, fallback='download'):
    """
    An ASCII filename safe to place in a Content-Disposition header.

    Everything outside a conservative allowlist becomes an underscore, so a
    stray character in stored data cannot break the header — or inject a
    second one.
    """
    cleaned = re.sub(r'[^A-Za-z0-9._-]+', '_', _clean_text(value, 80)).strip('._-')
    return cleaned or fallback


def _attachment_headers(filename):
    """Content-Disposition for an attachment, with the filename made safe."""
    return {'Content-Disposition': f'attachment; filename="{_safe_filename(filename)}"'}


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates using the Haversine formula."""
    R = 6371000  # Radius of Earth in metres
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ------------------------------------------------------------------
# FIX #4: Class locations stored in Redis, not a global dict
# ------------------------------------------------------------------

def _redis_timed(operation, function, *args, **kwargs):
    started = time.perf_counter()
    try:
        return function(*args, **kwargs)
    finally:
        runtime_metrics.observe_ms(
            f'redis.{operation}', (time.perf_counter() - started) * 1000
        )
        runtime_metrics.increment(f'redis.{operation}')

# A classroom belongs to a MEETING, not to a course. The same course legitimately
# runs in different rooms on the same day — the lecture in the theatre, the
# tutorial in a computer lab, the makeup class wherever was free — and a
# course-scoped pin geofences all of them against whichever room was pinned
# last. Keyed by session id, it is also self-cleaning: the key dies with the
# meeting instead of lingering to catch the next one.
CLASS_LOCATION_TTL = int(os.environ.get('CLASS_LOCATION_TTL', 14400))   # 4 hours


def set_class_location(session_id, lat, lon):
    """Store the lecturer's pinned classroom for ONE class session."""
    if redis_client:
        _redis_timed(
            'setex', redis_client.setex,
            f"class_location:session:{session_id}", CLASS_LOCATION_TTL,
            f"{lat},{lon}"
        )
    else:
        # Local-dev fallback: module-level dict (single process only)
        _local_locations[session_id] = {'lat': lat, 'lon': lon}


def _parse_location(raw):
    try:
        lat_str, lon_str = raw.decode().split(',')
        return {'lat': float(lat_str), 'lon': float(lon_str)}
    except (AttributeError, UnicodeDecodeError, ValueError):
        return None


def get_class_location(session_id, course_id=None):
    """
    The pinned classroom for this meeting.

    Falls back to the old course-scoped key so a class already running through
    a rolling deploy keeps its pin instead of suddenly having none — which,
    with GEOFENCE_REQUIRED on, would refuse every remaining scan in the room.
    """
    if not redis_client:
        found = _local_locations.get(session_id)
        if found is None and course_id is not None:
            found = _local_locations.get(f"course:{course_id}")
        return found

    value = _redis_timed('get', redis_client.get,
                         f"class_location:session:{session_id}")
    if value:
        return _parse_location(value)
    if course_id is not None:
        legacy = _redis_timed('get', redis_client.get,
                              f"class_location:{course_id}")
        if legacy:
            return _parse_location(legacy)
    return None


# Local-dev fallback only (never used when Redis is available)
_local_locations = {}


def _enrolled_count(course_id):
    """
    COUNT of students enrolled in a course RIGHT NOW, straight off the
    enrollments table. Use this instead of len(course.students), which
    materialises every enrolled User row (2000 ORM objects) just to take its
    length.

    This is the live roster. It is the right denominator for "how full is this
    class today" and the WRONG one for any historical percentage — use
    _session_expected_counts() for those.
    """
    return (db.session.query(func.count(enrollments.c.user_id))
            .filter(enrollments.c.course_id == course_id)
            .scalar()) or 0


def _session_expected_counts(session_ids):
    """
    ``{session_id: how many students were on the roster that day}``.

    The snapshot taken when the meeting opened, not today's enrolment.
    """
    session_ids = list(session_ids)
    if not session_ids:
        return {}
    rows = (db.session.query(SessionRoster.session_id,
                             func.count(SessionRoster.student_id))
            .filter(SessionRoster.session_id.in_(session_ids))
            .group_by(SessionRoster.session_id)
            .all())
    return {session_id: count for session_id, count in rows}


def _expected_sessions_for_students(course_id, student_ids):
    """
    ``{student_id: classes they were enrolled for}`` in one course.

    A student who joined in week 6 was never expected at weeks 1-5, so those
    meetings are not counted against them.
    """
    student_ids = list(student_ids)
    if not student_ids:
        return {}
    rows = (db.session.query(SessionRoster.student_id,
                             func.count(SessionRoster.session_id))
            .filter(SessionRoster.course_id == course_id,
                    SessionRoster.student_id.in_(student_ids))
            .group_by(SessionRoster.student_id)
            .all())
    return {student_id: count for student_id, count in rows}


def _attendance_percentage(attended, expected):
    """Percentage, or None when no class was ever expected of this student."""
    if not expected:
        return None
    # Capped because a roster can still be edited by hand in the database;
    # a register that reads 104% is a bug report, not a statistic.
    return min(100, round(attended / expected * 100))


# ------------------------------------------------------------------
# FIX #3 & #6: Signed, cached QR tokens
# ------------------------------------------------------------------

QR_TOKEN_TTL = int(os.environ.get('QR_TOKEN_TTL', 12))   # seconds a token stays valid in Redis
# Seconds before the attendance endpoint rejects the token. Deliberately
# wider than the 12s on-screen rotation: expiry is checked when the request
# is PROCESSED, not when the student scanned, and during a full-class burst
# a legitimate scan can wait ~30s (the platform router timeout) in the queue.
# Without the headroom those queued scans bounce as "expired" and the
# clients retry, amplifying the burst.
#
# It is also the replay window: for this many seconds a photograph of the
# projected code will mark somebody present, so it trades integrity against
# not failing legitimate scans under load. Narrow it only alongside a
# measured p99 that fits inside the smaller window, and keep the geofence
# on (see GEOFENCE_REQUIRED) as the primary presence check.
QR_CODE_WINDOW = int(os.environ.get('QR_CODE_WINDOW', 45))

# Longest a scan may sit between the student's camera reading the code and the
# server processing it. This is the actual replay window for a photograph of
# the projected code, and it is checked against the CLIENT's capture time, so
# a queued offline scan is still judged on when it was taken rather than on
# when the phone got signal back.
QR_CAPTURE_WINDOW = int(os.environ.get('QR_CAPTURE_WINDOW', QR_CODE_WINDOW))

# Whether a scan must say when its camera read the code. On by default: the
# check is worthless if leaving the field out is how you skip it. The switch
# exists only for the window in which offline scans queued by a service worker
# from before this release are still draining.
REQUIRE_CAPTURED_AT = _env_flag('REQUIRE_CAPTURED_AT', True)

# Max distance (metres) between the lecturer's pinned class location and the
# scanning student. The old route hard-coded 50 while its message referenced
# the configurable 100m value. One authoritative value prevents policy drift.
# balances anti-cheating with real-world phone GPS error inside buildings.
GEOFENCE_RADIUS_M = int(os.environ.get('GEOFENCE_RADIUS_M', 100))

# When a lecturer never pins a classroom location — they dismissed the
# browser's GPS prompt, or the projector machine has no location service —
# get_class_location() returns None and there is nothing to measure against.
#
# This now defaults ON. Off, the failure mode is silent and total: the class
# is recorded with no proximity requirement whatsoever and nothing on the
# register says so afterwards, so a lecturer who dismissed one browser prompt
# has been marking a term's worth of attendance that anyone could have
# submitted from anywhere. Refusing the scan is loud, immediate and fixable in
# ten seconds by granting location on the QR screen. Set GEOFENCE_REQUIRED
# =false to accept unverifiable scans deliberately.
GEOFENCE_REQUIRED = _env_flag('GEOFENCE_REQUIRED', True)

# Reported GPS accuracy beyond which a reading proves nothing: a fix with a
# 2km error radius "inside" a 100m geofence is not evidence of presence.
#
# Deliberately NOT used to widen the fence. Treating the near edge of the
# error circle as the student's position would mean a phone reporting the
# worst permitted accuracy is accepted a further GEOFENCE_MAX_ACCURACY_M out
# — and accuracy is a self-reported number, so that is a free pass for the
# asking. GEOFENCE_RADIUS_M is already sized for indoor GPS drift; an
# imprecise fix is refused outright instead.
GEOFENCE_MAX_ACCURACY_M = int(
    os.environ.get('GEOFENCE_MAX_ACCURACY_M') or GEOFENCE_RADIUS_M
)

# Oldest position fix a scan may carry. A phone will happily hand back a
# cached fix from hours ago and somewhere else entirely.
GEOFENCE_MAX_LOCATION_AGE_MS = int(
    os.environ.get('GEOFENCE_MAX_LOCATION_AGE_MS', 30000)
)


def _make_signature(message: str) -> str:
    """Return a 16-char HMAC-SHA256 hex signature."""
    return hmac.new(
        app.config['SECRET_KEY'].encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:16]


def generate_signed_qr(session_id: int) -> str:
    """
    Generate a signed QR payload for one CLASS SESSION and cache it in Redis
    so that /api/qr_data and the live image endpoint always return the SAME
    token. Format: "S<session_id>|timestamp|hmac_sig"

    Tokens are scoped to a ClassSession (one class meeting), not the course,
    so every scan lands in the record set of that specific lecture.
    """
    cache_key = f"qr_token:session:{session_id}"

    if redis_client:
        cached = _redis_timed('get', redis_client.get, cache_key)
        if cached:
            return cached.decode()

    # Create a new token
    timestamp = int(time.time())
    message = f"S{session_id}|{timestamp}"
    sig = _make_signature(message)
    token = f"{message}|{sig}"

    if redis_client:
        _redis_timed('setex', redis_client.setex, cache_key, QR_TOKEN_TTL, token)

    return token


def verify_signed_qr(qr_text: str):
    """
    Verify the QR payload signature and expiry.
    Returns (session_id, timestamp) on success, or raises ValueError.
    """
    if not isinstance(qr_text, str) or len(qr_text) > 256:
        raise ValueError("Invalid QR code format.")

    parts = qr_text.split('|')
    if len(parts) != 3:
        raise ValueError("Invalid QR code format.")

    session_part, timestamp_str, received_sig = parts
    message = f"{session_part}|{timestamp_str}"
    expected_sig = _make_signature(message)

    if not hmac.compare_digest(received_sig, expected_sig):
        raise ValueError("QR code signature is invalid.")

    if not session_part.startswith('S') or not session_part[1:].isdigit():
        raise ValueError("Invalid QR code format.")

    try:
        timestamp = int(timestamp_str)
    except ValueError as exc:
        raise ValueError("Invalid QR code format.") from exc
    age = int(time.time()) - timestamp
    if age < -5:
        raise ValueError("QR code timestamp is invalid.")
    if age > QR_CODE_WINDOW:
        raise ValueError("QR code has expired. Please scan again.")

    return int(session_part[1:]), timestamp


# ------------------------------------------------------------------
# FIX #11: Optimised analytics (single query, no N+1)
# ------------------------------------------------------------------
# (get_course_analytics() lived here and had no callers — /course/<id>/analytics
# builds its per-session series inline. Removed rather than left to rot.)


def get_department_analytics(dept_name, academic_year=None, semester=None):
    """
    Comparative attendance for an HOD, as the PERCENTAGE the chart claims to
    show.

    The chart is labelled "Average Attendance %" with its axis capped at 100,
    and it used to be fed a raw count of scans: a 900-student course with
    three lectures reported 2700, which the axis clipped to a bar identical to
    every other large course. The number a percentage axis needs is
    ``scans ÷ places on the roster``, and the roster has to be the snapshot
    taken at each meeting, or a course whose enrolment changed reads above
    100%.
    """
    if not dept_name:
        # An HOD who has not been placed in a department presides over
        # nothing. `Course.department == None` would match every course that
        # also has no department, which is the opposite of nothing.
        return {"labels": [], "data": [], "meta": []}

    courses = (Course.query
               .filter(Course.department == dept_name,
                       Course.archived.is_(False))
               .filter(*_term_filters(academic_year, semester))
               .order_by(Course.code.asc())
               .all())
    if not courses:
        return {"labels": [], "data": [], "meta": []}

    course_ids = [course.id for course in courses]

    attended = dict(
        db.session.query(Attendance.course_id, func.count(Attendance.id))
        .filter(Attendance.course_id.in_(course_ids),
                Attendance.session_id.isnot(None))
        .group_by(Attendance.course_id)
        .all())
    expected = dict(
        db.session.query(SessionRoster.course_id,
                         func.count(SessionRoster.student_id))
        .filter(SessionRoster.course_id.in_(course_ids))
        .group_by(SessionRoster.course_id)
        .all())
    sessions_held = dict(
        db.session.query(ClassSession.course_id, func.count(ClassSession.id))
        .filter(ClassSession.course_id.in_(course_ids))
        .group_by(ClassSession.course_id)
        .all())

    labels, data, meta = [], [], []
    for course in courses:
        places = expected.get(course.id, 0)
        present = attended.get(course.id, 0)
        labels.append(course.code)
        data.append(_attendance_percentage(present, places) or 0)
        meta.append({
            'code': course.code,
            'title': course.title,
            'course_id': course.id,
            'sessions': sessions_held.get(course.id, 0),
            'present': present,
            'expected': places,
        })

    return {"labels": labels, "data": data, "meta": meta}


def _term_filters(academic_year=None, semester=None):
    """SQLAlchemy filters narrowing Course to one term, if one was named."""
    filters = []
    if academic_year:
        filters.append(Course.academic_year == academic_year)
    if semester:
        filters.append(Course.semester == semester)
    return filters


def _requested_term():
    """
    The term the viewer is looking at: whatever they asked for in the query
    string, else the one the calendar is in now.

    Reports are scoped to a term by default. Without this, every percentage on
    every dashboard silently accumulates across years — last session's
    lectures dragging down this session's figures forever.
    """
    year = normalize_academic_year(request.args.get('academic_year'))
    semester = normalize_semester(request.args.get('semester'))
    if request.args.get('academic_year', '').strip().lower() == 'all':
        return None, None
    default_year, default_semester = academic_term_of()
    return year or default_year, semester or default_semester


def _known_terms():
    """Every term that actually has courses, newest first, for the pickers."""
    rows = (db.session.query(Course.academic_year, Course.semester)
            .distinct()
            .order_by(Course.academic_year.desc(), Course.semester.asc())
            .all())
    return [{'academic_year': year, 'semester': semester,
             'label': describe_term(year, semester)}
            for year, semester in rows]


# ============================================================
# SERVICE WORKER
# ============================================================

@app.route('/service-worker.js')
def serve_sw():
    """
    Serve the worker with the server's own QR acceptance window baked in.

    The offline queue has to know how long a scanned token stays redeemable,
    otherwise it promises to retry scans the server will certainly refuse —
    which is what used to happen: it held them for five minutes against a
    45-second window and then deleted them without telling anyone.

    The asset hash goes in the same way, and it is what makes this file
    byte-different after a deploy that touched static/. That difference is
    what makes the browser install the new worker, which names its cache
    after the hash and drops the previous one.
    """
    worker_path = os.path.join(_static_root, 'service-worker.js')
    try:
        with open(worker_path, encoding='utf-8') as handle:
            body = handle.read()
    except OSError:
        app.logger.exception('Could not read the service worker')
        return '', 404
    prelude = (f'self.SCANMARK_QR_WINDOW_SECONDS = {QR_CODE_WINDOW};\n'
               f'self.SCANMARK_ASSET_VERSION = "{ASSET_VERSION}";\n')
    return Response(
        prelude + body,
        mimetype='application/javascript',
        # The worker carries a server-side constant now, so it must not be
        # pinned in an HTTP cache across a config change.
        headers={'Cache-Control': 'no-cache'},
    )


# ============================================================
# USER LOADER  (FIX #12: use db.session.get instead of Query.get)
# ============================================================

@login_manager.user_loader
def load_user(user_id):
    """
    Resolve the signed-in user from "<id>|<security stamp>".

    The stamp is what makes a credential revocable. A session record in Redis
    and a 30-day remember-me cookie are both just this string; when the stamp
    on the row changes — a password reset, a recovered account — every
    credential minted before it stops resolving here.
    """
    raw_id, _, stamp = str(user_id).partition('|')
    try:
        user = db.session.get(User, int(raw_id))
    except (TypeError, ValueError):
        return None
    if user is None:
        return None
    # A cookie issued before this column existed carries no stamp, and matches
    # only while the account has never rotated one.
    if (user.security_stamp or '') != stamp:
        return None
    return user


def rotate_security_stamp(user):
    """Invalidate every session and remember-me cookie issued for this user."""
    user.security_stamp = secrets.token_hex(16)
    return user.security_stamp


# ============================================================
# ROLE NORMALISATION
# ============================================================
# The database holds 'Lecturer' from self-signup, 'lecturer' from a CampOS
# launch and 'Course Coordinator' from the signup form. Every comparison goes
# through here, because a `role == 'lecturer'` test somewhere else is how the
# dean's dashboard came to count only the lowercase half of its own faculty.

STUDENT_ROLE = 'student'
LECTURER_ROLE = 'lecturer'
COORDINATOR_ROLE = 'course coordinator'
HOD_ROLE = 'hod'
DEAN_ROLE = 'dean'
DAP_ROLE = 'dap'

#: Canonical spelling stored on new rows, keyed by normalised role.
CANONICAL_ROLE_NAMES = {
    STUDENT_ROLE: 'Student',
    LECTURER_ROLE: 'Lecturer',
    COORDINATOR_ROLE: 'Course Coordinator',
    HOD_ROLE: 'HOD',
    DEAN_ROLE: 'Dean',
    DAP_ROLE: 'DAP',
}

#: Roles that teach: both may run a class, only a coordinator owns one.
TEACHING_ROLES = (LECTURER_ROLE, COORDINATOR_ROLE)

ROLE_DASHBOARDS = {
    STUDENT_ROLE: 'student_dashboard',
    LECTURER_ROLE: 'lecturer_dashboard',
    COORDINATOR_ROLE: 'lecturer_dashboard',
    HOD_ROLE: 'hod_dashboard',
    DEAN_ROLE: 'dean_dashboard',
    DAP_ROLE: 'dap_dashboard',
}


def normalize_role(role):
    """'  Course Coordinator ' -> 'course coordinator'."""
    return (role or '').lower().strip()


def user_has_role(user, *roles):
    return normalize_role(getattr(user, 'role', None)) in roles


def role_matches(column):
    """
    A SQL predicate matching a role however it happens to be capitalised.

    ``User.role == 'lecturer'`` counts only the accounts CampOS created and
    silently drops every self-signup, which stores 'Lecturer'.
    """
    def _predicate(*roles):
        return func.lower(func.trim(column)).in_([normalize_role(r) for r in roles])
    return _predicate


role_is = role_matches(User.role)


# ============================================================
# 🚨 FIX: SAFE REDIRECT BY ROLE (NO LOOPS!)
# ============================================================

def redirect_by_role(role: str):
    """
    Send a user to the dashboard their role actually has.

    An unrecognised role used to be sent to the student dashboard, which
    bounced it to /login, which sent it back — /dashboard → /student_dashboard
    → /login → /student_dashboard, forever, with no way out of the browser.
    A role with no dashboard now lands on a page that explains that and offers
    a way to sign out.
    """
    target = ROLE_DASHBOARDS.get(normalize_role(role))
    if target is None:
        return redirect(url_for('account_pending'))
    return redirect(url_for(target))


def require_role(*roles):
    """
    Guard a dashboard. Returns a redirect response, or None when allowed.

    Sending the wrong role to their OWN dashboard is the only safe bounce: to
    /login would be a loop for anyone whose role has no dashboard at all.
    """
    if user_has_role(current_user, *roles):
        return None
    flash("Access denied. Redirecting to your dashboard.", "warning")
    return redirect_by_role(current_user.role)


@app.route('/account_pending')
@login_required
def account_pending():
    """
    Terminal page for an account whose role has no dashboard.

    Deliberately not a redirect to anything: it is the end of the chain.
    """
    if normalize_role(current_user.role) in ROLE_DASHBOARDS:
        return redirect_by_role(current_user.role)
    app.logger.warning('User id=%s holds unrecognised role %r',
                       current_user.id, (current_user.role or '')[:40])
    return render_template('account_pending.html',
                           role=current_user.role or 'none'), 403


# ============================================================
# AUDIT TRAIL
# ============================================================

def record_audit(action, target_type=None, target_id=None, target_label=None,
                 course_id=None, **details):
    """
    Write one append-only line about a destructive or privileged action.

    Deleting a course or a class session destroys attendance nobody can
    reconstruct. Whatever else happens, the fact that it happened, and who did
    it, survives — the table carries no foreign keys precisely so that it
    outlives the rows it describes.

    Never raises: an audit write that fails must not take the operation with
    it, but it must be loud in the log.
    """
    try:
        entry = AuditLog(
            actor_id=getattr(current_user, 'id', None),
            actor_email=getattr(current_user, 'email', None),
            actor_role=getattr(current_user, 'role', None),
            action=action,
            target_type=target_type,
            target_id=target_id,
            course_id=course_id,
            target_label=(str(target_label)[:200] if target_label else None),
            details=json.dumps(details, default=str) if details else None,
            ip_address=(request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                        or request.remote_addr or '')[:45] or None,
            user_agent=(request.headers.get('User-Agent') or '')[:200] or None,
        )
        db.session.add(entry)
        db.session.flush()
        app.logger.info('audit %s', json.dumps({
            'action': action,
            'actor_id': entry.actor_id,
            'target': f'{target_type}:{target_id}',
            'label': entry.target_label,
        }, separators=(',', ':')))
        return entry
    except Exception:
        app.logger.exception('Failed to write audit entry for %s', action)
        return None


# ============================================================
# EMAIL VERIFICATION
# ============================================================

EMAIL_VERIFY_MAX_AGE = 24 * 60 * 60   # link is good for a day

#: Roles whose password stays locked until the address is confirmed.
#: Only students: a class is hundreds of self-registered strangers, and the
#: link is what stops one of them registering under somebody else's name.
#: Staff sign-ups (Lecturer, Course Coordinator) are a handful of people who
#: are known to their department and are needed in front of a class today, so
#: their account works the moment it exists. They are still SENT the link —
#: confirming still clears the "unproven address" flag CampOS/Google adoption
#: reads — but nothing waits on it.
VERIFICATION_REQUIRED_ROLES = (STUDENT_ROLE,)


def role_requires_email_verification(role):
    """True when an account of this role may not sign in until confirmed."""
    return normalize_role(role) in VERIFICATION_REQUIRED_ROLES


def account_needs_verification(user):
    """True when this specific account is being held back by an unconfirmed
    address — the switch is on, the flag is unset, AND the role is gated."""
    return (REQUIRE_EMAIL_VERIFICATION
            and getattr(user, 'email_verified', None) is False
            and role_requires_email_verification(getattr(user, 'role', None)))


@app.context_processor
def inject_verification_policy():
    """So the signup page tells each visitor what actually applies to them,
    rather than promising a gate that a staff account never meets."""
    return {'email_verification_required': REQUIRE_EMAIL_VERIFICATION}


def send_verification_email(user):
    """Mail a signed, single-use confirmation link to a new self-service account."""
    token = serializer.dumps(user.email, salt='email-verify-salt')
    # Built from the configured origin, never from the request's Host header:
    # this link carries a signed token that verifies an account.
    verify_url = external_url_for('verify_email', token=token)
    msg = Message(
        "Confirm your ScanMark email",
        recipients=[user.email],
        sender=app.config['MAIL_DEFAULT_SENDER'],
    )
    # Say which of the two things this link actually is, so a lecturer who is
    # already signed in is not told to wait for an email they don't need.
    if account_needs_verification(user):
        closing = ("If you did not create a ScanMark account, ignore this "
                   "email — no account can be used until this link is "
                   "opened.\n")
    else:
        closing = ("Your account already works — signing in does not wait for "
                   "this link. Opening it just confirms the address is "
                   "yours.\n\n"
                   "If you did not create a ScanMark account, tell your "
                   "department: somebody registered using your address.\n")
    msg.body = (
        f"Hello {user.full_name},\n\n"
        "Confirm your ScanMark account by opening the link below "
        "(valid for 24 hours):\n\n"
        f"{verify_url}\n\n"
        + closing
    )
    if account_email_executor.submit(send_async_email, app, msg) is None:
        app.logger.warning('notification queue full; verification email dropped')


@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify-salt',
                                 max_age=EMAIL_VERIFY_MAX_AGE)
    except Exception:
        flash("That verification link is invalid or has expired. "
              "Sign in to request a new one.", "error")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("That verification link is invalid or has expired.", "error")
        return redirect(url_for('login'))

    if user.email_verified is not True:
        user.email_verified = True
        db.session.commit()
        app.logger.info('Email verified for user id=%s', user.id)

    flash("Email confirmed! You can now sign in.", "success")
    return redirect(url_for('login'))


@app.route('/resend_verification', methods=['POST'])
@limiter.limit(
    "3 per hour",
    key_func=lambda: f"verify:{get_remote_address()}:"
                     f"{(request.form.get('email') or '').strip().lower()}",
    error_message="Too many requests. Please try again later."
)
def resend_verification():
    email = (request.form.get('email') or '').strip().lower()
    user = User.query.filter_by(email=email).first()
    # Only ever send to an account that actually needs it, but say the same
    # thing either way so this cannot be used to test which addresses exist.
    if user and user.email_verified is False:
        send_verification_email(user)
    flash("If that account still needs confirming, a new link is on its way.", "info")
    return redirect(url_for('login'))


# ============================================================
# PASSWORD RESET
# ============================================================

RESET_TOKEN_MAX_AGE = 900   # 15 minutes


def _password_fingerprint(password_hash):
    """
    Short HMAC of the stored password hash. Embedding it in a reset token
    makes that token single-use: the moment the password changes the
    fingerprint changes with it, so a link cannot be replayed inside its
    15-minute window (nor can an old link undo a newer reset).
    """
    return _make_signature(f"pwreset:{password_hash}")


@app.route('/forgot_password', methods=['GET', 'POST'])
# Unauthenticated and it sends mail, so it is both an enumeration probe and a
# way to spam somebody's inbox. Keyed per (IP, address).
@limiter.limit(
    "5 per hour;20 per day",
    methods=["POST"],
    key_func=lambda: f"forgot:{get_remote_address()}:"
                     f"{(request.form.get('email') or '').strip().lower()}",
    error_message="Too many password reset requests. Please try again later."
)
def forgot_password():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        user = User.query.filter_by(email=email).first()

        if user:
            token = serializer.dumps(
                {'email': user.email, 'pw': _password_fingerprint(user.password)},
                salt='password-reset-salt',
            )
            reset_url = external_url_for('reset_password', token=token)

            msg = Message(
                "Reset Your ScanMark Password",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[user.email]
            )
            msg.body = (
                f"Hello {user.full_name},\n\n"
                "We received a request to reset your ScanMark password.\n"
                f"Click the link below (valid for 15 minutes):\n\n{reset_url}\n\n"
                "If you did not make this request, ignore this email.\n"
            )
            # Use the bounded notification executor instead of a per-request thread.
            if account_email_executor.submit(send_async_email, app, msg) is None:
                app.logger.warning('notification queue full; reset email dropped')

        # Always show the same message to prevent email enumeration
        flash("If an account with that email exists, a password reset link has been sent.", "info")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


def _load_reset_token(token):
    """Return the User a still-valid reset token names, else None."""
    try:
        payload = serializer.loads(token, salt='password-reset-salt',
                                   max_age=RESET_TOKEN_MAX_AGE)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None   # a link minted before tokens carried a fingerprint
    user = User.query.filter_by(email=payload.get('email')).first()
    if not user:
        return None
    if not hmac.compare_digest(payload.get('pw') or '',
                               _password_fingerprint(user.password)):
        return None   # already redeemed, or the password changed since
    return user


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"], key_func=get_remote_address,
               error_message="Too many attempts. Please request a new link.")
def reset_password(token):
    user = _load_reset_token(token)
    if not user:
        flash("The password reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password') or ''
        problem = validate_password_strength(new_password)
        if problem:
            flash(problem, "error")
            return render_template('reset_password.html')

        # FIX #1: Consistent hashing method (scrypt everywhere)
        user.password = generate_password_hash(new_password, method='scrypt')
        # Reaching the inbox proves the address; an account stuck unverified
        # can legitimately recover this way.
        user.email_verified = True
        # Somebody resets a password because they think somebody else has it.
        # Leaving the intruder's session in Redis and their 30-day remember-me
        # cookie working makes the reset theatre: rotate the stamp so every
        # credential issued before this moment stops resolving.
        rotate_security_stamp(user)
        db.session.commit()
        # Including this browser — the person resetting signs in fresh.
        # session.clear() first, so logout_user()'s remember-cookie marker
        # survives to be acted on.
        session.clear()
        logout_user()
        app.logger.info(
            'Password reset completed for user id=%s; existing sessions revoked',
            user.id)
        flash("Password updated, and you have been signed out everywhere else. "
              "You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# ============================================================
# AUTHENTICATION ROUTES
# ============================================================

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/livez', methods=['GET', 'HEAD'])
@limiter.exempt
def livez():
    """
    Process-only probe, answered by the WSGI middleware before Flask opens a
    session or an extension. Used to overlap a cold start with CampOS SSO.
    """
    return '', 204


#: How long a dependency check is reused. Platform probes run every few
#: seconds; the answer does not change faster than this and the checks cost a
#: round trip each.
READINESS_CACHE_SECONDS = float(os.environ.get('READINESS_CACHE_SECONDS', 5))
_readiness_cache = {'checked_at': 0.0, 'report': None}
_readiness_lock = threading.Lock()


def _check_database():
    db.session.execute(db.text('SELECT 1'))
    db.session.commit()


def _check_redis():
    if redis_client is None:
        # Not configured. In production the process would not have booted.
        return 'not configured'
    redis_client.ping()
    return 'ok'


def _check_smtp():
    """Open a connection to the mail server without sending anything."""
    if not app.config.get('MAIL_SERVER') or not app.config.get('MAIL_USERNAME'):
        return 'not configured'
    import smtplib
    with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'],
                      timeout=3) as smtp:
        smtp.ehlo()
    return 'ok'


def dependency_report():
    """
    Check what a real request depends on, and say which part is down.

    ``/healthz`` used to answer 204 from the WSGI layer without touching
    anything, so a deployment whose database or Redis had gone stayed
    'healthy' while every actual request failed.
    """
    checks = {}
    healthy = True

    for name, probe, required in (
        ('database', _check_database, True),
        ('redis', _check_redis, redis_client is not None),
        # SMTP failing loses signup and password-reset mail, which is
        # serious but not a reason to pull the instance out of the pool.
        ('smtp', _check_smtp, False),
    ):
        try:
            checks[name] = probe() or 'ok'
        except Exception as exc:
            checks[name] = f'error: {type(exc).__name__}'
            app.logger.warning('Readiness check %s failed: %s', name, exc)
            if required:
                healthy = False

    return healthy, checks


@app.route('/healthz', methods=['GET', 'HEAD'])
@limiter.exempt
def healthz():
    """
    Readiness: 204 when this instance can actually serve, 503 when it cannot.

    Kept credential-free and cheap — the result is cached for a few seconds so
    a per-second probe does not add a database round trip per second.
    """
    now = time.monotonic()
    with _readiness_lock:
        cached = _readiness_cache['report']
        fresh = cached is not None and (
            now - _readiness_cache['checked_at'] < READINESS_CACHE_SECONDS)

    if fresh:
        healthy, checks = cached
    else:
        healthy, checks = dependency_report()
        with _readiness_lock:
            _readiness_cache['report'] = (healthy, checks)
            _readiness_cache['checked_at'] = now

    if healthy:
        return '', 204, {'Cache-Control': 'no-store'}
    response = jsonify({'status': 'unhealthy', 'checks': checks})
    response.headers['Cache-Control'] = 'no-store'
    return response, 503


@app.route('/internal/metrics')
@limiter.exempt
def internal_metrics():
    """Prometheus text endpoint protected by an optional bearer token."""
    expected = os.environ.get('METRICS_TOKEN', '')
    if expected:
        supplied = request.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied, f'Bearer {expected}'):
            return '', 404
    elif is_production_environment():
        return '', 404

    # Redis pool occupancy, sampled at scrape time rather than tracked on
    # every command. "How many connections are in use, out of how many we
    # allow" is the number that says whether Redis is the bottleneck.
    if redis_pool is not None:
        try:
            in_use = len(getattr(redis_pool, '_in_use_connections', ()) or ())
            available = len(getattr(redis_pool, '_available_connections', ()) or ())
            runtime_metrics.gauge('redis.pool.in_use', in_use)
            runtime_metrics.gauge('redis.pool.available', available)
            runtime_metrics.gauge('redis.pool.max',
                                  getattr(redis_pool, 'max_connections', 0))
        except Exception:
            runtime_metrics.increment('redis.pool.stat_errors')

    return Response(runtime_metrics.prometheus(), mimetype='text/plain')


@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize/google')
def authorize_google():
    # An interrupted or replayed OAuth round trip (stale state cookie, someone
    # opening the callback directly, the user hitting back) raises out of
    # authlib. Unhandled, that is a 500 on a route real users land on.
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo') or {}
    except Exception as e:
        app.logger.warning('Google OAuth callback failed: %s', e)
        flash('Google sign-in failed or expired. Please try again.', 'error')
        return redirect(url_for('login'))

    email = (user_info.get('email') or '').strip().lower()
    full_name = (user_info.get('name') or '').strip()[:100]

    # Google marks addresses it has actually confirmed; an unconfirmed one is
    # no better evidence than a stranger typing the address into our own form.
    # Require a positive True: `is not False` also accepted a claim that was
    # missing entirely or null, which is precisely the case where Google is
    # telling us it has not checked.
    if not email or user_info.get('email_verified') is not True:
        app.logger.warning(
            'Google sign-in refused: email_verified=%r',
            user_info.get('email_verified'))
        flash('Google sign-in failed: no confirmed email address.', 'error')
        return redirect(url_for('login'))

    # Validate FUNAAB email
    is_valid, message, auto_role = is_valid_funaab_email(email)
    if not is_valid:
        flash(f'Access Denied: {message}', 'error')
        return redirect(url_for('login'))

    full_name = full_name or email.split('@')[0][:100]

    user = User.query.filter_by(email=email).first()
    if not user:
        # FIX #7: Use a cryptographically random dummy password (not a known string)
        user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(secrets.token_hex(32), method='scrypt'),
            # Google only hands us an address it has already verified, and a
            # Google sign-in never mints a staff role.
            role='student' if (auto_role or 'student') != 'lecturer' else auto_role,
            email_verified=True,
        )
        db.session.add(user)
        db.session.commit()

        # Send welcome email
        send_welcome_email(email, full_name, user.role)

        flash('Account created via Google! Check your email for confirmation.', 'success')
    elif user.email_verified is not True:
        # This local account was opened through the public signup form against
        # an address nobody proved they held — and the real owner is only
        # arriving now. Marking it verified and stopping there is an account
        # takeover with extra steps: the squatter's chosen password keeps
        # working on an account that is now trusted. Retire that password and
        # revoke anything it already minted, exactly as the CampOS path does.
        user.password = generate_password_hash(secrets.token_hex(32), method='scrypt')
        rotate_security_stamp(user)
        user.email_verified = True
        db.session.commit()
        app.logger.warning(
            'Google sign-in adopted an unconfirmed local account (id=%s); '
            'its password was retired and its sessions revoked', user.id)
        flash("This address had an unconfirmed ScanMark account. Its old "
              "password has been retired — use 'Forgot password' if you want "
              "to sign in without Google.", "warning")

    login_user(user, remember=True)
    return redirect_by_role(user.role)


# ============================================================
# CAMPOS SSO HAND-OFF  (Single Sign-On from CampOS Core)
# ============================================================
# The browser receives only an opaque, one-time code. ScanMark redeems it with
# CAMPOS_CORE_URL over a server-to-server request, then verifies the returned
# JWT using CAMPOS_SSO_SECRET (CampOS Core's SSO_JWT_SECRET_SCANMARK).


def _end_sso_response(response):
    """Finish an SSO round trip: no caching, and burn the one-time nonce."""
    protect_sso_response(response)
    response.delete_cookie(CAMPOS_STATE_COOKIE, httponly=True,
                           secure=IS_PRODUCTION, samesite='Lax')
    return response


def _campos_sso_redirect(location):
    return _end_sso_response(redirect(location))


# ------------------------------------------------------------------
# Browser-bound SSO state
# ------------------------------------------------------------------
# A hand-off code alone says "somebody's CampOS account", not "the account of
# the person holding this browser". Anyone who obtains a code — including an
# attacker who deliberately makes one for their OWN account — can feed it to
# somebody else's browser and silently sign that browser into the attacker's
# account, where the victim's subsequent scans are recorded. That is login
# CSRF, and the fix is a nonce this browser stored before the round trip
# started and must present on the way back.

CAMPOS_STATE_COOKIE = 'campos_sso_state'
CAMPOS_STATE_MAX_AGE = 600   # ten minutes to complete a sign-in

# Turn off ONLY for a CampOS deployment that predates state support, and only
# knowingly: without it a callback cannot be tied to the browser that started
# it. Defaults on everywhere.
CAMPOS_SSO_REQUIRE_STATE = _env_flag('CAMPOS_SSO_REQUIRE_STATE', True)


def _issue_sso_state(response):
    """Mint a nonce, put it in a cookie, and return it for the redirect URL."""
    nonce = secrets.token_urlsafe(24)
    response.set_cookie(
        CAMPOS_STATE_COOKIE,
        serializer.dumps(nonce, salt='campos-sso-state'),
        max_age=CAMPOS_STATE_MAX_AGE,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite='Lax',
    )
    return nonce


def _consume_sso_state(supplied):
    """True when `supplied` matches the nonce this browser was issued."""
    cookie = request.cookies.get(CAMPOS_STATE_COOKIE)
    if not cookie or not supplied:
        return False
    try:
        expected = serializer.loads(cookie, salt='campos-sso-state',
                                    max_age=CAMPOS_STATE_MAX_AGE)
    except Exception:
        return False
    return hmac.compare_digest(str(expected), str(supplied))


@app.route('/sso/start')
def campos_sso_start():
    """
    Begin a CampOS sign-in from ScanMark's side.

    Sets the browser-bound nonce, then hands off to CampOS with it. CampOS
    returns it as `state` on the callback.
    """
    try:
        from campos_integration import get_campos_core_url
        core_url = get_campos_core_url()
    except CamposIntegrationError as e:
        app.logger.warning('CampOS SSO start unavailable: %s', e)
        flash('CampOS sign-in is not configured for this deployment.', 'error')
        return redirect(url_for('login'))

    from urllib.parse import urlencode

    response = redirect(core_url)
    nonce = _issue_sso_state(response)

    params = {
        'module': 'scanmark',
        'state': nonce,
        'redirect_uri': external_url_for('campos_sso_callback'),
    }
    next_path = sanitize_next_path(request.args.get('next'))
    if next_path:
        params['next'] = next_path
    response.location = f"{core_url}/sso/launch?{urlencode(params)}"
    return protect_sso_response(response)


@app.route('/sso/callback')
@csrf.exempt
def campos_sso_callback():
    code = request.args.get('code', '')
    next_path = request.args.get('next')

    if not code:
        flash('Sign-in failed: missing CampOS hand-off code.', 'error')
        return _campos_sso_redirect(url_for('login'))

    # The hand-off must belong to the browser that asked for it.
    if CAMPOS_SSO_REQUIRE_STATE and not _consume_sso_state(request.args.get('state')):
        app.logger.warning(
            'CampOS SSO refused: callback carried no browser-bound state')
        flash('Sign-in could not be verified as started by this browser. '
              'Please sign in again from the ScanMark login page.', 'error')
        return _campos_sso_redirect(url_for('login'))

    try:
        token = exchange_campos_sso_code(code)
        claims = verify_campos_sso_token(token)
        identity = map_campos_launch_identity(claims)
        role = identity.role
    except CamposIntegrationError as e:
        app.logger.warning('CampOS SSO rejected: %s', e)
        flash('Sign-in failed: the link is invalid or has expired.', 'error')
        return _campos_sso_redirect(url_for('login'))

    email = (claims.get('email') or '').strip().lower()
    if not email or len(email) > 120 or not re.fullmatch(
        r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email
    ):
        flash('Sign-in failed: no email in identity token.', 'error')
        return _campos_sso_redirect(url_for('login'))

    full_name = ' '.join(
        filter(None, [claims.get('firstName'), claims.get('lastName')])
    ).strip()[:100] or email.split('@')[0][:100]
    matric_no = str(claims.get('matricNumber') or '').strip()[:20] or None
    level = str(claims.get('level') or '').strip()[:10] or None
    campos_user_id = claims['sub'].strip()
    campos_institution_id = claims['institutionId'].strip()

    # Resolve the stable CampOS subject first. Email is only a guarded
    # migration path for ordinary legacy accounts that are not linked yet.
    user = User.query.filter_by(campos_user_id=campos_user_id).first()
    email_user = User.query.filter_by(email=email).first()
    if user and email_user and user.id != email_user.id:
        app.logger.warning('CampOS SSO rejected: email belongs to another local account')
        flash('Sign-in failed: this identity cannot be linked automatically.', 'error')
        return _campos_sso_redirect(url_for('login'))
    if not user:
        user = email_user

    if user:
        try:
            validate_account_binding(
                existing_campos_user_id=user.campos_user_id,
                existing_institution_id=user.campos_institution_id,
                existing_role=user.role,
                incoming_campos_user_id=campos_user_id,
                incoming_institution_id=campos_institution_id,
            )
        except CamposIntegrationError as e:
            app.logger.warning('CampOS SSO account linking rejected: %s', e)
            flash('Sign-in failed: this identity cannot be linked automatically.', 'error')
            return _campos_sso_redirect(url_for('login'))

    if not user:
        # First arrival from CampOS — provision the local account.
        user = User(
            campos_user_id=campos_user_id,
            campos_institution_id=campos_institution_id,
            full_name=full_name,
            email=email,
            password=generate_password_hash(secrets.token_hex(32), method='scrypt'),
            role=role,
            # CampOS is the identity provider; the address arrives inside a
            # signed token, so there is nothing left for ScanMark to confirm.
            email_verified=True,
        )
        # CampOS is the source of truth for matric number (guard uniqueness).
        if matric_no and not User.query.filter_by(matric_no=matric_no).first():
            user.matric_no = matric_no
        if level:
            user.level = level
        # A dean's and an HOD's dashboards filter on these, so the signed scope
        # is what places them in the hierarchy.
        if identity.faculty:
            user.faculty = identity.faculty
        if identity.department:
            user.department = identity.department
        db.session.add(user)
        db.session.commit()
        app.logger.info('Created ScanMark user via CampOS SSO (id=%s)', user.id)
    else:
        # Keep identity fresh from the source of truth.
        changed = False
        if user.email_verified is False:
            # This local account was opened through the public signup form and
            # never confirmed — i.e. somebody claimed this address without
            # proving they hold it, and the real owner is only arriving now.
            # Adopting it as-is would leave the squatter's password working, so
            # retire that password; the owner can set a new one through
            # "forgot password" if they ever want to sign in without CampOS.
            user.password = generate_password_hash(secrets.token_hex(32), method='scrypt')
            # And anything that password already minted: a squatter's live
            # session outlives the password it was created with.
            rotate_security_stamp(user)
            changed = True
            app.logger.warning(
                'CampOS SSO adopted an unconfirmed local account (id=%s); '
                'its password was retired and its sessions revoked', user.id
            )
        if user.email_verified is not True:
            user.email_verified = True
            changed = True
        if user.campos_user_id != campos_user_id:
            user.campos_user_id = campos_user_id
            changed = True
        if user.campos_institution_id != campos_institution_id:
            user.campos_institution_id = campos_institution_id
            changed = True
        if user.email != email:
            user.email = email
            changed = True
        if full_name and user.full_name != full_name:
            user.full_name = full_name
            changed = True
        matric_owner = User.query.filter_by(matric_no=matric_no).first() if matric_no else None
        if matric_no and (not matric_owner or matric_owner.id == user.id) and user.matric_no != matric_no:
            user.matric_no = matric_no
            changed = True
        if level and user.level != level:
            user.level = level
            changed = True
        # CampOS is authoritative for placement on an account bound to the same
        # stable CampOS subject; validate_account_binding already refused an
        # unlinked privileged local account above. A signed launch identity
        # therefore switches the surface — without that, choosing a different
        # hierarchy would only ever work on a user's very first sign-in.
        # A legacy token names no identity, so it keeps the narrower rule of
        # only ever promoting an ordinary account.
        if identity.scoped or (user.role or '').lower() in ('student', 'lecturer'):
            if user.role != role:
                user.role = role
                changed = True
        # Placement follows the signed scope. A legacy token carries none, so it
        # must not erase what the local record already holds.
        if identity.scoped:
            if user.faculty != identity.faculty:
                user.faculty = identity.faculty
                changed = True
            if user.department != identity.department:
                user.department = identity.department
                changed = True
        if changed:
            db.session.commit()

    # Clear anonymous/pre-existing state and rotate the server-side session ID
    # when Flask-Session provides that capability.
    rotate_flask_session(app.session_interface, session)
    login_user(user, remember=False, fresh=True)

    safe_next = sanitize_next_path(next_path)
    if safe_next:
        return _campos_sso_redirect(safe_next)
    return _end_sso_response(redirect_by_role(user.role))


# A matric number is the identity the register is printed against and the key
# CampOS reconciles attendance on, so it is not free text. FUNAAB numbers look
# like 20200001 / 2020-1-0001; keep the shape strict but the punctuation
# forgiving, and normalise before storing so two spellings cannot become two
# students.
MATRIC_PATTERN = re.compile(r'^[A-Z0-9]{4,20}$')
LEVEL_CHOICES = ('100', '200', '300', '400', '500', '600', '700', '800')


def normalize_matric(raw):
    """Uppercase, strip separators, and return None when it is not one."""
    text = re.sub(r'[\s/\\._-]+', '', (raw or '').strip().upper())
    return text if MATRIC_PATTERN.fullmatch(text) else None


@app.route('/complete_profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    """
    Fill in the student details a CampOS launch or a Google sign-in did not
    carry. Students only — nothing else on a staff account uses these fields,
    and a staff member who submits here would take a matric number out of
    circulation for the student it belongs to.
    """
    if not user_has_role(current_user, STUDENT_ROLE):
        flash("Only student accounts have a matric number and level.", "warning")
        return redirect_by_role(current_user.role)

    if request.method == 'POST':
        matric_no = normalize_matric(request.form.get('matric_no', ''))
        level = request.form.get('level', '').strip()

        if not matric_no:
            flash("Enter a valid matric number (4-20 letters and digits).", "danger")
            return render_template('complete_profile.html',
                                   levels=LEVEL_CHOICES), 400
        if level not in LEVEL_CHOICES:
            flash("Choose your level from the list.", "danger")
            return render_template('complete_profile.html',
                                   levels=LEVEL_CHOICES), 400

        current_user.matric_no = matric_no
        current_user.level = level
        try:
            db.session.commit()
        except IntegrityError:
            # matric_no is unique: another account already holds this one.
            # Uncaught, this was a 500 on a page every new student sees.
            db.session.rollback()
            app.logger.warning(
                'Matric number already registered (user id=%s)', current_user.id)
            flash("That matric number is already registered to another "
                  "account. Check it, or contact your department.", "danger")
            return render_template('complete_profile.html',
                                   levels=LEVEL_CHOICES), 409

        flash("Profile updated! Welcome to ScanMark.", "success")
        return redirect_by_role(current_user.role)

    return render_template('complete_profile.html', levels=LEVEL_CHOICES)

@app.route('/login', methods=['GET', 'POST'])
# Count only actual login ATTEMPTS (POSTs) — the old limit also counted GETs,
# so viewing the page burned an attempt and one login cost 2 of the 5 hits.
# Key by IP + submitted email: brute-forcing one account stays capped, but a
# whole class logging in from behind one campus NAT IP before a lecture no
# longer shares a single 5-request bucket.
@limiter.limit(
    "10 per minute",
    methods=["POST"],
    key_func=lambda: f"login:{get_remote_address()}:{(request.form.get('email') or '').strip().lower()}",
    error_message="Too many login attempts. Please try again later."
)
def login():
    if current_user.is_authenticated:
        return redirect_by_role(current_user.role)

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # An unconfirmed self-service STUDENT account is not yet proof
            # that the person typing owns the address they registered. Staff
            # accounts are not held here — see role_requires_email_verification.
            if account_needs_verification(user):
                flash("Please confirm your email address first. "
                      "Check your inbox for the verification link.", "warning")
                return render_template('login.html', unverified_email=email)
            login_user(user, remember=True)
            return redirect_by_role(user.role)
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
# Account creation is unauthenticated, so it is keyed by IP. The default
# 1000/minute bucket let one host mint accounts faster than a human ever
# could; a real person signs up once.
@limiter.limit(
    "5 per hour;20 per day",
    methods=["POST"],
    key_func=get_remote_address,
    error_message="Too many signup attempts from this network. Please try again later."
)
def signup():
    if request.method == 'POST':
        name = (request.form.get('full_name') or
                request.form.get('name') or '').strip()[:100]
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        matric_no = normalize_matric(request.form.get('matric_no', ''))
        level = request.form.get('level', '').strip()[:10]
        staff_role = request.form.get('staff_role', '').strip()

        def reject(message, category='danger'):
            flash(message, category)
            return render_template('signup.html')

        if not name:
            return reject('Please enter your full name!')
        if not email:
            return reject('Please enter your email address!')
        if not password:
            return reject('Please enter a password!')

        is_valid, message, auto_role = is_valid_funaab_email(email)
        if not is_valid:
            return reject(message)

        # A staff address may pick between the self-service staff roles and
        # nothing else. The previous code assigned request.form['staff_role']
        # verbatim, so posting staff_role=dap minted an account that reads
        # every course's attendance in the institution.
        # Stored in its canonical spelling so nothing downstream has to guess
        # whether this row says 'lecturer' or 'Lecturer'.
        final_role = CANONICAL_ROLE_NAMES.get(normalize_role(auto_role), auto_role)
        if email.endswith(STAFF_DOMAIN):
            if not staff_role:
                return reject('Please select your role (Lecturer or Course Coordinator)')
            final_role = SELF_SERVICE_STAFF_ROLES.get(staff_role.lower())
            if not final_role:
                app.logger.warning(
                    'Rejected signup requesting non-self-service role %r', staff_role[:40]
                )
                return reject('Please select your role (Lecturer or Course Coordinator)')

        password_problem = validate_password_strength(password)
        if password_problem:
            return reject(password_problem)

        if User.query.filter_by(email=email).first():
            flash('This FUNAAB email is already registered!', 'warning')
            return redirect(url_for('login'))

        new_user = User(
            full_name=name,
            email=email,
            password=generate_password_hash(password, method='scrypt'),
            role=final_role,
            matric_no=matric_no,
            level=level or None,
            # Nobody proved they own this address yet.
            email_verified=False,
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            # Two simultaneous signups for the same address, or a matric number
            # already spoken for by another account.
            db.session.rollback()
            flash('This FUNAAB email is already registered!', 'warning')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            app.logger.exception('Signup failed to persist the new account')
            return reject('Error creating account. Please try again.')

        app.logger.info('Account created (id=%s, role=%s)', new_user.id, final_role)
        send_verification_email(new_user)
        send_welcome_email(email, name, final_role)

        if account_needs_verification(new_user):
            flash('Account created! Check your email for a verification link '
                  'before you sign in.', 'success')
        else:
            flash('Account created successfully! You can sign in now — '
                  'welcome to ScanMark.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    POST only, and therefore CSRF-protected.

    As a GET, any page on the internet could sign a student out mid-lecture
    with an <img src="/logout"> — irritating on its own, and a way to force a
    re-login through a page the attacker chose the moment they know a scan is
    about to happen.
    """
    # Order matters: logout_user() leaves a marker in the session telling
    # Flask-Login to delete the remember-me cookie on the way out. Clearing
    # the session afterwards throws that marker away, and the next request
    # signs the user straight back in from the cookie.
    session.clear()
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ============================================================
# DASHBOARD ROUTES
# ============================================================

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect_by_role(current_user.role)


def _student_attendance_summary(include_archived=False):
    """
    (enrolled courses, per-course attendance rows) for the signed-in student.

    Two GROUP BY queries for ALL courses at once — the old loop ran two COUNT
    queries per enrolled course (~18 queries per dashboard load), and this
    page reloads after every successful scan.

    "Classes held" is the number of meetings THIS student was on the roster
    for, not every meeting the course has ever had. Counting all of them marks
    a student absent for lectures that took place before they enrolled, and
    for a course still running from a previous term it never stops
    accumulating.
    """
    enrolled_courses = [
        course for course in (getattr(current_user, 'enrolled_courses', []) or [])
        if include_archived or not course.archived
    ]
    course_ids = [c.id for c in enrolled_courses]

    attended_by_course = {}
    expected_by_course = {}
    if course_ids:
        attended_by_course = dict(
            db.session.query(Attendance.course_id, func.count(Attendance.id))
            .filter(Attendance.student_id == current_user.id,
                    Attendance.course_id.in_(course_ids))
            .group_by(Attendance.course_id)
            .all())
        expected_by_course = dict(
            db.session.query(SessionRoster.course_id,
                             func.count(SessionRoster.session_id))
            .filter(SessionRoster.student_id == current_user.id,
                    SessionRoster.course_id.in_(course_ids))
            .group_by(SessionRoster.course_id)
            .all())

    attendance_data = []
    for course in enrolled_courses:
        count = attended_by_course.get(course.id, 0)
        total_sessions = expected_by_course.get(course.id, 0)
        attendance_data.append({
            'code': course.code,
            'title': course.title,
            'term': course.term_label,
            'count': count,
            'total_sessions': total_sessions,
            'pct': _attendance_percentage(count, total_sessions),
        })

    return enrolled_courses, attendance_data


@app.route('/student_dashboard')
@login_required
def student_dashboard():
    # Sending a non-student to /login was one leg of the redirect loop: an
    # unrecognised role landed here, got bounced to /login, and /login sent it
    # straight back. Bounce to whatever dashboard they DO have instead.
    denied = require_role(STUDENT_ROLE)
    if denied:
        return denied

    # 🚨 THE INTERCEPTOR
    if not current_user.matric_no or not current_user.level:
        flash("Please complete your profile to access your dashboard.", "info")
        return redirect(url_for('complete_profile'))

    enrolled_courses, attendance_data = _student_attendance_summary()

    return render_template('student_dashboard.html',
                           attendance_data=attendance_data,
                           enrolled_courses=enrolled_courses,
                           threshold=ATTENDANCE_TARGET_PERCENT)


@app.route('/lecturer_dashboard')
@login_required
def lecturer_dashboard():
    denied = require_role(*TEACHING_ROLES)
    if denied:
        return denied

    show_archived = request.args.get('archived', '').strip().lower() in ('1', 'true', 'yes')

    if user_has_role(current_user, COORDINATOR_ROLE):
        query = Course.query.filter_by(coordinator_id=current_user.id)
        can_create = True
    else:
        query = Course.query.join(
            course_instructors, course_instructors.c.course_id == Course.id
        ).filter(course_instructors.c.user_id == current_user.id)
        can_create = False

    if not show_archived:
        query = query.filter(Course.archived.is_(False))
    my_courses = query.order_by(Course.academic_year.desc(),
                                Course.semester.asc(),
                                Course.code.asc()).all()

    # The count the "Instructors" tile is supposed to show, actually computed.
    # It was rendered as an em dash by a deliberate `if false`, which is not a
    # statistic — it is a placeholder that shipped.
    course_ids = [course.id for course in my_courses]
    instructor_total = 0
    if course_ids:
        instructor_total = (
            db.session.query(func.count(func.distinct(course_instructors.c.user_id)))
            .filter(course_instructors.c.course_id.in_(course_ids))
            .scalar()) or 0
        # A coordinator teaches their own courses without an invitation row.
        coordinator_ids = {course.coordinator_id for course in my_courses}
        invited = {
            row[0] for row in
            db.session.query(course_instructors.c.user_id)
            .filter(course_instructors.c.course_id.in_(course_ids)).distinct()
        }
        instructor_total = len(invited | coordinator_ids)

    # Live sessions, so the dashboard button can say "Resume" rather than
    # opening a second meeting the lecturer did not ask for.
    open_sessions = {}
    if course_ids:
        open_sessions = {
            row.course_id: row.id for row in
            ClassSession.query
            .filter(ClassSession.course_id.in_(course_ids),
                    ClassSession.active.is_(True),
                    ClassSession.ended_at.is_(None))
            .order_by(ClassSession.date_created.asc())
            .all()
        }

    return render_template('lecturer_dashboard.html', courses=my_courses,
                           can_create=can_create,
                           instructor_total=instructor_total,
                           open_sessions=open_sessions,
                           show_archived=show_archived,
                           is_coordinator=can_create,
                           current_term=describe_term(*academic_term_of()))


@app.route('/hod_dashboard')
@login_required
def hod_dashboard():
    denied = require_role(HOD_ROLE)
    if denied:
        return denied

    academic_year, semester = _requested_term()

    # An HOD who has not been placed in a department presides over nothing.
    # `filter_by(department=None)` matched every course whose department is
    # also NULL — the unclassified pile — which is the opposite of the
    # documented behaviour and leaks courses across the institution.
    if not current_user.department:
        flash("Your account is not linked to a department yet, so there are "
              "no departmental courses to show. Ask academic planning to set "
              "your department.", "warning")
        courses, pagination = [], None
    else:
        page = max(1, request.args.get('page', default=1, type=int) or 1)
        pagination = (Course.query
                      .filter(Course.department == current_user.department,
                              Course.archived.is_(False))
                      .filter(*_term_filters(academic_year, semester))
                      .order_by(Course.code.asc())
                      .paginate(page=page, per_page=50, error_out=False))
        courses = pagination.items

    return render_template('hod_dashboard.html', courses=courses,
                           pagination=pagination, dept=current_user.department,
                           terms=_known_terms(),
                           academic_year=academic_year, semester=semester,
                           term_label=describe_term(academic_year, semester)
                           if academic_year else 'All terms')


@app.route('/hod_analytics')
@login_required
def hod_analytics():
    denied = require_role(HOD_ROLE)
    if denied:
        return denied

    academic_year, semester = _requested_term()
    if not current_user.department:
        flash("Your account is not linked to a department yet.", "warning")

    data = get_department_analytics(current_user.department,
                                    academic_year, semester)
    return render_template('analytics_hod.html', dept=current_user.department,
                           data=data, terms=_known_terms(),
                           academic_year=academic_year, semester=semester,
                           term_label=describe_term(academic_year, semester)
                           if academic_year else 'All terms')


@app.route('/dean_dashboard')
@login_required
def dean_dashboard():
    denied = require_role(DEAN_ROLE)
    if denied:
        return denied

    academic_year, semester = _requested_term()

    if not current_user.faculty:
        flash("Your account is not linked to a faculty yet, so there is "
              "nothing to report on.", "warning")
        return render_template('dean_dashboard.html', faculty=None,
                               course_count=0, lecturer_count=0,
                               department_rows=[], terms=_known_terms(),
                               academic_year=academic_year, semester=semester,
                               term_label='—')

    course_query = Course.query.filter(Course.faculty == current_user.faculty,
                                       Course.archived.is_(False))
    course_count = course_query.filter(*_term_filters(academic_year, semester)).count()

    # `role='lecturer'` counted only the accounts CampOS created: self-signup
    # stores 'Lecturer', so a faculty of thirty could report four. Compare on
    # the normalised role, and count coordinators too — they teach.
    lecturer_count = (User.query
                      .filter(role_is(LECTURER_ROLE, COORDINATOR_ROLE),
                              User.faculty == current_user.faculty)
                      .count())

    # Per-department attendance so the page says something a dean can act on.
    department_rows = _faculty_department_summary(current_user.faculty,
                                                  academic_year, semester)

    return render_template('dean_dashboard.html',
                           faculty=current_user.faculty,
                           course_count=course_count,
                           lecturer_count=lecturer_count,
                           department_rows=department_rows,
                           terms=_known_terms(),
                           academic_year=academic_year, semester=semester,
                           term_label=describe_term(academic_year, semester)
                           if academic_year else 'All terms')


def _faculty_department_summary(faculty, academic_year=None, semester=None):
    """Attendance percentage per department inside one faculty."""
    courses = (Course.query
               .filter(Course.faculty == faculty, Course.archived.is_(False))
               .filter(*_term_filters(academic_year, semester))
               .all())
    if not courses:
        return []

    course_ids = [course.id for course in courses]
    attended = dict(
        db.session.query(Attendance.course_id, func.count(Attendance.id))
        .filter(Attendance.course_id.in_(course_ids),
                Attendance.session_id.isnot(None))
        .group_by(Attendance.course_id).all())
    expected = dict(
        db.session.query(SessionRoster.course_id,
                         func.count(SessionRoster.student_id))
        .filter(SessionRoster.course_id.in_(course_ids))
        .group_by(SessionRoster.course_id).all())

    by_department = {}
    for course in courses:
        bucket = by_department.setdefault(
            course.department or 'Unassigned',
            {'department': course.department or 'Unassigned',
             'courses': 0, 'present': 0, 'expected': 0})
        bucket['courses'] += 1
        bucket['present'] += attended.get(course.id, 0)
        bucket['expected'] += expected.get(course.id, 0)

    rows = sorted(by_department.values(), key=lambda row: row['department'])
    for row in rows:
        row['pct'] = _attendance_percentage(row['present'], row['expected'])
    return rows


@app.route('/dap_dashboard')
@login_required
def dap_dashboard():
    denied = require_role(DAP_ROLE)
    if denied:
        return denied

    academic_year, semester = _requested_term()

    # Same casing bug as the dean's lecturer count: self-signup students are
    # stored as 'Student' by the canonical-role mapping, CampOS sends
    # 'student', and `filter_by(role='student')` sees only one of them.
    total_students = User.query.filter(role_is(STUDENT_ROLE)).count()
    total_staff = User.query.filter(
        role_is(LECTURER_ROLE, COORDINATOR_ROLE, HOD_ROLE, DEAN_ROLE)).count()
    total_courses = (Course.query
                     .filter(Course.archived.is_(False))
                     .filter(*_term_filters(academic_year, semester))
                     .count())
    return render_template('dap_dashboard.html',
                           total_students=total_students,
                           total_staff=total_staff,
                           total_courses=total_courses,
                           terms=_known_terms(),
                           academic_year=academic_year, semester=semester,
                           term_label=describe_term(academic_year, semester)
                           if academic_year else 'All terms')


@app.route('/dap_analytics')
@login_required
def dap_analytics():
    denied = require_role(DAP_ROLE)
    if denied:
        return denied

    academic_year, semester = _requested_term()

    courses = (Course.query
               .filter(Course.archived.is_(False))
               .filter(*_term_filters(academic_year, semester))
               .all())
    course_ids = [course.id for course in courses]

    attended, expected = {}, {}
    if course_ids:
        attended = dict(
            db.session.query(Attendance.course_id, func.count(Attendance.id))
            .filter(Attendance.course_id.in_(course_ids),
                    Attendance.session_id.isnot(None))
            .group_by(Attendance.course_id).all())
        expected = dict(
            db.session.query(SessionRoster.course_id,
                             func.count(SessionRoster.student_id))
            .filter(SessionRoster.course_id.in_(course_ids))
            .group_by(SessionRoster.course_id).all())

    by_faculty = {}
    for course in courses:
        bucket = by_faculty.setdefault(course.faculty or 'Unassigned',
                                       {'present': 0, 'expected': 0})
        bucket['present'] += attended.get(course.id, 0)
        bucket['expected'] += expected.get(course.id, 0)

    labels = sorted(by_faculty)
    # The doughnut shows each faculty's SHARE of recorded attendance, which is
    # what a distribution chart means; the percentage each faculty actually
    # achieved rides along in the tooltip data.
    data = [by_faculty[name]['present'] for name in labels]
    rates = [_attendance_percentage(by_faculty[name]['present'],
                                    by_faculty[name]['expected']) or 0
             for name in labels]
    return render_template('analytics_dap.html', labels=labels, data=data,
                           rates=rates, terms=_known_terms(),
                           academic_year=academic_year, semester=semester,
                           term_label=describe_term(academic_year, semester)
                           if academic_year else 'All terms')


# ============================================================
# AUTHORIZATION HELPERS
# ============================================================
# One place decides who may manage or read a course, so a new route cannot
# quietly invent a weaker rule than its neighbours.

def _is_coordinator():
    """True when the signed-in user holds the course-coordinator post."""
    return user_has_role(current_user, COORDINATOR_ROLE)


def _owns_course(course):
    """
    True when the current user OWNS this course, not merely teaches it.

    Ownership is what gates destruction. An invited instructor runs classes;
    deleting a session takes its whole attendance sheet with it, and deleting
    the course takes the term's register, so both belong to the coordinator
    who created the course.
    """
    return course.coordinator_id == current_user.id


def _is_course_authorized(course):
    """
    True when the current user may MANAGE this course: open its sessions,
    mint its QR tokens, read its roster, export its register.

    Managing is deliberately narrower than viewing (see _attendance_authorized):
    it is limited to the people actually teaching the course.
    """
    if course.coordinator_id == current_user.id:
        return True
    # `instructors` is a dynamic relationship — ask the database for this one
    # row rather than loading every instructor to run `in` over them.
    return course.instructors.filter(User.id == current_user.id).first() is not None


def _attendance_authorized(course):
    """
    FIX #8: Extended to allow HOD, Dean, and DAP to READ attendance
    in addition to coordinators and instructors.
    """
    role = normalize_role(current_user.role)
    if _is_course_authorized(course):
        return True
    # A supervisory post only reaches courses inside its own patch, and only
    # when that patch is actually recorded — a NULL department must never
    # match a course whose department is also NULL.
    if role == HOD_ROLE:
        return bool(current_user.department) and course.department == current_user.department
    if role == DEAN_ROLE:
        return bool(current_user.faculty) and course.faculty == current_user.faculty
    if role == DAP_ROLE:
        return True
    return False


# ============================================================
# COURSE MANAGEMENT
# ============================================================

@app.route('/add_course', methods=['POST'])
@login_required
def add_course():
    # Creating a course makes you its coordinator, which carries the roster and
    # the attendance register. Without this check any signed-in student could
    # mint courses.
    if not _is_coordinator():
        flash("Only a Course Coordinator can create a course.", "error")
        return redirect(url_for('dashboard'))

    code = _clean_course_code(request.form.get('code'))
    title = _clean_text(request.form.get('title'), 100)

    if not code or not title:
        flash("Course code and title are required, and the code may only "
              "contain letters, digits, spaces and hyphens.", "error")
        return redirect(url_for('dashboard'))

    # A course belongs to a term. Without one, next year's CSC201 either
    # collides with this year's or silently inherits its class sessions.
    default_year, default_semester = academic_term_of()
    academic_year = (normalize_academic_year(request.form.get('academic_year'))
                     or default_year)
    semester = normalize_semester(request.form.get('semester')) or default_semester
    section = _clean_text(request.form.get('section'), 20).upper()

    existing = Course.query.filter_by(code=code, academic_year=academic_year,
                                      semester=semester, section=section).first()
    if existing:
        flash(f"{code} already exists for "
              f"{describe_term(academic_year, semester, section)}.", "error")
        return redirect(url_for('dashboard'))

    new_course = Course(
        code=code,
        title=title,
        academic_year=academic_year,
        semester=semester,
        section=section,
        coordinator_id=current_user.id,
        department=getattr(current_user, 'department', None),
        faculty=getattr(current_user, 'faculty', None),
    )
    db.session.add(new_course)
    try:
        # Flush first: the row has no id until it reaches the database, and an
        # audit entry naming no course cannot be found again.
        db.session.flush()
        record_audit('course.create', 'course', new_course.id,
                     f'{code} {title}', course_id=new_course.id,
                     academic_year=academic_year, semester=semester,
                     section=section)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(f"{code} already exists for "
              f"{describe_term(academic_year, semester, section)}.", "error")
        return redirect(url_for('dashboard'))
    flash(f"Course {code} created for "
          f"{describe_term(academic_year, semester, section)}!", "success")
    return redirect(url_for('dashboard'))


@app.route('/course/<int:course_id>/archive', methods=['POST'])
@login_required
def archive_course(course_id):
    """
    Close a finished offering.

    An archived course keeps every record it ever had — the register still
    downloads, the audit trail still resolves — but it stops appearing on
    working dashboards and stops being counted in this term's figures.
    """
    course = db.get_or_404(Course, course_id)
    if not _owns_course(course):
        flash('Unauthorised: only the course creator can archive it.', 'error')
        return redirect(url_for('dashboard'))

    unarchive = request.form.get('unarchive', '').strip().lower() in ('1', 'true', 'yes')
    course.archived = not unarchive
    course.archived_at = None if unarchive else _utcnow()
    record_audit('course.unarchive' if unarchive else 'course.archive',
                 'course', course.id, f'{course.code} {course.title}',
                 course_id=course.id,
                 academic_year=course.academic_year, semester=course.semester)
    db.session.commit()
    flash(f"{course.code} was "
          f"{'restored to' if unarchive else 'archived from'} your dashboard.",
          "success")
    return redirect(url_for('dashboard'))


@app.route('/api/course/<int:course_id>/enrolled_students')
@login_required
@limiter.exempt
def get_enrolled_students(course_id):
    """
    One page of the course roster.

    A 2000-student course used to come back as a single JSON document holding
    every row, built from 2000 ORM objects — several megabytes onto a phone,
    and the whole roster materialised in the worker for each caller. Callers
    walk it with ``?after=<last id>`` instead.
    """
    course = db.get_or_404(Course, course_id)

    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403

    after_id = max(0, request.args.get('after', default=0, type=int) or 0)
    limit = min(500, max(1, request.args.get('limit', default=200, type=int) or 200))

    rows = (db.session.query(User.id, User.full_name, User.matric_no, User.level)
            .join(enrollments, enrollments.c.user_id == User.id)
            .filter(enrollments.c.course_id == course_id, User.id > after_id)
            .order_by(User.id.asc())
            .limit(limit + 1)
            .all())
    has_more = len(rows) > limit
    rows = rows[:limit]

    return jsonify({
        "status": "success",
        # The size of the roster, not the size of this page — the old `total`
        # was len(students) and happened to be both.
        "total": _enrolled_count(course_id),
        "count": len(rows),
        "has_more": has_more,
        "last_id": rows[-1][0] if rows else after_id,
        "students": [{
            "id": student_id,
            "name": full_name,
            "matric_no": matric_no or "N/A",
            "level": level or "N/A",
        } for student_id, full_name, matric_no, level in rows],
    })

# FIX #9: DELETE only via POST (removed GET)
def _forget_legacy_table(name):
    """
    Drop a legacy table from the per-worker list once it no longer exists.

    Each gunicorn worker detects the list at boot and heals its own copy the
    first time a table turns out to be gone, so dropping the tables never
    needs a restart.
    """
    global LEGACY_COURSE_REF_TABLES
    LEGACY_COURSE_REF_TABLES = tuple(
        table for table in LEGACY_COURSE_REF_TABLES if table != name
    )
    app.logger.info(
        'Legacy table %s no longer exists; it will not be cleared again.', name)


def discover_course_ref_tables():
    """
    Ask the live database which tables still point at ``course.id``.

    Detecting this once at boot is not enough. A table that appears after the
    worker started — an upgrade run against a live deployment, a restored
    dump — is invisible to a boot-time snapshot, and the first symptom is a
    500 on course deletion in production only, because SQLite never enforced
    the constraint that fails.
    """
    # Tables this release clears itself, in the right order, in delete_course.
    # `audit_log` is deliberately absent from BOTH this set and the search
    # below: it carries a course_id but no foreign key, precisely so that the
    # record of a deletion is not deleted along with what it describes.
    known = {'attendance', 'class_session', 'session_roster',
             'enrollments', 'course_instructors', 'course', 'audit_log'}
    try:
        inspector = inspect(db.engine)
        found = []
        for table_name in inspector.get_table_names():
            if table_name in known:
                continue
            for fk in inspector.get_foreign_keys(table_name):
                if fk.get('referred_table') == 'course':
                    found.append(table_name)
                    break
            else:
                # A legacy table may carry the column without a declared FK.
                if table_name.startswith(('early_warning', 'notification',
                                          'weekly_report')):
                    columns = {c['name'] for c in inspector.get_columns(table_name)}
                    if 'course_id' in columns:
                        found.append(table_name)
        return tuple(sorted(found))
    except Exception:
        app.logger.exception('Could not inspect tables referencing course')
        return ()


def _clear_course_references(course_id):
    """
    Empty every table that would otherwise block deleting this course.

    Returns the number of legacy rows removed, for the audit entry.
    """
    removed = 0
    # Re-inspect rather than trusting the boot-time snapshot: the tables
    # present now are what the delete has to satisfy.
    tables = tuple(LEGACY_COURSE_REF_TABLES) or discover_course_ref_tables()
    for legacy_table in tables:
        quoted = db.engine.dialect.identifier_preparer.quote(legacy_table)
        try:
            # SAVEPOINT, because the startup message invites an operator to
            # drop these tables whenever they like — including while this is
            # serving. Without it, the first DELETE against a table that has
            # since gone aborts the whole transaction on Postgres, and every
            # course deletion 500s until all workers restart.
            with db.session.begin_nested():
                result = db.session.execute(
                    db.text(f'DELETE FROM {quoted} WHERE course_id = :course_id'),
                    {'course_id': course_id},
                )
                removed += result.rowcount or 0
        except (ProgrammingError, OperationalError):
            # It has been dropped since boot. Stop asking for it; the
            # savepoint means the rest of this deletion is still good.
            _forget_legacy_table(legacy_table)
    return removed


@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    course = db.get_or_404(Course, course_id)

    if not _owns_course(course):
        flash('Unauthorised: Only the course creator can delete it.', 'error')
        return redirect(url_for('dashboard'))

    label = f'{course.code} — {course.title}'
    session_count = ClassSession.query.filter_by(course_id=course_id).count()
    scan_count = Attendance.query.filter_by(course_id=course_id).count()

    # Clear every table that references this course before removing it.
    # Postgres enforces the foreign keys (and SQLite now does too), so missing
    # one here used to mean the delete failed in production and nowhere else.
    Attendance.query.filter_by(course_id=course_id).delete()
    SessionRoster.query.filter_by(course_id=course_id).delete()
    ClassSession.query.filter_by(course_id=course_id).delete()
    db.session.execute(enrollments.delete().where(
        enrollments.c.course_id == course_id))
    db.session.execute(course_instructors.delete().where(
        course_instructors.c.course_id == course_id))

    legacy_rows = _clear_course_references(course_id)

    # Written BEFORE the delete, so the record of the deletion is part of the
    # same transaction as the deletion itself: either both happen or neither.
    record_audit('course.delete', 'course', course_id, label,
                 course_id=course_id,
                 academic_year=course.academic_year, semester=course.semester,
                 section=course.section, sessions_deleted=session_count,
                 attendance_deleted=scan_count, legacy_rows_deleted=legacy_rows)

    db.session.delete(course)
    db.session.commit()
    flash(f'Course "{course.code}" and its {scan_count} attendance record(s) '
          f'have been deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/add_instructor', methods=['POST'])
@login_required
def add_instructor():
    course_id = request.form.get('course_id', type=int)
    lecturer_email = (request.form.get('lecturer_email') or '').strip().lower()

    course = Course.query.get(course_id) if course_id else None
    if not course:
        flash("Course or lecturer not found.", "error")
        return redirect(url_for('dashboard'))

    # Holding the Course Coordinator role was the ONLY check here, so any
    # coordinator could add themselves as an instructor on somebody else's
    # course and inherit its roster, live QR tokens and attendance register.
    # Coordinating THIS course is what grants the right.
    if course.coordinator_id != current_user.id:
        flash("Unauthorised: you do not coordinate that course.", "error")
        return redirect(url_for('dashboard'))

    lecturer = User.query.filter_by(email=lecturer_email).first()
    if not lecturer:
        flash("Course or lecturer not found.", "error")
        return redirect(url_for('dashboard'))

    if (lecturer.role or '').lower() not in ('lecturer', 'course coordinator'):
        flash("Only staff accounts can be added as instructors.", "error")
        return redirect(url_for('dashboard'))

    if course.instructors.filter(User.id == lecturer.id).first():
        flash("User is already an instructor.", "info")
        return redirect(url_for('dashboard'))

    course.instructors.append(lecturer)
    db.session.commit()
    flash(f"Added {lecturer.full_name} to {course.code}.", "success")
    return redirect(url_for('dashboard'))


@app.route('/register_course', methods=['POST'])
@login_required
def register_course():
    # Enrolment is what /mark_attendance checks, so it belongs to students.
    if not user_has_role(current_user, STUDENT_ROLE):
        flash("Only students can register for a course.", "error")
        return redirect(url_for('dashboard'))

    course_code = _clean_course_code(request.form.get('course_code'))
    if not course_code:
        flash("Enter a course code, for example CSC201.", "error")
        return redirect(url_for('student_dashboard'))

    # A code names several offerings now — one per term, and possibly several
    # sections within a term.
    academic_year, semester = academic_term_of()
    section = _clean_text(request.form.get('section'), 20).upper()

    offerings = (Course.query
                 .filter(Course.code == course_code, Course.archived.is_(False))
                 .filter(*_term_filters(academic_year, semester))
                 .order_by(Course.section.asc())
                 .all())
    if not offerings:
        # Still offer whatever current offering exists, so a course created
        # under a term label that differs from the calendar's is reachable.
        offerings = (Course.query
                     .filter(Course.code == course_code,
                             Course.archived.is_(False))
                     .order_by(Course.academic_year.desc(),
                               Course.semester.desc(),
                               Course.section.asc())
                     .all()[:1])

    if not offerings:
        flash("Course not found!", "error")
        return redirect(url_for('student_dashboard'))

    if section:
        offerings = [row for row in offerings if row.section.upper() == section]
        if not offerings:
            flash(f"{course_code} has no section {section} this term.", "error")
            return redirect(url_for('student_dashboard'))

    # Never guess. Picking the first section alphabetically puts the student on
    # the wrong roster: they are missing from their real section's register and
    # their scans there are refused as "not registered", with nothing on either
    # screen explaining why.
    if len(offerings) > 1:
        available = ', '.join(row.section or '(unnamed)' for row in offerings)
        flash(f"{course_code} runs in more than one section this term "
              f"({available}). Enter your section to register.", "warning")
        return redirect(url_for('student_dashboard'))

    course = offerings[0]

    if course in current_user.enrolled_courses:
        flash(f"You are already registered for {course.code}.", "info")
    else:
        current_user.enrolled_courses.append(course)
        try:
            db.session.commit()
            flash(f"✅ Successfully registered for {course.code} "
                  f"({course.term_label}).", "success")
        except IntegrityError:
            db.session.rollback()
            flash(f"You are already registered for {course.code}.", "info")

    return redirect(url_for('student_dashboard'))


# ============================================================
# QR CODE ROUTES  (FIX #3, #5, #6)
# ============================================================

_daily_session_locks = {}
_daily_session_locks_guard = threading.Lock()

#: What kind of meeting a session is. Two lectures, a tutorial and a makeup
#: class can all happen on the same day and are all separate record sets.
SESSION_KINDS = ('Lecture', 'Tutorial', 'Practical', 'Makeup Class', 'Test')


def _course_lock(course_id):
    with _daily_session_locks_guard:
        return _daily_session_locks.setdefault(course_id, threading.Lock())


def _take_course_advisory_lock(course_id):
    """Serialise session decisions for one course across gunicorn workers."""
    if db.session.get_bind().dialect.name == 'postgresql':
        db.session.execute(
            db.text('SELECT pg_advisory_xact_lock(:namespace, :course_id)'),
            {'namespace': 835_211, 'course_id': course_id},
        )


def open_session_for(course_id):
    """The meeting currently running for this course, or None."""
    return (ClassSession.query
            .filter(ClassSession.course_id == course_id,
                    ClassSession.active.is_(True),
                    ClassSession.ended_at.is_(None))
            .order_by(ClassSession.date_created.desc())
            .first())


def _snapshot_roster(session_row):
    """
    Freeze who was enrolled the moment this meeting opened.

    One INSERT ... SELECT, so a 2000-student course costs a single statement
    rather than 2000 ORM objects. This snapshot is the denominator for every
    percentage involving this session, for good — which is what stops a
    student who enrols in week 6 being marked absent for weeks 1 to 5, and
    what stops a later roster change pushing an old figure above 100%.
    """
    inserted = db.session.execute(
        SessionRoster.__table__.insert().from_select(
            ['session_id', 'student_id', 'course_id'],
            select(literal(session_row.id), enrollments.c.user_id,
                   literal(session_row.course_id))
            .where(enrollments.c.course_id == session_row.course_id)
        )
    )
    return inserted.rowcount or 0


def create_class_session(course, kind='Lecture', title=None):
    """
    Open a NEW meeting for this course, however many it already had today.

    The previous behaviour returned the day's existing session instead, so a
    lecture and the tutorial that followed it merged into one record set and a
    makeup class could not be recorded at all.
    """
    kind = kind if kind in SESSION_KINDS else 'Lecture'
    now = _utcnow()
    day_start, day_end = local_day_bounds_utc(local_date(now))

    todays_count = (db.session.query(func.count(ClassSession.id))
                    .filter(ClassSession.course_id == course.id,
                            ClassSession.date_created >= day_start,
                            ClassSession.date_created < day_end)
                    .scalar()) or 0
    sequence = todays_count + 1

    label = _clean_text(title, 100) if title else ''
    if not label:
        label = f"{kind} on {local_date_only(now)}"
        if sequence > 1:
            # Distinguishable at a glance in the accordion and the CSV header.
            label = f"{label} (#{sequence})"

    session_row = ClassSession(
        course_id=course.id,
        title=label,
        kind=kind,
        sequence=sequence,
        date_created=now,
        active=True,
    )
    db.session.add(session_row)
    db.session.flush()
    expected = _snapshot_roster(session_row)
    record_audit('session.start', 'class_session', session_row.id, label,
                 course_id=course.id, course_code=course.code,
                 kind=kind, sequence=sequence, roster_size=expected)
    db.session.commit()
    return session_row


def _close_session_row(session_row, reason='ended'):
    """
    Mark a meeting closed WITHOUT committing, so the caller decides the
    transaction boundary. Returns True when this call did the closing.
    """
    if session_row.ended_at is not None:
        return False
    session_row.active = False
    session_row.ended_at = _utcnow()
    session_row.ended_by_id = getattr(current_user, 'id', None)
    record_audit('session.end', 'class_session', session_row.id,
                 session_row.title, course_id=session_row.course_id,
                 reason=reason)
    return True


def end_class_session(session_row, reason='ended'):
    """
    Close a meeting: no further scan can land on it, whatever token it holds.

    Ending is a server-side fact, not a page the browser navigated away from.
    The cached token is dropped too, so a projector screenshot taken a second
    ago stops working immediately rather than at the end of its window.
    """
    if _close_session_row(session_row, reason):
        db.session.commit()

    _invalidate_session_caches(session_row)
    return session_row


def _invalidate_session_caches(session_row):
    """Drop the live token, its rendered PNG and the pinned classroom."""
    if not redis_client:
        _local_locations.pop(session_row.course_id, None)
        return
    try:
        token_key = f"qr_token:session:{session_row.id}"
        token = _redis_timed('get', redis_client.get, token_key)
        keys = [token_key, f"attendees_summary:{session_row.id}"]
        if token:
            keys.append(f"qr_png:{token.decode()}")
        # The classroom pin is per course and only meaningful while a class is
        # running; leaving it behind geofences the NEXT class against the last
        # room used.
        if open_session_for(session_row.course_id) is None:
            keys.append(f"class_location:{session_row.course_id}")
        _redis_timed('delete', redis_client.delete, *keys)
    except redis.RedisError:
        runtime_metrics.increment('redis.invalidation_errors')


def resume_or_start_session(course, kind='Lecture', force_new=False, title=None):
    """
    Resume the meeting that is currently OPEN, or start a new one.

    "Open", not "started today": a refresh of the projector page must land
    back on the same session, but tomorrow — and the tutorial after lunch —
    must get their own. Ending a class is what closes the old one.
    """
    with _course_lock(course.id):
        _take_course_advisory_lock(course.id)

        if not force_new:
            existing = open_session_for(course.id)
            if existing:
                db.session.commit()
                return existing

        # Starting a new meeting closes whatever was left running, so a
        # lecturer who forgot to press End Class does not have two live
        # sessions competing for the same scans.
        #
        # Closing and creating happen in ONE transaction, because the
        # advisory lock is held only until the transaction ends. Committing
        # the close first would drop the lock in the gap before the new
        # session exists, and a second worker arriving in that gap would see
        # no open session and create one of its own — two live meetings, the
        # exact outcome the lock is here to prevent.
        stale = open_session_for(course.id)
        if stale:
            _close_session_row(stale, reason='superseded')

        session_row = create_class_session(course, kind=kind, title=title)
        if stale:
            # After the commit: this is Redis, not part of the transaction.
            _invalidate_session_caches(stale)
        return session_row


@app.route('/generate_qr/<int:course_id>', methods=['POST'])
@login_required
def generate_qr(course_id):
    """
    Legacy entry point: opens (or resumes) the course's live session.

    POST, because it CREATES one. As a GET, any cross-site top-level
    navigation — a link, a redirect, an <img> — opened a class session in a
    lecturer's name, and every student enrolled at that moment was then
    counted absent for a class that never happened.
    """
    course = db.get_or_404(Course, course_id)
    if not _is_course_authorized(course):
        flash('Unauthorised Access', 'error')
        return redirect(url_for('dashboard'))
    session_row = resume_or_start_session(course)
    return redirect(url_for('session_qr', session_id=session_row.id))


@app.route('/session/<int:session_id>/qr')
@login_required
def session_qr(session_id):
    """Live QR projector page for ONE class session."""
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _is_course_authorized(course):
        flash('Unauthorised Access', 'error')
        return redirect(url_for('dashboard'))

    if not session_row.is_open:
        flash("This class has ended. Its register is below; start a new "
              "session to take attendance again.", "info")
        return redirect(url_for('view_attendance', course_id=course.id))

    expected = _session_expected_counts([session_row.id]).get(session_row.id, 0)
    return render_template('generate_qr.html', course=course, session=session_row,
                           qr_token_ttl=QR_TOKEN_TTL,
                           expected_total=expected,
                           projector_recent_rows=PROJECTOR_RECENT_ROWS,
                           geofence_required=GEOFENCE_REQUIRED)


@app.route('/session/<int:session_id>/end', methods=['POST'])
@login_required
def end_session(session_id):
    """End a running class. The button used to be a link to the dashboard."""
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _is_course_authorized(course):
        flash('Unauthorised Access', 'error')
        return redirect(url_for('dashboard'))

    if session_row.is_open:
        end_class_session(session_row)
        flash(f'"{session_row.title}" has ended. Its QR code no longer works.',
              'success')
    else:
        flash(f'"{session_row.title}" had already ended.', 'info')
    return redirect(url_for('view_attendance', course_id=course.id))


@app.route('/api/qr_data/<int:session_id>')
@login_required
@limiter.exempt
def get_qr_data(session_id):
    """
    FIX #6: Returns the same cached signed token as the image endpoint.
    FIX #3: Token is HMAC-signed so it cannot be forged.
    """
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403
    if not session_row.is_open:
        return jsonify({"error": "This class has ended.", "ended": True}), 409

    qr_text = generate_signed_qr(session_id)
    return jsonify({"qr_text": qr_text})


@app.route('/session/<int:session_id>/live')
@login_required
@limiter.exempt
def get_qr_image(session_id):
    """
    FIX #6: Uses the same shared cached token as /api/qr_data.
    FIX #3: Token is HMAC-signed.
    """
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _is_course_authorized(course):
        return "Unauthorised", 403
    if not session_row.is_open:
        return "This class has ended.", 409

    qr_text = generate_signed_qr(session_id)

    # The projector page re-fetches this image on an interval; render the
    # PNG once per token and share it via Redis for the token's lifetime
    # instead of re-encoding on every poll.
    png_cache_key = f"qr_png:{qr_text}"
    if redis_client:
        cached_png = _redis_timed('get', redis_client.get, png_cache_key)
        if cached_png:
            return send_file(io.BytesIO(cached_png), mimetype='image/png')

    try:
        import qrcode
        img = qrcode.make(qr_text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()
        if redis_client:
            _redis_timed('setex', redis_client.setex,
                         png_cache_key, QR_TOKEN_TTL, png_bytes)
        return send_file(io.BytesIO(png_bytes), mimetype='image/png')
    except ImportError:
        return "QR code library not installed", 500


@app.route('/api/session/<int:session_id>/attendees')
@login_required
@limiter.exempt
def get_session_attendees(session_id):
    """Incremental roll-call feed; ``after`` is the last attendance id seen."""
    feed_started = time.perf_counter()
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403

    # Every open projector screen polls this every 3 seconds, so it has to
    # stay cheap even with 2000 scans in one session: a short shared cache
    # plus one JOINed query (the old version lazy-loaded each row's student
    # — 2000 extra queries per poll — and loaded every enrolled User just
    # to count them).
    after_id = max(0, request.args.get('after', default=0, type=int) or 0)
    batch_size = min(500, max(1, request.args.get('limit', default=250, type=int) or 250))
    cache_key = f"attendees_summary:{session_id}"
    present = enrolled_total = None

    # Redis is an accelerator here, never a dependency. Postgres can answer
    # both of these; a cache that has gone unhealthy must cost the lecturer
    # some database load, not the ability to see who is in the room.
    if redis_client:
        try:
            cached = _redis_timed('get', redis_client.get, cache_key)
            if cached:
                summary = json.loads(cached)
                present = int(summary['present'])
                enrolled_total = int(summary['enrolled'])
        except (redis.RedisError, TypeError, ValueError, KeyError,
                json.JSONDecodeError):
            runtime_metrics.increment('redis.feed_cache_errors')
            present = enrolled_total = None

    if present is None:
        present = (db.session.query(func.count(Attendance.id))
                   .filter(Attendance.session_id == session_id)
                   .scalar()) or 0
        enrolled_total = _enrolled_count(course.id)
        if redis_client:
            try:
                _redis_timed('setex', redis_client.setex, cache_key,
                             ATTENDEE_SUMMARY_TTL, json.dumps({
                                 'present': present,
                                 'enrolled': enrolled_total,
                             }))
            except redis.RedisError:
                runtime_metrics.increment('redis.feed_cache_errors')

    rows = (db.session.query(Attendance.id, Attendance.timestamp, User.full_name,
                             User.matric_no, User.level)
            .join(User, User.id == Attendance.student_id)
            .filter(Attendance.session_id == session_id,
                    Attendance.id > after_id)
            .order_by(Attendance.id.asc())
            .limit(batch_size + 1)
            .all())
    has_more = len(rows) > batch_size
    rows = rows[:batch_size]
    attendees = [{
        "id": attendance_id,
        "name": full_name or "Unknown",
        "matric_no": matric_no or "N/A",
        "level": level or "N/A",
        # Local time: the lecturer is watching this list in the room.
        "time": local_time_only(ts),
    } for attendance_id, ts, full_name, matric_no, level in rows]

    payload = {
        "status": "success",
        "present": present,
        "enrolled": enrolled_total,
        "new_attendees": attendees,
        "last_id": attendees[-1]['id'] if attendees else after_id,
        "has_more": has_more,
    }
    runtime_metrics.observe_ms(
        'attendee_feed.response', (time.perf_counter() - feed_started) * 1000
    )
    runtime_metrics.increment('attendee_feed.requests')
    return jsonify(payload)


@app.route('/scan_page')
@login_required
def scan_page():
    # scan.html renders a "My Attendance Records" table guarded on
    # `attendance_data`. Rendering without it meant every student always saw
    # the "you haven't marked attendance yet" empty state, however many
    # classes they had actually attended.
    _courses, attendance_data = _student_attendance_summary()
    return render_template('scan.html', attendance_data=attendance_data)


def _read_pin(data):
    """Validate a posted classroom pin, returning (lat, lon) or an error."""
    try:
        latitude = float(data['lat'])
        longitude = float(data['lon'])
    except (KeyError, TypeError, ValueError):
        return None, "Valid latitude and longitude are required."
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return None, "Latitude or longitude is out of range."
    return (latitude, longitude), None


@app.route('/session/<int:session_id>/set_location', methods=['POST'])
@login_required
def set_session_location(session_id):
    """
    Pin the room THIS meeting is in.

    The projector page posts here every 30 seconds while the class runs.
    """
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _is_course_authorized(course):
        return jsonify({"status": "error", "message": "Unauthorised"}), 403
    if not session_row.is_open:
        return jsonify({"status": "error", "message": "This class has ended."}), 409

    pin, problem = _read_pin(request.get_json(silent=True) or {})
    if problem:
        return jsonify({"status": "error", "message": problem}), 400

    set_class_location(session_id, *pin)
    app.logger.info('Classroom pinned for session %s (course %s)',
                    session_id, course.id)
    return jsonify({"status": "ok"})


@app.route('/set_location/<int:course_id>', methods=['POST'])
@login_required
def set_location(course_id):
    """
    Compatibility shim for a projector page cached from a previous release.

    It pins the course's currently-open meeting, because that is what the old
    course-scoped call actually meant. Without it, a lecturer whose browser is
    still running yesterday's JavaScript silently pins nothing and — with
    GEOFENCE_REQUIRED on — every scan in the room is refused.
    """
    course = db.get_or_404(Course, course_id)
    if not _is_course_authorized(course):
        return jsonify({"status": "error", "message": "Unauthorised"}), 403

    pin, problem = _read_pin(request.get_json(silent=True) or {})
    if problem:
        return jsonify({"status": "error", "message": problem}), 400

    session_row = open_session_for(course_id)
    if session_row is None:
        return jsonify({"status": "error",
                        "message": "No class is currently running."}), 409

    set_class_location(session_row.id, *pin)
    app.logger.info('Classroom pinned for session %s via the legacy '
                    'course-scoped endpoint', session_row.id)
    return jsonify({"status": "ok"})


# ============================================================
# ATTENDANCE ROUTES
# ============================================================

# ============================================================
# CAMPOS ATTENDANCE REPORTING
# ============================================================
# After attendance is recorded locally, report it to CampOS Core so it appears
# on the student's CampOS dashboard. Keyed by the shared identity (matric/email).
# Delivery stays off the scan request path and retries bounded transient errors.
# Configure CAMPOS_CORE_URL and CAMPOS_API_KEY to enable it.

def report_attendance_to_campos(
    matric_no,
    email,
    course_code,
    course_title,
    session_id,
    session_title,
    external_id,
    scanned_at_iso,
):
    if not os.environ.get('CAMPOS_API_KEY'):
        return
    try:
        report_attendance_event({
            'matricNumber': matric_no,
            'email': email,
            'courseCode': course_code,
            'courseTitle': course_title,
            'sessionId': str(session_id),
            'sessionTitle': session_title,
            'status': 'present',
            'externalId': str(external_id),
            'scannedAt': scanned_at_iso,
        })
    except CamposIntegrationError as e:
        app.logger.warning('CampOS attendance report failed: %s', e)


def _parse_client_timestamp(value):
    """
    Read a client-reported capture time as epoch seconds, or None.

    The scanner sends an ISO-8601 string; the offline queue may replay an
    older payload holding epoch milliseconds. Both are accepted, anything
    else is treated as absent rather than as an error — this is a
    corroborating signal, not the primary check.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        # Milliseconds if it is far too large to be seconds.
        return value / 1000.0 if value > 1e11 else float(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def _insert_attendance_once(student_id, course_id, session_id, device_id, scanned_at):
    """
    Insert exactly one attendance row and return its id, or None if this
    student already has a row for this class session.

    On Postgres and SQLite this is a single atomic
    ``INSERT ... ON CONFLICT DO NOTHING ... RETURNING``, so the duplicate
    decision is made by the database and no separate SELECT is needed. The
    unique index on (student_id, session_id) is what makes it safe: two
    simultaneous requests cannot both win.
    """
    values = {
        'student_id': student_id,
        'course_id': course_id,
        'session_id': session_id,
        'device_id': device_id,
        'timestamp': scanned_at,
    }
    dialect = db.session.get_bind().dialect.name

    if dialect in {'postgresql', 'sqlite'}:
        if dialect == 'postgresql':
            from sqlalchemy.dialects.postgresql import insert as _conflict_insert
        else:
            from sqlalchemy.dialects.sqlite import insert as _conflict_insert
        statement = (_conflict_insert(Attendance)
                     .values(**values)
                     .on_conflict_do_nothing(
                         index_elements=['student_id', 'session_id'])
                     .returning(Attendance.id))
        record_id = db.session.execute(statement).scalar_one_or_none()
        if record_id is None:
            db.session.rollback()
            return None
        db.session.commit()
        return record_id

    # Any other dialect: fall back to insert-and-catch, which relies on the
    # same unique index rather than an application-level check.
    try:
        record = Attendance(**values)
        db.session.add(record)
        db.session.commit()
        return record.id
    except IntegrityError:
        db.session.rollback()
        return None


# ------------------------------------------------------------------
# BURST ADMISSION CONTROL
# ------------------------------------------------------------------
# A lecturer puts the code on the projector and two thousand phones fire at
# once. Every one of those requests can otherwise walk independently into the
# database, so the arrival rate — not the sustainable rate — decides how much
# work Postgres is asked to do in the first second. Past its capacity that
# does not degrade gently: connections queue, latency crosses the QR window,
# scans start bouncing as "expired", and the phones retry, which is the burst
# again but larger.
#
# A token bucket per session smooths the microburst down to a rate the
# database is measured to sustain. It is emphatically NOT a queue: a shed scan
# is told to retry in well under a second, because attendance is time-sensitive
# and hiding overload for minutes would be worse than refusing it. The point is
# to convert a 1,000/sec spike into a steady admitted rate, not to absorb a
# genuine overload.
#
# Set SCAN_ADMISSION_RATE from the staging matrix — the measured safe rate for
# YOUR database plan. It defaults to 0 (off), because a number invented here
# would be a guess with the authority of a default.
SCAN_ADMISSION_RATE = float(os.environ.get('SCAN_ADMISSION_RATE', 0))

# How much instantaneous burst is allowed through untouched before shaping
# begins. One second's worth by default: a class that arrives inside the
# sustainable rate never sees this code at all.
SCAN_ADMISSION_BURST = float(
    os.environ.get('SCAN_ADMISSION_BURST') or max(SCAN_ADMISSION_RATE, 1)
)

# What a shed phone is told to wait. Deliberately sub-second.
SCAN_ADMISSION_RETRY_SECONDS = float(
    os.environ.get('SCAN_ADMISSION_RETRY_SECONDS', 0.5)
)

# Atomic token bucket. Lua because the read-modify-write has to be one
# operation: with 2,000 callers, a GET/SET pair admits far more than the rate.
_ADMISSION_LUA = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'updated')
local tokens = tonumber(bucket[1])
local updated = tonumber(bucket[2])

if tokens == nil then
  tokens = burst
  updated = now
end

-- Refill for the time that has passed, capped at the burst size.
local elapsed = math.max(0, now - updated)
tokens = math.min(burst, tokens + elapsed * rate)

local admitted = 0
if tokens >= 1 then
  tokens = tokens - 1
  admitted = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'updated', now)
redis.call('EXPIRE', key, ttl)
return admitted
"""

_admission_script = None


def _admission_key(session_id):
    return f"scanburst:{session_id}"


def admit_scan(session_id):
    """
    True when this scan may proceed to the database right now.

    Fails OPEN: if Redis is unavailable or the script errors, the scan is
    admitted. A limiter outage must never become an attendance outage — the
    worst case without shaping is the behaviour this code was added to
    improve, not a loss of the register.
    """
    if SCAN_ADMISSION_RATE <= 0 or redis_client is None:
        return True

    global _admission_script
    try:
        if _admission_script is None:
            _admission_script = redis_client.register_script(_ADMISSION_LUA)
        admitted = _admission_script(
            keys=[_admission_key(session_id)],
            args=[SCAN_ADMISSION_RATE, SCAN_ADMISSION_BURST, time.time(),
                  max(60, int(SCAN_ADMISSION_BURST / max(SCAN_ADMISSION_RATE, 0.001)) + 60)],
        )
        return bool(admitted)
    except redis.RedisError as error:
        runtime_metrics.increment('scan.admission.errors')
        app.logger.warning('Scan admission control unavailable, admitting: %s',
                           error)
        return True


# ------------------------------------------------------------------
# SCAN RESPONSE BUDGET
# ------------------------------------------------------------------
# The contract each stage of a scan is held to, in milliseconds. Breaching one
# is not an error the student sees — it is a counter that says WHICH part of
# the system is the problem during a rehearsal, so "the scan got slow" becomes
# "Postgres insertion is fine, Redis is the problem" without guesswork.
#
# Derive these from your own staging run; the defaults are a starting shape
# sized so the total sits an order of magnitude inside QR_CODE_WINDOW.
SCAN_STAGE_BUDGET_MS = {
    'qr_verify': float(os.environ.get('BUDGET_QR_VERIFY_MS', 1)),
    'session_course': float(os.environ.get('BUDGET_SESSION_COURSE_MS', 10)),
    'enrollment': float(os.environ.get('BUDGET_ENROLLMENT_MS', 10)),
    'admission': float(os.environ.get('BUDGET_ADMISSION_MS', 5)),
    'geofence': float(os.environ.get('BUDGET_GEOFENCE_MS', 5)),
    'db_insert': float(os.environ.get('BUDGET_DB_INSERT_MS', 20)),
    'enqueue': float(os.environ.get('BUDGET_ENQUEUE_MS', 5)),
}
SCAN_TOTAL_BUDGET_MS = float(os.environ.get('BUDGET_SCAN_TOTAL_MS', 100))


# Fraction of SUCCESSFUL scans that get a timing line in the log. Every
# non-success outcome is always logged. 2% keeps a 2000-scan class to ~40
# lines instead of 2000 while still giving a latency sample.
SCAN_LOG_SAMPLE_RATE = max(0.0, min(1.0, float(
    os.environ.get('SCAN_LOG_SAMPLE_RATE', '0.02')
)))


@app.route('/mark_attendance', methods=['POST'])
@limiter.limit("10 per minute", error_message="Too many scan attempts. Please wait.")
@login_required
def mark_attendance():
    """
    Record one scan.

    Every rejection carries a real HTTP status code, because the phone
    scanner decides whether to stop, retry or back off from that status:
      400  the token is malformed, expired,   -> a fresh code may work
           or was not read from the screen
           just now
      403  not enrolled                       -> terminal
      404  the session no longer exists       -> terminal
      409  already marked; the class has      -> terminal
           ended; the course is archived; or
           a queued scan belonging to a
           different account
      422  location missing/stale/imprecise/  -> retryable once they move
           too far
      429  rate limited (from the limiter)    -> back off
      5xx  server fault                       -> back off
    Returning 200 for all of these is what put rejected phones into an
    endless resubmit loop.

    Every response also carries a machine-readable ``outcome``, because the
    status alone no longer identifies the reason: 409 covers both "you are
    already on the register" (fine) and "that class had ended" (not fine), and
    the offline queue must not report the second as a success.
    """
    request_started = time.perf_counter()
    stage_started = request_started
    stages = {}

    def checkpoint(name):
        nonlocal stage_started
        now = time.perf_counter()
        duration_ms = (now - stage_started) * 1000
        stages[name] = duration_ms
        runtime_metrics.observe_ms(f'scan.stage.{name}', duration_ms)
        # Which stage broke its contract, counted separately from how long it
        # took. During a rehearsal this is the difference between "scans are
        # slow" and "db_insert is over budget and nothing else is".
        budget = SCAN_STAGE_BUDGET_MS.get(name)
        if budget and duration_ms > budget:
            runtime_metrics.increment(f'scan.budget_exceeded.{name}')
        stage_started = now

    def respond(status, message, http_status, outcome, headers=None):
        total_ms = (time.perf_counter() - request_started) * 1000
        runtime_metrics.observe_ms('scan.response', total_ms)
        runtime_metrics.increment(f'scan.outcome.{outcome}')
        if total_ms > SCAN_TOTAL_BUDGET_MS:
            runtime_metrics.increment('scan.budget_exceeded.total')
        if status != 'success' or secrets.randbelow(10000) < int(SCAN_LOG_SAMPLE_RATE * 10000):
            app.logger.info('scan_performance %s', json.dumps({
                'outcome': outcome,
                'total_ms': round(total_ms, 2),
                'stages_ms': {key: round(value, 2) for key, value in stages.items()},
            }, separators=(',', ':')))
        # `outcome` is the machine-readable reason. The offline queue needs it:
        # 409 now covers "already marked" (a success from where the student
        # stands) as well as "the class had ended" and "that queued scan is
        # somebody else's", which are emphatically not.
        response = jsonify({'status': status, 'message': message,
                            'outcome': outcome})
        if stages:
            response.headers['Server-Timing'] = ', '.join(
                f'{name};dur={value:.2f}' for name, value in stages.items()
            )
        for header, value in (headers or {}).items():
            response.headers[header] = value
        return response, http_status

    data = request.get_json(silent=True) or {}

    try:
        qr_text = data.get('qr_data')
        if not qr_text:
            return respond('error', 'No QR data provided.', 400, 'missing_qr')

        try:
            session_id, _token_timestamp = verify_signed_qr(qr_text)
        except ValueError as error:
            return respond('error', str(error), 400, 'invalid_qr')
        checkpoint('qr_verify')

        # Session and course in one join instead of two point lookups.
        target = db.session.execute(
            select(
                ClassSession.id.label('session_id'),
                ClassSession.title.label('session_title'),
                ClassSession.active.label('session_active'),
                ClassSession.ended_at.label('session_ended_at'),
                Course.id.label('course_id'),
                Course.code.label('course_code'),
                Course.title.label('course_title'),
                Course.archived.label('course_archived'),
            )
            .join(Course, Course.id == ClassSession.course_id)
            .where(ClassSession.id == session_id)
        ).mappings().one_or_none()
        checkpoint('session_course')
        if target is None:
            return respond('error', 'Invalid QR Code: Class session not found.',
                           404, 'missing_session')

        # "End Class" has to mean something here, or it means nothing at all.
        # Checking the token's age alone left every code minted in the last
        # QR_CODE_WINDOW seconds redeemable after the lecturer ended the
        # class — including a photograph of the projector taken on the way
        # out. The session's state is authoritative, not the token's age.
        if not target['session_active'] or target['session_ended_at'] is not None:
            return respond('error',
                           'This class has ended. Attendance is closed.',
                           409, 'session_ended')

        if target['course_archived']:
            return respond('error', 'This course is archived.',
                           409, 'course_archived')

        # A scan replayed from another phone's offline queue must never land
        # on whoever happens to be signed in now.
        user_marker = data.get('user_marker')
        if user_marker is not None and str(user_marker) != str(current_user.id):
            return respond('error', 'That queued scan belongs to a different account.',
                           409, 'wrong_user_queue')

        # Indexed existence check rather than materialising every course the
        # student is enrolled on.
        enrolled = db.session.execute(
            select(enrollments.c.user_id)
            .where(enrollments.c.user_id == current_user.id,
                   enrollments.c.course_id == target['course_id'])
            .limit(1)
        ).scalar_one_or_none()
        checkpoint('enrollment')
        if enrolled is None:
            return respond(
                'error',
                f"Access denied: you are not registered for {target['course_code']}.",
                403,
                'not_enrolled',
            )

        # Admission control sits here on purpose: after the cheap rejections
        # (a forged token, a closed class, a student who is not on the course
        # should never consume a token) and before anything touches the
        # database. It shapes the arrival rate into the write path, which is
        # the only part of this request that Postgres has to absorb.
        if not admit_scan(target['session_id']):
            runtime_metrics.increment('scan.admission.shed')
            return respond(
                'error',
                'The class is being marked very quickly right now. '
                'Your scan was not lost — please try again in a moment.',
                429,
                'admission_throttled',
                headers={'Retry-After': str(max(1, round(SCAN_ADMISSION_RETRY_SECONDS)))},
            )
        runtime_metrics.increment('scan.admission.admitted')
        checkpoint('admission')

        # How long ago the CLIENT says it read the code. Checked against the
        # token timestamp rather than the arrival time, so a scan that queued
        # offline is still judged on when the camera actually saw the screen.
        captured_epoch = _parse_client_timestamp(data.get('captured_at'))
        if captured_epoch is None:
            if REQUIRE_CAPTURED_AT:
                # A security signal the client omitted is not a signal that
                # does not apply. Skipping the freshness check whenever
                # `captured_at` failed to parse made omitting it the way to
                # avoid it — the same shape of hole `accuracy_m` and
                # `location_age_ms` had.
                return respond('error',
                               'Your device did not report when it read the code. '
                               'Please reload the scan page and try again.',
                               400, 'missing_capture_time')
        else:
            capture_lag = captured_epoch - _token_timestamp
            if capture_lag > QR_CAPTURE_WINDOW or capture_lag < -QR_CAPTURE_WINDOW:
                return respond('error',
                               'That code was not read from the screen just now. '
                               'Please scan the current code.',
                               400, 'capture_out_of_window')

        class_loc = get_class_location(target['session_id'], target['course_id'])
        if class_loc:
            try:
                student_lat = float(data['lat'])
                student_lon = float(data['lon'])
            except (KeyError, TypeError, ValueError):
                return respond('error', 'Location required. Please allow GPS access.',
                               422, 'missing_location')
            if not (-90 <= student_lat <= 90 and -180 <= student_lon <= 180):
                return respond('error', 'Location coordinates are invalid.',
                               422, 'invalid_location')

            # These fields were accepted-if-present and ignored otherwise, so
            # the way past every proximity check was to leave them out. They
            # are required now, and a value outside its plausible range is a
            # rejection rather than a shrug.
            #
            # None of this makes a browser's coordinates trustworthy — they
            # are self-reported and a determined student can override the
            # geolocation API. It removes the trivial paths and bounds the
            # rest; the register is evidence of a scan, not of a body in a
            # seat.
            location_age_ms = data.get('location_age_ms')
            if not isinstance(location_age_ms, (int, float)) or isinstance(location_age_ms, bool):
                return respond('error',
                               'Your device did not report how fresh its location is. '
                               'Please allow GPS access and scan again.',
                               422, 'missing_location_age')
            if location_age_ms < 0 or location_age_ms > GEOFENCE_MAX_LOCATION_AGE_MS:
                return respond('error', 'Location fix is stale. Please scan again.',
                               422, 'stale_location')

            accuracy_m = data.get('accuracy_m')
            if not isinstance(accuracy_m, (int, float)) or isinstance(accuracy_m, bool):
                return respond('error',
                               'Your device did not report its location accuracy. '
                               'Please allow precise GPS access and scan again.',
                               422, 'missing_location_accuracy')
            if accuracy_m < 0 or accuracy_m > GEOFENCE_MAX_ACCURACY_M:
                return respond(
                    'error',
                    f'Your location is only accurate to {int(accuracy_m)}m, which is '
                    f'too imprecise to confirm you are in the classroom. Move '
                    f'towards a window and scan again.',
                    422, 'imprecise_location',
                )

            distance_m = calculate_distance(
                class_loc['lat'], class_loc['lon'], student_lat, student_lon
            )
            if distance_m > GEOFENCE_RADIUS_M:
                return respond(
                    'error',
                    f'Too far from the classroom. You are {int(distance_m)}m away '
                    f'(max {GEOFENCE_RADIUS_M}m).',
                    422,
                    'outside_geofence',
                )
        elif GEOFENCE_REQUIRED:
            # Opt-in strict mode: no pinned classroom means no proof of
            # presence, so refuse rather than silently accepting from anywhere.
            app.logger.warning(
                'Scan refused: GEOFENCE_REQUIRED is on and course %s has no pinned location',
                target['course_id'],
            )
            return respond(
                'error',
                'This class has no pinned location yet. Ask your lecturer to '
                'allow location access on the QR screen.',
                422,
                'no_class_location',
            )
        checkpoint('geofence')

        client_metrics = data.get('client_metrics')
        if isinstance(client_metrics, dict):
            for metric_name in ('camera_ready_ms', 'qr_decode_ms',
                                'gps_wait_ms', 'capture_to_request_ms'):
                value = client_metrics.get(metric_name)
                if isinstance(value, (int, float)) and 0 <= value <= 120000:
                    runtime_metrics.observe_ms(f'client.{metric_name}', value)

        scanned_at = _utcnow()
        record_id = _insert_attendance_once(
            current_user.id,
            target['course_id'],
            target['session_id'],
            str(data.get('device_id') or 'browser')[:200],
            scanned_at,
        )
        checkpoint('db_insert')
        if record_id is None:
            return respond(
                'error',
                'You are already marked present for this class.',
                409,
                'duplicate',
            )

        # Deliberately NO cache invalidation here. The lecturer's headcount is
        # cached for ATTENDEE_SUMMARY_TTL seconds, so it is at most that stale
        # whether or not each scan deletes the key — and deleting it made every
        # one of 2,000 scans do a Redis round trip inside the request, to buy
        # back at most two seconds on a number that is already moving. Redis
        # accelerates the lecturer's reads; it is not on the write path.

        scanned_iso = scanned_at.isoformat() + 'Z'
        if campos_executor.submit(
            report_attendance_to_campos,
            current_user.matric_no,
            current_user.email,
            target['course_code'],
            target['course_title'],
            target['session_id'],
            target['session_title'],
            f'scanmark-attendance:{record_id}',
            scanned_iso,
        ) is None:
            app.logger.warning(
                'CampOS delivery queue full; attendance id %s not reported', record_id)

        # Nothing else happens on a scan. A scan used to queue a confirmation
        # email, a WhatsApp, parent copies of both and an attendance-threshold
        # check — five extra queries and up to four outbound jobs per student,
        # all of it courtesy traffic nobody asked for. The register is the
        # record; students read it on their dashboard.
        checkpoint('enqueue')

        return respond('success', 'Attendance marked successfully!', 200, 'success')

    except PoolTimeoutError:
        # Saturation, not a fault. Told apart from a 500 so the scanner backs
        # off and retries instead of treating it as terminal, and so the
        # metric that fires points at the database rather than at this code.
        db.session.rollback()
        runtime_metrics.increment('db.pool.exhausted')
        app.logger.error('Scan refused: no database connection available')
        return respond(
            'error',
            'The system is very busy right now. Please try again in a moment '
            '— your scan was not recorded.',
            503, 'database_saturated',
            headers={'Retry-After': str(max(1, int(
                os.environ.get('DB_SATURATION_RETRY_SECONDS', 2))))},
        )
    except Exception:
        # Leave no half-finished transaction on this connection for whichever
        # request picks it up next.
        db.session.rollback()
        app.logger.exception('Server error in mark_attendance')
        return respond('error', 'An unexpected server error occurred.',
                       500, 'server_error')


@app.route('/course/<int:course_id>/attendance')
@login_required
def view_attendance(course_id):
    """
    Attendance records grouped BY CLASS SESSION: each weekly lecture is its
    own sheet (who was present that day), instead of one flat pile of scans.
    """
    course = db.get_or_404(Course, course_id)

    if not _attendance_authorized(course):  # FIX #8
        flash("Unauthorised access to attendance list.", "error")
        return redirect(url_for('dashboard'))

    page = max(1, request.args.get('page', default=1, type=int) or 1)
    pagination = (ClassSession.query
                  .filter_by(course_id=course_id)
                  .order_by(ClassSession.date_created.desc())
                  .paginate(page=page, per_page=10, error_out=False))
    sessions = pagination.items
    session_ids = [sess.id for sess in sessions]

    enrolled_total = _enrolled_count(course_id)
    # The roster as it stood at each meeting — the only correct denominator
    # for a class that already happened.
    expected_by_session = _session_expected_counts(session_ids)
    present_by_session = dict(
        db.session.query(Attendance.session_id, func.count(Attendance.id))
        .filter(Attendance.session_id.in_(session_ids or [-1]))
        .group_by(Attendance.session_id).all())

    # Only a bounded preview of each sheet is rendered. Ten sessions of a
    # 2000-student course is 20,000 ORM objects and 20,000 table rows in one
    # HTML document — minutes to build, tens of megabytes to send, and a page
    # a phone cannot open. The full sheet has its own paginated page and its
    # own CSV.
    records_by_session = {}
    for sess in sessions:
        records_by_session[sess.id] = (
            db.session.query(Attendance.id, Attendance.timestamp,
                             User.full_name, User.matric_no, User.level)
            .join(User, User.id == Attendance.student_id)
            .filter(Attendance.session_id == sess.id)
            .order_by(Attendance.timestamp.asc(), Attendance.id.asc())
            .limit(ATTENDANCE_PREVIEW_ROWS)
            .all())

    sessions_data = []
    for sess in sessions:
        present = present_by_session.get(sess.id, 0)
        expected = expected_by_session.get(sess.id, 0)
        sessions_data.append({
            'session': sess,
            'records': records_by_session.get(sess.id, []),
            'present': present,
            'expected': expected,
            'pct': _attendance_percentage(present, expected),
            'truncated': present > ATTENDANCE_PREVIEW_ROWS,
        })

    total_scans = (db.session.query(func.count(Attendance.id))
                   .filter(Attendance.course_id == course_id,
                           Attendance.session_id.isnot(None))
                   .scalar()) or 0
    # pagination.total is every session the course has held. The header used
    # to print len(sessions_data), which is the number on THIS page — capped
    # at ten however long the semester ran.
    classes_held = pagination.total
    avg_present = round(total_scans / classes_held) if classes_held else 0

    # Rows that never got adopted by the startup backfill (shouldn't happen)
    unassigned = Attendance.query.filter_by(course_id=course_id) \
                                 .filter(Attendance.session_id.is_(None)).count()

    return render_template('view_attendance.html',
                           course=course,
                           sessions_data=sessions_data,
                           enrolled_total=enrolled_total,
                           classes_held=classes_held,
                           total_scans=total_scans,
                           avg_present=avg_present,
                           unassigned=unassigned,
                           preview_rows=ATTENDANCE_PREVIEW_ROWS,
                           pagination=pagination,
                           can_manage=_is_course_authorized(course),
                           can_delete=_owns_course(course))


@app.route('/session/<int:session_id>/attendance')
@login_required
def session_attendance(session_id):
    """The full sheet for one meeting, a page at a time."""
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)
    if not _attendance_authorized(course):
        flash("Unauthorised access to attendance list.", "error")
        return redirect(url_for('dashboard'))

    page = max(1, request.args.get('page', default=1, type=int) or 1)
    pagination = (db.session.query(Attendance.id, Attendance.timestamp,
                                   User.full_name, User.matric_no, User.level)
                  .join(User, User.id == Attendance.student_id)
                  .filter(Attendance.session_id == session_id)
                  .order_by(Attendance.timestamp.asc(), Attendance.id.asc())
                  .paginate(page=page, per_page=100, error_out=False))

    expected = _session_expected_counts([session_id]).get(session_id, 0)
    return render_template('session_attendance.html',
                           course=course, session=session_row,
                           records=pagination.items, pagination=pagination,
                           expected=expected,
                           pct=_attendance_percentage(pagination.total, expected),
                           can_manage=_is_course_authorized(course))


#: Characters that make a spreadsheet treat a cell as a formula rather than
#: text. Quoting alone does not stop this — Excel, LibreOffice and Sheets all
#: parse the cell AFTER unquoting it.
_CSV_FORMULA_LEADERS = ('=', '+', '-', '@', '\t', '\r')


def _csv_cell(value):
    """
    Quote a value for CSV, escaping embedded double quotes, and neutralise
    anything a spreadsheet would execute.

    A student whose "full name" is ``=HYPERLINK("http://evil","payroll")`` —
    or the classic ``=cmd|'/c calc'!A0`` — becomes a live formula the moment a
    lecturer opens the register, running in their session with their files. A
    leading apostrophe is the standard neutraliser: spreadsheets read the rest
    as literal text and do not display it.
    """
    text = str(value if value is not None else "N/A")
    if text.startswith(_CSV_FORMULA_LEADERS):
        text = "'" + text
    return '"' + text.replace('"', '""') + '"'


class _StreamingCSVBuffer:
    """Append-compatible CSV spool which streams and spills beyond 1 MiB."""

    def __init__(self, initial=''):
        self._file = tempfile.SpooledTemporaryFile(
            max_size=1024 * 1024, mode='w+t', encoding='utf-8', newline=''
        )
        self._file.write(initial)

    def __iadd__(self, value):
        self._file.write(value)
        return self

    def __iter__(self):
        self._file.seek(0)
        try:
            while True:
                chunk = self._file.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            self._file.close()


@app.route('/course/<int:course_id>/download_csv')
@login_required
def download_csv(course_id):
    """
    Without ?session_id: the SEMESTER REGISTER — one row per student, one
    column per class session held, plus attended/total/% columns.
    With ?session_id=<id>: the sheet for that single class meeting.
    """
    course = db.get_or_404(Course, course_id)

    # The register carries every enrolled student's name and matric number, so
    # it follows the same rule as the on-screen attendance view.
    if not _attendance_authorized(course):
        return "Unauthorised", 403

    # Course codes reach an HTTP header here. A stored code containing CR/LF
    # made werkzeug refuse the Content-Disposition value and turned the export
    # into a 500 — and a header an attacker can put newlines into is a header
    # they can add lines to.
    safe_code = _safe_filename(course.code, 'course')
    session_id = request.args.get('session_id', type=int)

    # ── Single-session sheet ──
    if session_id:
        sess = ClassSession.query.filter_by(id=session_id, course_id=course_id).first_or_404()
        # One JOINed query (attendances + their students) instead of a lazy
        # student lookup per scanned row.
        session_records = (Attendance.query
                           .options(joinedload(Attendance.student))
                           .filter_by(session_id=sess.id)
                           .all())
        records = {rec.student_id: rec for rec in session_records}

        # Who was expected AT THIS MEETING, from the snapshot taken when it
        # opened — not who happens to be enrolled today. A student who joined
        # afterwards has no business appearing as "Absent" on this sheet.
        expected_students = (db.session.query(User)
                             .join(SessionRoster,
                                   SessionRoster.student_id == User.id)
                             .filter(SessionRoster.session_id == sess.id)
                             .all())
        if not expected_students:
            # A session that predates roster snapshots: fall back to the
            # current roster, which is the best evidence available.
            expected_students = list(course.students) if hasattr(course, 'students') else []

        csv_data = _StreamingCSVBuffer(
            "Matric Number,Full Name,Level,Status,Time Scanned,Device ID\n"
        )
        listed_ids = set()
        for student in sorted(expected_students,
                              key=lambda s: (s.matric_no or '', s.full_name or '')):
            listed_ids.add(student.id)
            rec = records.get(student.id)
            if rec:
                time_str = format_local(rec.timestamp, '%Y-%m-%d %I:%M %p') or "N/A"
                device = rec.device_id or "N/A"
                row = [student.matric_no, student.full_name, student.level, "Present", time_str, device]
            else:
                row = [student.matric_no, student.full_name, student.level, "Absent", "-", "-"]
            csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

        # Scans from students who were not on that day's roster (kept for the
        # record — a late enrolment who attended anyway, or a since-removed
        # student).
        for rec in session_records:
            if rec.student_id in listed_ids:
                continue
            student = rec.student
            time_str = format_local(rec.timestamp, '%Y-%m-%d %I:%M %p') or "N/A"
            row = [student.matric_no if student else "UNKNOWN",
                   (student.full_name if student else "Deleted User") + " (not on roster)",
                   student.level if student else "N/A",
                   "Present", time_str, rec.device_id or "N/A"]
            csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

        date_tag = format_local(sess.date_created, '%Y-%m-%d') or "session"
        return Response(
            csv_data,
            mimetype='text/csv',
            headers=_attachment_headers(f"{safe_code}_{date_tag}_attendance.csv"),
        )

    # ── Full semester register ──
    sessions = (ClassSession.query
                .filter_by(course_id=course_id)
                .order_by(ClassSession.date_created.asc())
                .all())

    # student_id -> set of session_ids attended.
    # One JOINed query over the whole course instead of a lazy attendances
    # load per session plus a lazy student load per scan row.
    all_records = (Attendance.query
                   .options(joinedload(Attendance.student))
                   .filter(Attendance.course_id == course_id,
                           Attendance.session_id.isnot(None))
                   .all())
    attended_map = {}
    students_by_id = {}
    for rec in all_records:
        attended_map.setdefault(rec.student_id, set()).add(rec.session_id)
        if rec.student:
            students_by_id[rec.student_id] = rec.student

    enrolled = list(course.students) if hasattr(course, 'students') else []
    enrolled_ids = {s.id for s in enrolled}
    for s in enrolled:
        students_by_id[s.id] = s

    # Who was on the roster for each meeting. This is what makes "Classes
    # Held" mean "classes held while this student was enrolled" — the figure
    # the percentage is actually of.
    rostered_by_student = {}
    for student_id, roster_session_id in db.session.query(
            SessionRoster.student_id, SessionRoster.session_id).filter(
            SessionRoster.course_id == course_id).all():
        rostered_by_student.setdefault(student_id, set()).add(roster_session_id)

    session_labels = []
    for sess in sessions:
        date_str = format_local(sess.date_created, '%Y-%m-%d') or "?"
        session_labels.append(f"{sess.title} ({date_str})")

    header = ["Matric Number", "Full Name", "Level"] + session_labels + \
             ["Classes Attended", "Classes Held", "Attendance %"]
    csv_data = _StreamingCSVBuffer(",".join(_csv_cell(h) for h in header) + "\n")

    all_students = sorted(students_by_id.values(),
                          key=lambda s: (s.matric_no or '', s.full_name or ''))
    all_session_ids = {sess.id for sess in sessions}

    if not all_students:
        csv_data += _csv_cell("NO STUDENTS ENROLLED YET") + "\n"
    for student in all_students:
        attended = attended_map.get(student.id, set())
        # Sessions with no snapshot at all predate roster tracking; count
        # every one of them, as the old register did.
        rostered = rostered_by_student.get(student.id)
        if rostered is None:
            rostered = all_session_ids if not rostered_by_student else set()
        name = student.full_name or "N/A"
        if student.id not in enrolled_ids:
            name += " (not enrolled)"
        row = [student.matric_no, name, student.level]
        for sess in sessions:
            if sess.id in attended:
                row.append("Present")
            elif sess.id in rostered:
                row.append("Absent")
            else:
                # Held before they enrolled (or after they left). Not a miss.
                row.append("-")
        expected = len(rostered)
        row += [len(attended), expected,
                f"{_attendance_percentage(len(attended), expected) or 0}%"]
        csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

    term_tag = _safe_filename(f"{course.academic_year}_{course.semester}", 'term')
    return Response(
        csv_data,
        mimetype='text/csv',
        headers=_attachment_headers(
            f"{safe_code}_{term_tag}_attendance_register.csv"),
    )

    # ============================================================
# ANALYTICS
# ============================================================

@app.route('/course/<int:course_id>/analytics')
@login_required
def course_analytics(course_id):
    course = db.get_or_404(Course, course_id)

    # Security check: Ensure they own the course
    if not _attendance_authorized(course):
        return "Unauthorised", 403

    # One data point PER CLASS SESSION (a session nobody scanned still shows
    # as 0, which a plain group-by-date of scans could never reveal).
    per_session = (
        db.session.query(ClassSession, func.count(Attendance.id))
        .outerjoin(Attendance, Attendance.session_id == ClassSession.id)
        .filter(ClassSession.course_id == course_id)
        .group_by(ClassSession.id)
        .order_by(ClassSession.date_created.asc())
        .all()
    )

    session_ids = [sess.id for sess, _count in per_session]
    expected_by_session = _session_expected_counts(session_ids)

    # Format the data for Chart.js. Labels are LOCAL dates — a 9pm class
    # plotted from its UTC timestamp lands on the following day.
    dates = [format_local(sess.date_created, '%b %d') or '?'
             for sess, _count in per_session]
    counts = [count for _sess, count in per_session]
    # Percentage against each meeting's own roster, so the line means the same
    # thing before and after the roster changed.
    percentages = [
        _attendance_percentage(count, expected_by_session.get(sess.id, 0)) or 0
        for sess, count in per_session
    ]
    titles = [sess.title for sess, _count in per_session]

    return render_template('analytics.html',
                           course=course,
                           dates=dates,
                           counts=counts,
                           percentages=percentages,
                           titles=titles)


@app.route('/course/<int:course_id>/start_session', methods=['POST'])
@login_required
def start_session(course_id):
    course = db.get_or_404(Course, course_id)

    # Security check: Ensure they are the lecturer
    if not _is_course_authorized(course):
        return "Unauthorised", 403

    if course.archived:
        flash(f"{course.code} is archived. Restore it before taking "
              "attendance.", "warning")
        return redirect(url_for('dashboard'))

    # A second meeting on the same day is a deliberate choice, not an
    # accident: `new_session` is what the "Start another meeting" button
    # sends, and without it a refresh resumes the class already running.
    force_new = request.form.get('new_session', '').strip().lower() in ('1', 'true', 'yes')
    kind = request.form.get('kind', 'Lecture').strip() or 'Lecture'
    title = request.form.get('title', '')

    session_row = resume_or_start_session(course, kind=kind,
                                                force_new=force_new, title=title)
    return redirect(url_for('session_qr', session_id=session_row.id))


@app.route('/session/<int:session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    """
    Remove a class session started by mistake (and its scans), so it doesn't
    count as a 'class held' in every student's percentage.

    Coordinator only. Any invited instructor used to be able to destroy a
    whole meeting and every attendance record in it — including one they had
    no part in running — with a single POST and no record of who did it.
    """
    session_row = db.get_or_404(ClassSession, session_id)
    course = db.get_or_404(Course, session_row.course_id)

    if not _owns_course(course):
        flash("Unauthorised: only the course coordinator can delete a session.",
              "error")
        return redirect(url_for('view_attendance', course_id=course.id))

    scan_count = (db.session.query(func.count(Attendance.id))
                  .filter(Attendance.session_id == session_id).scalar()) or 0
    title = session_row.title

    record_audit('session.delete', 'class_session', session_id, title,
                 course_id=course.id, course_code=course.code,
                 attendance_deleted=scan_count,
                 held_at=iso_utc(session_row.date_created))

    db.session.delete(session_row)  # cascade removes attendance and roster
    db.session.commit()
    _invalidate_session_caches(session_row)
    flash(f'Session "{title}" and its {scan_count} record(s) were deleted.',
          'success')
    return redirect(url_for('view_attendance', course_id=course.id))


@app.route('/course/<int:course_id>/audit')
@login_required
def course_audit(course_id):
    """
    The trail for one course: who started, ended or destroyed what.

    Read by the same people who may read the register — this is the record
    that makes a deletion answerable.
    """
    course = db.get_or_404(Course, course_id)
    if not _attendance_authorized(course):
        flash("Unauthorised access to the audit trail.", "error")
        return redirect(url_for('dashboard'))

    page = max(1, request.args.get('page', default=1, type=int) or 1)
    pagination = (AuditLog.query
                  .filter(AuditLog.course_id == course_id)
                  .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
                  .paginate(page=page, per_page=50, error_out=False))

    return render_template('audit_log.html', course=course,
                           entries=pagination.items, pagination=pagination)

# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(429)
def ratelimit_handler(e):
    if request.is_json:
        return jsonify({
            "status": "error",
            "message": f"Rate limit exceeded. Please slow down. ({e.description})"
        }), 429

    # 🚨 STOPS THE LOOP BY RENDERING HTML DIRECTLY.
    # e.description is set from each limit's error_message, which is ours — but
    # escape it anyway rather than trusting that every future caller remembers.
    return Response(
        "<h2>Too Many Requests!</h2>"
        f"<p>{escape(str(e.description))}</p>"
        f"<p>Please wait a minute and <a href='{url_for('dashboard')}'>try again</a>.</p>",
        status=429, mimetype='text/html'
    )


@app.errorhandler(PoolTimeoutError)
def database_pool_exhausted(error):
    """
    Every database connection is busy and this request waited its full
    pool_timeout for one.

    That is saturation, not a bug, and the distinction matters to the caller:
    503 with Retry-After tells the phone scanner to back off and try again,
    while the 500 it used to get says "this will never work" and is recorded
    as a server fault in every dashboard. Raising the worker count in response
    to those 500s makes it worse, by pointing more connections at the same
    exhausted database.
    """
    db.session.rollback()
    runtime_metrics.increment('db.pool.exhausted')
    app.logger.error('Database pool exhausted: %s', error)
    retry_after = str(max(1, int(os.environ.get('DB_SATURATION_RETRY_SECONDS', 2))))
    if request.is_json or request.path.startswith('/api/'):
        response = jsonify({
            'status': 'error',
            'outcome': 'database_saturated',
            'message': 'The system is very busy right now. Please try again '
                       'in a moment — your scan was not recorded.',
        })
        response.headers['Retry-After'] = retry_after
        return response, 503
    return Response(
        "<h2>Very busy right now</h2>"
        "<p>The database is at capacity. Please try again in a moment.</p>",
        status=503, mimetype='text/html', headers={'Retry-After': retry_after},
    )


@app.errorhandler(500)
def internal_error_handler(e):
    """Never leave a broken transaction attached to the pooled connection."""
    db.session.rollback()
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({"status": "error",
                        "message": "An unexpected server error occurred."}), 500
    return Response(
        "<h2>Something went wrong</h2>"
        "<p>The error has been logged. Please try again in a moment.</p>",
        status=500, mimetype='text/html'
    )

# ============================================================
# DATABASE INITIALIZATION & SCHEDULER
# ============================================================

with app.app_context():
    db.create_all()

    # ── Idempotent migration: add columns that create_all won't add ──
    # db.create_all() only creates NEW tables; it never alters existing ones.
    # This block safely adds any missing columns to production.
    _default_year, _default_semester = academic_term_of()
    _migrations = [
        # Attendance.course_id (was previously commented out)
        ("attendance", "course_id", "INTEGER REFERENCES course(id)"),
        # Attendance.session_id — model declares it but older tables lack the
        # column, so reads/inserts on `attendance` fail until it is added.
        ("attendance", "session_id", "INTEGER"),
        ("attendance", "device_id", "VARCHAR(200)"),
        # Stable CampOS identity binding; email is not an identity key.
        ("user", "campos_user_id", "VARCHAR(100)"),
        ("user", "campos_institution_id", "VARCHAR(100)"),
        # Self-service signups must confirm their address. Existing rows are
        # backfilled TRUE by this DDL default so nobody who could sign in
        # yesterday is locked out today; only rows inserted after this point
        # start out unconfirmed (the ORM sets False explicitly).
        ("user", "email_verified", "BOOLEAN DEFAULT TRUE"),
        # Rotating credential marker. NULL on existing rows, which matches the
        # empty stamp their already-issued cookies carry, so nobody is signed
        # out by the upgrade itself.
        ("user", "security_stamp", "VARCHAR(32)"),
        # --- The academic calendar a course belongs to ---
        # Existing rows are adopted into the current term: they were created
        # for whatever is running now, and a term label they can be filtered
        # and archived by is strictly better than none.
        ("course", "academic_year", f"VARCHAR(9) DEFAULT '{_default_year}'"),
        ("course", "semester", f"VARCHAR(20) DEFAULT '{_default_semester}'"),
        ("course", "section", "VARCHAR(20) DEFAULT ''"),
        ("course", "archived", "BOOLEAN DEFAULT FALSE"),
        ("course", "archived_at", "TIMESTAMP"),
        # --- Session lifecycle ---
        # Sessions that predate this are treated as ended: they are history,
        # and leaving them 'active' would keep their tokens redeemable.
        ("class_session", "active", "BOOLEAN DEFAULT FALSE"),
        ("class_session", "ended_at", "TIMESTAMP"),
        ("class_session", "ended_by_id", "INTEGER"),
        ("class_session", "kind", "VARCHAR(20) DEFAULT 'Lecture'"),
        ("class_session", "sequence", "INTEGER DEFAULT 1"),
        # When a student joined a course.
        ("enrollments", "enrolled_at", "TIMESTAMP"),
    ]
    database_inspector = inspect(db.engine)
    existing_columns = {
        table: {column['name'] for column in database_inspector.get_columns(table)}
        for table in {table for table, _column, _type in _migrations}
    }

    def _fatal_migration(step, error):
        """
        A migration that fails must stop the boot.

        Printing and carrying on is how a worker ends up serving without the
        unique attendance index: `INSERT ... ON CONFLICT (student_id,
        session_id)` then has no constraint to name, so every scan in the
        class returns a 500 — and the log line explaining why scrolled past
        at boot on a different day.
        """
        raise StartupError(
            f"CRITICAL: schema migration step '{step}' failed and the "
            f"application cannot serve correctly without it: {error}"
        ) from error
    with db.engine.connect() as conn:
        for table, column, col_type in _migrations:
            if column in existing_columns[table]:
                continue
            quote = db.engine.dialect.identifier_preparer.quote
            add_column = (
                "ADD COLUMN IF NOT EXISTS"
                if db.engine.dialect.name == "postgresql"
                else "ADD COLUMN"
            )
            try:
                conn.execute(db.text(
                    f"ALTER TABLE {quote(table)} {add_column} {quote(column)} {col_type}"
                ))
                conn.commit()
            except Exception as _error:
                conn.rollback()
                _fatal_migration(f"add {table}.{column}", _error)
            existing_columns[table].add(column)
            print(f"[MIGRATION] Added {table}.{column}")

        # The old schema made course.code globally unique, which is exactly
        # what stopped a course recurring next term. Postgres names the
        # constraint and can drop it in place; SQLite bakes it into the table
        # definition and needs the rebuild further down.
        try:
            if db.engine.dialect.name == 'postgresql':
                conn.execute(db.text(
                    'ALTER TABLE course DROP CONSTRAINT IF EXISTS course_code_key'))
                conn.commit()
        except Exception as _error:
            conn.rollback()
            _fatal_migration('drop the global course.code unique constraint', _error)

        # ...and put the replacement invariant in its place. create_all() never
        # alters an existing table, so on an upgraded database dropping the old
        # constraint without adding this one would leave offerings with NO
        # uniqueness at all — two simultaneous /add_course posts would both
        # pass the pre-insert lookup and split one course's enrolments and
        # sessions across two rows. A fresh database already has the model's
        # constraint; do not add a redundant second index over it.
        _course_uniques = database_inspector.get_unique_constraints('course')
        _course_indexes = database_inspector.get_indexes('course')
        _offering_columns = ['code', 'academic_year', 'semester', 'section']
        _has_offering_unique = any(
            sorted(c.get('column_names') or []) == sorted(_offering_columns)
            for c in _course_uniques
        ) or any(
            i.get('unique') and sorted(i.get('column_names') or []) == sorted(_offering_columns)
            for i in _course_indexes
        )
        if not _has_offering_unique:
            try:
                conn.execute(db.text(
                    'CREATE UNIQUE INDEX IF NOT EXISTS uq_course_offering '
                    'ON course (code, academic_year, semester, section)'))
                conn.commit()
                print('[MIGRATION] Added the per-offering unique index on course')
            except Exception as _error:
                conn.rollback()
                _fatal_migration('create the per-offering unique index', _error)

        # Nullable links keep standalone/local accounts valid while enforcing
        # one ScanMark account per CampOS subject. New databases may already
        # have equivalent ORM-generated indexes; avoid creating redundant
        # indexes under different names.
        user_indexes = database_inspector.get_indexes("user")
        user_unique_constraints = database_inspector.get_unique_constraints("user")
        has_campos_user_unique = any(
            index.get("unique")
            and index.get("column_names") == ["campos_user_id"]
            for index in user_indexes
        ) or any(
            constraint.get("column_names") == ["campos_user_id"]
            for constraint in user_unique_constraints
        )
        has_campos_institution_index = any(
            index.get("column_names") == ["campos_institution_id"]
            for index in user_indexes
        )
        try:
            if not has_campos_user_unique:
                conn.execute(db.text(
                    'CREATE UNIQUE INDEX IF NOT EXISTS "user_campos_user_id_key" '
                    'ON "user" (campos_user_id) WHERE campos_user_id IS NOT NULL'
                ))
            if not has_campos_institution_index:
                conn.execute(db.text(
                    'CREATE INDEX IF NOT EXISTS "user_campos_institution_id_idx" '
                    'ON "user" (campos_institution_id)'
                ))
            conn.commit()
        except Exception as _error:
            conn.rollback()
            _fatal_migration('create the CampOS identity indexes', _error)

        # Backfill the term columns on rows that predate them. The DDL default
        # covers new rows; existing ones may still hold NULL on Postgres if
        # the column was added without a default in an earlier release.
        try:
            conn.execute(db.text(
                "UPDATE course SET academic_year = :year "
                "WHERE academic_year IS NULL OR academic_year = ''"),
                {'year': _default_year})
            conn.execute(db.text(
                "UPDATE course SET semester = :semester "
                "WHERE semester IS NULL OR semester = ''"),
                {'semester': _default_semester})
            conn.execute(db.text(
                "UPDATE course SET section = '' WHERE section IS NULL"))
            conn.execute(db.text(
                "UPDATE course SET archived = FALSE WHERE archived IS NULL"))
            # Sessions from before the lifecycle existed are finished, and
            # their end time is the best evidence we have: the last scan.
            conn.execute(db.text(
                "UPDATE class_session SET active = FALSE WHERE active IS NULL"))
            conn.execute(db.text(
                "UPDATE class_session SET kind = 'Lecture' WHERE kind IS NULL"))
            conn.execute(db.text(
                "UPDATE class_session SET sequence = 1 WHERE sequence IS NULL"))
            conn.commit()
        except Exception as _error:
            conn.rollback()
            _fatal_migration('backfill the academic-term columns', _error)

    if db.engine.dialect.name == 'sqlite':
        # SQLite bakes a column-level UNIQUE into the table definition, where
        # ALTER TABLE cannot reach it and (unlike Postgres) it is not a named
        # constraint. SQLAlchemy's inspector does not report it either, so it
        # has to be found through the autoindex SQLite creates for it —
        # otherwise the upgrade looks successful while the database still
        # refuses to let CSC201 run a second time. Rebuilding the table is the
        # only way to drop it.
        _rebuild_needed = False
        with db.engine.connect() as conn:
            for _index in conn.execute(db.text("PRAGMA index_list('course')")).mappings():
                if _index['origin'] != 'u' or not _index['unique']:
                    continue
                _columns = [row['name'] for row in conn.execute(
                    db.text(f"PRAGMA index_info('{_index['name']}')")).mappings()]
                if _columns == ['code']:
                    _rebuild_needed = True
                    break

        if _rebuild_needed:
            print("[MIGRATION] Rebuilding `course` to drop the legacy global "
                  "UNIQUE on code (it blocks a course recurring next term)")
            _columns = ', '.join(Course.__table__.columns.keys())
            # Pragmas cannot run inside a transaction, and legacy_alter_table
            # stops the RENAME from rewriting child tables' references to
            # `course` — they must keep pointing at the name the new table
            # will take.
            _raw = db.engine.raw_connection()
            try:
                _cursor = _raw.cursor()
                _cursor.execute("PRAGMA foreign_keys=OFF")
                _cursor.execute("PRAGMA legacy_alter_table=ON")
                _cursor.execute("BEGIN")
                _cursor.execute("ALTER TABLE course RENAME TO course_pre_term_upgrade")
                _raw.commit()
                Course.__table__.create(bind=db.engine)
                _cursor = _raw.cursor()
                _cursor.execute("BEGIN")
                _cursor.execute(
                    f"INSERT INTO course ({_columns}) "
                    f"SELECT {_columns} FROM course_pre_term_upgrade")
                _cursor.execute("DROP TABLE course_pre_term_upgrade")
                _raw.commit()
                _cursor.execute("PRAGMA legacy_alter_table=OFF")
                _cursor.execute("PRAGMA foreign_keys=ON")
                print("[MIGRATION] `course` rebuilt; offerings are now unique "
                      "per (code, year, semester, section)")
            except Exception as _error:
                _raw.rollback()
                _fatal_migration('rebuild the course table', _error)
            finally:
                _raw.close()

    # ── Backfill: adopt legacy attendance rows into per-day class sessions ──
    # Before sessions were wired up, scans were saved with session_id NULL.
    # Group those rows by (course, calendar day) and attach each group to a
    # ClassSession so old records show up in the per-session views. Idempotent:
    # it only ever touches rows that still have no session.
    try:
        orphans = Attendance.query.filter(Attendance.session_id.is_(None)).all()
        if orphans:
            by_course_day = {}
            for rec in orphans:
                # The LOCAL calendar day the scan happened on. Grouping by the
                # UTC date files an 11pm lecture under the following morning.
                day = local_date(rec.timestamp or _utcnow())
                by_course_day.setdefault((rec.course_id, day), []).append(rec)

            for (course_id, day), recs in sorted(by_course_day.items(),
                                                 key=lambda item: (item[0][0], item[0][1])):
                day_start, day_end = local_day_bounds_utc(day)
                session_row = ClassSession.query.filter(
                    ClassSession.course_id == course_id,
                    ClassSession.date_created >= day_start,
                    ClassSession.date_created < day_end
                ).first()
                if not session_row:
                    first_ts = min((r.timestamp for r in recs if r.timestamp),
                                   default=_utcnow())
                    session_row = ClassSession(
                        course_id=course_id,
                        title=f"Lecture on {day.strftime('%b %d, %Y')}",
                        # Historical: it is over, and leaving it open would
                        # keep tokens for it redeemable.
                        active=False,
                        ended_at=max((r.timestamp for r in recs if r.timestamp),
                                     default=first_ts),
                        date_created=first_ts,
                    )
                    db.session.add(session_row)
                    db.session.flush()
                for rec in recs:
                    rec.session_id = session_row.id

            db.session.commit()
            print(f"[MIGRATION] Linked {len(orphans)} legacy attendance rows to daily class sessions")
    except Exception as e:
        db.session.rollback()
        print(f"[MIGRATION] Session backfill failed (will retry next boot): {e}")

    # ── Load-capacity indexes (idempotent) ──
    # db.create_all() adds these on fresh databases via the model's
    # __table_args__, but never touches existing tables — so create them
    # here for databases that predate the indexes. The unique index is the
    # race-proof duplicate-scan guard; the others serve the live attendee
    # feed and the per-student early-warning counts.
    with db.engine.connect() as conn:
        try:
            # The old check-then-insert flow could let two simultaneous
            # requests both insert; remove any such duplicates (keeping the
            # earliest scan) so the unique index can be created.
            result = conn.execute(db.text(
                "DELETE FROM attendance WHERE session_id IS NOT NULL AND id NOT IN ("
                " SELECT MIN(id) FROM attendance WHERE session_id IS NOT NULL"
                " GROUP BY student_id, session_id)"
            ))
            conn.commit()
            if result.rowcount:
                print(f"[MIGRATION] Removed {result.rowcount} duplicate attendance rows")
        except Exception as _error:
            conn.rollback()
            # Leaving duplicates in place means the unique index below cannot
            # be created, which means the scan path has no ON CONFLICT target.
            _fatal_migration('remove duplicate attendance rows', _error)

        for _index_sql in (
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_attendance_student_session"
            " ON attendance (student_id, session_id)",
            "CREATE INDEX IF NOT EXISTS ix_attendance_session_id"
            " ON attendance (session_id)",
            "CREATE INDEX IF NOT EXISTS ix_attendance_session_cursor"
            " ON attendance (session_id, id)",
            "CREATE INDEX IF NOT EXISTS ix_attendance_course_student"
            " ON attendance (course_id, student_id)",
            "CREATE INDEX IF NOT EXISTS ix_enrollments_course_id"
            " ON enrollments (course_id)",
            "CREATE INDEX IF NOT EXISTS ix_course_instructors_course_id"
            " ON course_instructors (course_id)",
            "CREATE INDEX IF NOT EXISTS ix_class_session_course_id"
            " ON class_session (course_id)",
            "CREATE INDEX IF NOT EXISTS ix_class_session_course_active"
            " ON class_session (course_id, active)",
            "CREATE INDEX IF NOT EXISTS ix_session_roster_student_course"
            " ON session_roster (student_id, course_id)",
            "CREATE INDEX IF NOT EXISTS ix_session_roster_course"
            " ON session_roster (course_id)",
            "CREATE INDEX IF NOT EXISTS ix_course_term"
            " ON course (academic_year, semester)",
        ):
            try:
                conn.execute(db.text(_index_sql))
                conn.commit()
            except Exception as _error:
                conn.rollback()
                # "will retry next boot" was never true for the unique index:
                # the worker carried on serving without it, and every scan hit
                # ON CONFLICT with no matching constraint — a 500 per student,
                # for the whole class.
                _fatal_migration(f'create index ({_index_sql.split()[-3]})', _error)

    # ── Backfill: freeze a roster for sessions that predate snapshots ──
    # Their true roster is unknowable now; today's enrolment is the closest
    # honest approximation and it is frozen from here on, so at least the
    # figures stop moving under people.
    try:
        _unsnapshotted = [
            row[0] for row in
            db.session.query(ClassSession.id)
            .outerjoin(SessionRoster, SessionRoster.session_id == ClassSession.id)
            .filter(SessionRoster.session_id.is_(None))
            .all()
        ]
        if _unsnapshotted:
            for _session_id in _unsnapshotted:
                _row = db.session.get(ClassSession, _session_id)
                if _row is not None:
                    _snapshot_roster(_row)
            db.session.commit()
            print(f"[MIGRATION] Captured a roster snapshot for "
                  f"{len(_unsnapshotted)} existing class session(s)")
    except Exception as _error:
        db.session.rollback()
        _fatal_migration('capture roster snapshots for existing sessions', _error)

    # ── Legacy notification tables ──
    # A database upgraded from a release that still had the notification
    # stack keeps `early_warning`, and its FOREIGN KEY to course.id is still
    # enforced by Postgres. Dropping the model does not drop the table:
    # db.create_all() only ever creates. So the rows are not inert — they
    # block DELETE on any course they reference, which surfaces as a 500 on
    # /delete_course in production and nowhere else.
    #
    # Detected once at boot rather than dropped: `notification_preference`
    # holds addresses and phone numbers people typed in, and silently
    # destroying that on a deploy is not this code's call to make. Clear the
    # references instead, and drop the tables by hand when you are ready.
    # Discovered from the live schema rather than from a hard-coded list, so a
    # table this release has never heard of still gets cleared instead of
    # blocking every course deletion with a foreign-key violation.
    LEGACY_COURSE_REF_TABLES = discover_course_ref_tables()
    if LEGACY_COURSE_REF_TABLES:
        print(f"[MIGRATION] Legacy notification table(s) still present: "
              f"{', '.join(LEGACY_COURSE_REF_TABLES)}. Course deletion clears "
              f"them. Safe to DROP at any time, including while running.")

    # Release the scoped session before disposing preload connections.  This
    # also keeps in-memory SQLite smoke tests from tearing down a live session.
    db.session.remove()
    db.engine.dispose()  # Forces Gunicorn workers to create fresh connections
    print("[OK] Database initialized successfully!")

if __name__ == '__main__':
    # Local development entry point only — production runs the Procfile's
    # `gunicorn --config gunicorn.conf.py app:app`.
    if is_production_environment():
        raise RuntimeError(
            "Refusing to start the development server in production. "
            "Use: gunicorn --config gunicorn.conf.py app:app"
        )

    print("\n" + "=" * 60)
    print("🎓 FUNAAB ATTENDANCE SYSTEM STARTING (development server)")
    print("=" * 60)
    print(f"📧 Mail Server: {app.config['MAIL_SERVER']}")
    print("🔐 CSRF Protection: Enabled")
    print("🛡️  Rate Limiting: Enabled")
    print("📧 Email Verification: "
          f"{'Required (students only)' if REQUIRE_EMAIL_VERIFICATION else 'Not required'}")
    print("📭 Email is sent at signup and password reset only")
    print(f"🎯 Attendance target shown on dashboards: {ATTENDANCE_TARGET_PERCENT}%")
    print("=" * 60 + "\n")

    # The reloader/debugger is opt-in rather than always-on: `debug=True` here
    # exposes the Werkzeug console to anything that can reach port 5000.
    app.run(host=os.environ.get('DEV_HOST', '127.0.0.1'), port=5000,
            debug=os.environ.get('FLASK_DEBUG', '').strip().lower()
            in ('1', 'true', 'yes', 'on'))
