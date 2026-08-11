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
from sqlalchemy import event, func, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine
from sqlalchemy.orm import joinedload, selectinload
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

from models import (
    db, User, Course, Attendance, ClassSession, NotificationPreference,
    WeeklyReport, enrollments,
)
from performance import BoundedExecutor, InstrumentedQueuePool, runtime_metrics
from campos_integration import (
    CamposIntegrationError,
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
from notifications import (
    send_attendance_whatsapp,
    process_early_warning,
    generate_student_weekly_pdf,
    generate_lecturer_weekly_pdf,
    send_weekly_report_email,
    send_parent_attendance_whatsapp,
    send_parent_attendance_email,
    DEFAULT_ATTENDANCE_THRESHOLD,
)

# Windows' legacy console encoding cannot represent some existing log text.
# Keep startup diagnostic output from crashing the process on local machines.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

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

# --- FIX #14: Crash loudly if SECRET_KEY is missing in production ---
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    if is_production_environment():
        raise RuntimeError("CRITICAL: SECRET_KEY environment variable is not set! Refusing to start.")
    else:
        _secret = 'local_dev_fallback_key_do_not_use_in_prod'
        print("⚠️  WARNING: SECRET_KEY not set. Using insecure fallback for local dev only.")

app.config['SECRET_KEY'] = _secret
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = is_production_environment()
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = is_production_environment()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 🚨 FIX: Silence SQLAlchemy warnings

# FIX #2: Enable CSRF protection globally
csrf = CSRFProtect(app)

# ============================================================
# STATIC FILES & COMPRESSION
# ============================================================

# WhiteNoise serves /static at the WSGI layer (before Flask routing) with
# Cache-Control headers and pre-compressed gzip/brotli variants, so a class
# of phones pulling CSS/logo doesn't occupy Flask request handlers.
# Filenames aren't content-hashed, so keep max-age moderate (1 day default).
_static_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

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
        if environ.get('PATH_INFO') == '/healthz' and environ.get('REQUEST_METHOD') in ('GET', 'HEAD'):
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

redis_url = os.environ.get('REDIS_URL')
redis_client = None

if redis_url:
    redis_client = redis.from_url(redis_url)
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REDIS'] = redis_client
    Session(app)
    print("🟢 Redis Sessions Enabled")
else:
    print("🟡 No REDIS_URL found. Using default cookie sessions (local dev only).")


# ============================================================
# RATE LIMITER
# ============================================================

# A copied .env commonly contains REDIS_URL="". Treat that the same as an
# unset value so local development still uses the documented in-memory store
# instead of passing an invalid empty storage URI to Flask-Limiter.
limiter_storage = os.environ.get('REDIS_URL') or 'memory://'

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
# BACKGROUND_WORKERS / BACKGROUND_QUEUE_MAXSIZE are the fleet-wide defaults
# documented in DEPLOYMENT.md; the per-pool variables override them. They used
# to be documented but read nowhere, so an operator sizing the background queue
# before a big event changed nothing.
_BACKGROUND_WORKERS_DEFAULT = os.environ.get('BACKGROUND_WORKERS')
_BACKGROUND_QUEUE_DEFAULT = int(os.environ.get('BACKGROUND_QUEUE_MAXSIZE', 2000))


def _pool_workers(specific_var, fallback):
    """Per-pool setting, else the fleet-wide default, else the built-in."""
    value = os.environ.get(specific_var) or _BACKGROUND_WORKERS_DEFAULT
    return int(value) if value else fallback


notification_work_executor = BoundedExecutor(
    name='notification_work',
    max_workers=_pool_workers('NOTIFICATION_WORKERS', 6),
    max_queue=int(os.environ.get('NOTIFICATION_QUEUE_SIZE',
                                 _BACKGROUND_QUEUE_DEFAULT)),
    metrics=runtime_metrics,
)
campos_executor = BoundedExecutor(
    name='campos_delivery',
    max_workers=_pool_workers('CAMPOS_WORKERS', 4),
    max_queue=int(os.environ.get('CAMPOS_QUEUE_SIZE',
                                 _BACKGROUND_QUEUE_DEFAULT)),
    metrics=runtime_metrics,
)


@atexit.register
def _shutdown_background_executors():
    # Do not hold process shutdown open for optional outbound notifications.
    notification_work_executor.shutdown(wait=False)
    campos_executor.shutdown(wait=False)

# Escape hatch for very large events: one confirmation email per scan can
# exceed the SMTP provider's quota (Gmail allows ~500-2000 sends/day), so
# ops can switch confirmations off with SCAN_CONFIRMATION_EMAILS=false
# without redeploying code.
SCAN_CONFIRMATION_EMAILS = os.environ.get(
    'SCAN_CONFIRMATION_EMAILS', 'true'
).strip().lower() not in ('false', '0', 'no', 'off')

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
    if notification_work_executor.submit(send_async_email, app, msg) is None:
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
        'Lecturer': 'Lecturer',
        'Course Coordinator': 'Course Coordinator',
        'course coordinator': 'Course Coordinator',
        'hod': 'Head of Department',
        'dean': 'Dean',
        'dap': 'Director of Academic Planning'
    }
    role_display = role_display_map.get(user_role, user_role.title() if user_role else 'Student')

    signup_date = datetime.now().strftime('%d %B %Y at %I:%M %p')

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
                Hello {user_name}! 👋
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
                    {user_name}
                  </td>
                </tr>
                <tr>
                  <td style="padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:1px;color:#006838;text-transform:uppercase;border-bottom:1px solid #e2e8e2;">
                    EMAIL
                  </td>
                  <td style="padding:12px 16px;font-size:14px;color:#1a1a1a;font-family:'Courier New',monospace;border-bottom:1px solid #e2e8e2;border-left:1px solid #e2e8e2;">
                    {user_email}
                  </td>
                </tr>
                <tr style="background:#f7faf7;">
                  <td style="padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:1px;color:#006838;text-transform:uppercase;border-bottom:1px solid #e2e8e2;">
                    ROLE
                  </td>
                  <td style="padding:12px 16px;border-bottom:1px solid #e2e8e2;border-left:1px solid #e2e8e2;">
                    <span style="display:inline-block;padding:3px 12px;background:#ffc107;color:#000;border-radius:20px;font-size:12px;font-weight:700;">
                      {role_display}
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
              <a href="{url_for('login', _external=True)}"
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
                © {datetime.now().year} ScanMark Attendance System · This is an automated message.
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


def send_attendance_confirmation(user_email, user_name, course_code, course_title, timestamp):
    """Send email when attendance is marked"""
    subject = f"Attendance Confirmed - {course_code}"
    
    text_body = f"""
Hello {user_name},

Your attendance has been successfully recorded:

Course: {course_code} - {course_title}
Time: {timestamp}

Best regards,
FUNAAB Attendance System Team
    """
    
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #198754 0%, #20c997 100%);
            color: white;
            padding: 30px;
            text-align: center;
            border-radius: 10px 10px 0 0;
        }}
        .content {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 0 0 10px 10px;
        }}
        .confirmation-box {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            border-left: 5px solid #198754;
            margin: 20px 0;
        }}
        .detail-row {{
            display: flex;
            padding: 10px 0;
            border-bottom: 1px solid #e9ecef;
        }}
        .detail-label {{
            font-weight: bold;
            width: 120px;
            color: #6c757d;
        }}
        .detail-value {{
            flex: 1;
            color: #333;
        }}
        .success-icon {{
            font-size: 48px;
            text-align: center;
            margin: 20px 0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>✅ Attendance Confirmed</h1>
    </div>
    
    <div class="content">
        <div class="success-icon">✓</div>
        
        <div class="confirmation-box">
            <h2>Hello {user_name}!</h2>
            <p>Your attendance has been successfully recorded.</p>
            
            <div class="detail-row">
                <div class="detail-label">Course:</div>
                <div class="detail-value">{course_code} - {course_title}</div>
            </div>
            
            <div class="detail-row">
                <div class="detail-label">Date & Time:</div>
                <div class="detail-value">{timestamp}</div>
            </div>
            
            <div class="detail-row">
                <div class="detail-label">Status:</div>
                <div class="detail-value" style="color: #198754; font-weight: bold;">Present</div>
            </div>
        </div>
        
        <p style="text-align: center; color: #6c757d;">
            Keep up the great attendance! 🎯
        </p>
    </div>
    
    <div class="footer">
        <p><strong>Federal University of Agriculture, Abeokuta (FUNAAB)</strong></p>
        <p>© 2024 FUNAAB Attendance Management System. All rights reserved.</p>
        <p>This is an automated message, please do not reply to this email.</p>
    </div>
</body>
</html>
    """
    
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
    if os.environ.get('FLASK_ENV') == 'production':
        print("🚨 WARNING: DATABASE_URL is not set — running production on SQLite!")
        print("   SQLite is single-writer and on ephemeral disk: it cannot handle")
        print("   concurrent scan load and attendance data will be LOST on restart.")
        print("   Provision Postgres and set DATABASE_URL before real classes use this.")

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


@event.listens_for(Pool, 'checkout')
def _pool_checkout(_dbapi_connection, _connection_record, _connection_proxy):
    global _pool_checked_out
    with _pool_lock:
        _pool_checked_out += 1
        runtime_metrics.gauge('db.pool.checked_out', _pool_checked_out)
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
app.config['REMEMBER_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'


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

# Self-service accounts must confirm their address before the password works.
# Defaults on in production and off elsewhere, so a local checkout without SMTP
# still logs in. Never disable it in production: the signup form accepts any
# address, including a @staff one the registrant does not own.
REQUIRE_EMAIL_VERIFICATION = (
    os.environ.get('REQUIRE_EMAIL_VERIFICATION', '').strip().lower()
    or ('true' if is_production_environment() else 'false')
) not in ('false', '0', 'no', 'off')


def validate_password_strength(password):
    """Return None when acceptable, else a message explaining what's missing."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if password.isdigit() or password.isalpha():
        return "Password must mix letters and numbers."
    return None


@app.context_processor
def inject_password_policy():
    """So the signup/reset forms advertise the same rule the server enforces."""
    return {'min_password_length': MIN_PASSWORD_LENGTH}


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

def set_class_location(course_id, lat, lon):
    """Store lecturer's class location in Redis (expires after 4 hours)."""
    if redis_client:
        _redis_timed(
            'setex', redis_client.setex,
            f"class_location:{course_id}", 14400, f"{lat},{lon}"
        )
    else:
        # Local-dev fallback: module-level dict (single process only)
        _local_locations[course_id] = {'lat': lat, 'lon': lon}


def get_class_location(course_id):
    """Retrieve the active class location for a course."""
    if redis_client:
        val = _redis_timed('get', redis_client.get, f"class_location:{course_id}")
        if val:
            lat_str, lon_str = val.decode().split(',')
            return {'lat': float(lat_str), 'lon': float(lon_str)}
        return None
    else:
        return _local_locations.get(course_id)


# Local-dev fallback only (never used when Redis is available)
_local_locations = {}


def _enrolled_count(course_id):
    """
    COUNT of students enrolled in a course, straight off the enrollments
    table. Use this instead of len(course.students), which materialises
    every enrolled User row (2000 ORM objects) just to take its length.
    """
    return (db.session.query(func.count(enrollments.c.user_id))
            .filter(enrollments.c.course_id == course_id)
            .scalar()) or 0


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

# Max distance (metres) between the lecturer's pinned class location and the
# scanning student. The old route hard-coded 50 while its message referenced
# the configurable 100m value. One authoritative value prevents policy drift.
# balances anti-cheating with real-world phone GPS error inside buildings.
GEOFENCE_RADIUS_M = int(os.environ.get('GEOFENCE_RADIUS_M', 100))

# When a lecturer never pins a classroom location — they dismissed the
# browser's GPS prompt, or the projector machine has no location service —
# get_class_location() returns None and the distance check is skipped
# entirely, so the class is marked with no proximity requirement at all.
# Default off, because switching it on mid-semester locks out every class
# whose lecturer has not granted location. Turn it on when attendance is
# graded and you would rather refuse a scan than record an unverifiable one.
GEOFENCE_REQUIRED = os.environ.get(
    'GEOFENCE_REQUIRED', 'false'
).strip().lower() in ('true', '1', 'yes', 'on')


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


def get_department_analytics(dept_name):
    """
    Return comparative attendance stats for an HOD.
    Uses a single aggregated SQL query instead of per-course loops.
    """
    # One query: join Course → Attendance, group by course
    rows = (
        db.session.query(
            Course.code,
            func.count(Attendance.id).label('total_attendance')
        )
        .outerjoin(Attendance, Attendance.course_id == Course.id)
        .filter(Course.department == dept_name)
        .group_by(Course.id)
        .all()
    )

    return {
        "labels": [r.code for r in rows],
        "data": [r.total_attendance for r in rows],
    }


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
    """
    worker_path = os.path.join(_static_root, 'service-worker.js')
    try:
        with open(worker_path, encoding='utf-8') as handle:
            body = handle.read()
    except OSError:
        app.logger.exception('Could not read the service worker')
        return '', 404
    prelude = f'self.SCANMARK_QR_WINDOW_SECONDS = {QR_CODE_WINDOW};\n'
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
    return db.session.get(User, int(user_id))   # FIX #12


# ============================================================
# 🚨 FIX: SAFE REDIRECT BY ROLE (NO LOOPS!)
# ============================================================

def redirect_by_role(role: str):
    """
    🚨 FIXED: Safe redirect with normalization to prevent loops
    Redirects users to their appropriate dashboard based on role.
    """
    # Normalize role to lowercase and strip whitespace
    role = (role or '').lower().strip()
    
    # Direct mapping to dashboard routes
    mapping = {
        'student': 'student_dashboard',
        'lecturer': 'lecturer_dashboard',
        'course coordinator': 'lecturer_dashboard',
        'hod': 'hod_dashboard',
        'dean': 'dean_dashboard',
        'dap': 'dap_dashboard',
    }
    
    target = mapping.get(role, 'student_dashboard')

    if target == 'student_dashboard' and role not in mapping:
        flash(f"Role '{role}' not recognized. Defaulting to student view.", "warning")
    
    return redirect(url_for(target))


# ============================================================
# EMAIL VERIFICATION
# ============================================================

EMAIL_VERIFY_MAX_AGE = 24 * 60 * 60   # link is good for a day


def send_verification_email(user):
    """Mail a signed, single-use confirmation link to a new self-service account."""
    token = serializer.dumps(user.email, salt='email-verify-salt')
    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message(
        "Confirm your ScanMark email",
        recipients=[user.email],
        sender=app.config['MAIL_DEFAULT_SENDER'],
    )
    msg.body = (
        f"Hello {user.full_name},\n\n"
        "Confirm your ScanMark account by opening the link below "
        "(valid for 24 hours):\n\n"
        f"{verify_url}\n\n"
        "If you did not create a ScanMark account, ignore this email — "
        "no account can be used until this link is opened.\n"
    )
    if notification_work_executor.submit(send_async_email, app, msg) is None:
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
            reset_url = url_for('reset_password', token=token, _external=True)

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
            if notification_work_executor.submit(send_async_email, app, msg) is None:
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
        db.session.commit()
        app.logger.info('Password reset completed for user id=%s', user.id)
        flash("Password updated! You can now log in.", "success")
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


@app.route('/healthz', methods=['GET', 'HEAD'])
@limiter.exempt
def healthz():
    """Process-only probe used to overlap a cold start with CampOS SSO."""
    return '', 204


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
    if not email or user_info.get('email_verified') is False:
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
        # Proving control of the address through Google clears any pending
        # self-service confirmation for the same address.
        user.email_verified = True
        db.session.commit()

    login_user(user, remember=True)
    return redirect_by_role(user.role)


# ============================================================
# CAMPOS SSO HAND-OFF  (Single Sign-On from CampOS Core)
# ============================================================
# The browser receives only an opaque, one-time code. ScanMark redeems it with
# CAMPOS_CORE_URL over a server-to-server request, then verifies the returned
# JWT using CAMPOS_SSO_SECRET (CampOS Core's SSO_JWT_SECRET_SCANMARK).


def _campos_sso_redirect(location):
    return protect_sso_response(redirect(location))


@app.route('/sso/callback')
@csrf.exempt
def campos_sso_callback():
    code = request.args.get('code', '')
    next_path = request.args.get('next')

    if not code:
        flash('Sign-in failed: missing CampOS hand-off code.', 'error')
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
            app.logger.warning(
                'CampOS SSO adopted an unconfirmed local account (id=%s); '
                'its password was retired', user.id
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
    return protect_sso_response(redirect_by_role(user.role))


@app.route('/complete_profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    if request.method == 'POST':
        matric_no = request.form.get('matric_no', '').strip()
        level = request.form.get('level', '').strip()
        
        if not matric_no or not level:
            flash("Both Matric Number and Level are required!", "danger")
            return render_template('complete_profile.html')
            
        # Save the missing data to the database
        current_user.matric_no = matric_no
        current_user.level = level
        db.session.commit()
        
        flash("Profile updated! Welcome to ScanMark.", "success")
        return redirect_by_role(current_user.role)
        
    return render_template('complete_profile.html')

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
            # An unconfirmed self-service account is not yet proof that the
            # person typing owns the address they registered.
            if REQUIRE_EMAIL_VERIFICATION and user.email_verified is False:
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
        matric_no = request.form.get('matric_no', '').strip()[:20]
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
        final_role = auto_role
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
            matric_no=matric_no or None,
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

        if REQUIRE_EMAIL_VERIFICATION:
            flash('Account created! Check your email for a verification link '
                  'before you sign in.', 'success')
        else:
            flash('Account created successfully! Welcome to ScanMark', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
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


def _student_attendance_summary():
    """
    (enrolled courses, per-course attendance rows) for the signed-in student.

    Two GROUP BY queries for ALL courses at once — the old loop ran two COUNT
    queries per enrolled course (~18 queries per dashboard load), and this
    page reloads after every successful scan.
    """
    enrolled_courses = list(getattr(current_user, 'enrolled_courses', []) or [])
    course_ids = [c.id for c in enrolled_courses]

    attended_by_course = {}
    sessions_by_course = {}
    if course_ids:
        attended_by_course = dict(
            db.session.query(Attendance.course_id, func.count(Attendance.id))
            .filter(Attendance.student_id == current_user.id,
                    Attendance.course_id.in_(course_ids))
            .group_by(Attendance.course_id)
            .all())
        sessions_by_course = dict(
            db.session.query(ClassSession.course_id, func.count(ClassSession.id))
            .filter(ClassSession.course_id.in_(course_ids))
            .group_by(ClassSession.course_id)
            .all())

    attendance_data = []
    for course in enrolled_courses:
        count = attended_by_course.get(course.id, 0)
        total_sessions = sessions_by_course.get(course.id, 0)
        pct = round(count / total_sessions * 100) if total_sessions else None
        attendance_data.append({
            'code': course.code,
            'title': course.title,
            'count': count,
            'total_sessions': total_sessions,
            'pct': pct,
        })

    return enrolled_courses, attendance_data


@app.route('/student_dashboard')
@login_required
def student_dashboard():
    user_role = (current_user.role or '').lower().strip()
    
    if user_role != 'student':
        flash("Access denied. Please log in again.", "error")
        return redirect(url_for('login')) # 🚨 SAFELY KICKS THEM OUT

        # 🚨 THE NEW INTERCEPTOR
    if not current_user.matric_no or not current_user.level:
        flash("Please complete your profile to access your dashboard.", "info")
        return redirect(url_for('complete_profile'))

    # FIX #10: Only iterate over the student's own enrolled courses
    pref = NotificationPreference.query.filter_by(user_id=current_user.id).first()
    threshold = pref.warning_threshold if pref and pref.warning_threshold else 75

    enrolled_courses, attendance_data = _student_attendance_summary()

    return render_template('student_dashboard.html',
                           attendance_data=attendance_data,
                           enrolled_courses=enrolled_courses,
                           threshold=threshold)


@app.route('/lecturer_dashboard')
@login_required
def lecturer_dashboard():
    # 🚨 FIX: Safe role normalization
    user_role = (current_user.role or '').lower().strip()
    
    if user_role not in ['lecturer', 'course coordinator']:
        flash("Access denied. Redirecting to your dashboard.", "warning")
        return redirect_by_role(current_user.role)

    if user_role == 'course coordinator':
        my_courses = Course.query.filter_by(coordinator_id=current_user.id).all()
        can_create = True
    else:
        my_courses = getattr(current_user, 'teaching_courses', [])
        can_create = False

    return render_template('lecturer_dashboard.html', courses=my_courses, can_create=can_create)


@app.route('/hod_dashboard')
@login_required
def hod_dashboard():
    # 🚨 FIX: Safe role check - redirect to appropriate dashboard, NOT login
    user_role = (current_user.role or '').lower().strip()
    
    if user_role != 'hod':
        flash("Access denied. Redirecting to your dashboard.", "warning")
        return redirect_by_role(current_user.role)

    page = max(1, request.args.get('page', default=1, type=int) or 1)
    pagination = (Course.query.filter_by(department=current_user.department)
                  .order_by(Course.code.asc())
                  .paginate(page=page, per_page=50, error_out=False))
    return render_template('hod_dashboard.html', courses=pagination.items,
                           pagination=pagination, dept=current_user.department)


@app.route('/hod_analytics')
@login_required
def hod_analytics():
    # 🚨 FIX: Safe role check
    user_role = (current_user.role or '').lower().strip()
    
    if user_role != 'hod':
        flash("Access denied. Redirecting to your dashboard.", "warning")
        return redirect_by_role(current_user.role)

    data = get_department_analytics(current_user.department)
    return render_template('analytics_hod.html', dept=current_user.department, data=data)


@app.route('/dean_dashboard')
@login_required
def dean_dashboard():
    # 🚨 FIX: Safe role check
    user_role = (current_user.role or '').lower().strip()
    
    if user_role != 'dean':
        flash("Access denied. Redirecting to your dashboard.", "warning")
        return redirect_by_role(current_user.role)

    course_count = Course.query.filter_by(faculty=current_user.faculty).count()
    lecturer_count = User.query.filter_by(role='lecturer', faculty=current_user.faculty).count()
    return render_template('dean_dashboard.html',
                           faculty=current_user.faculty,
                           course_count=course_count,
                           lecturer_count=lecturer_count)


@app.route('/dap_dashboard')
@login_required
def dap_dashboard():
    # 🚨 FIX: Safe role check
    user_role = (current_user.role or '').lower().strip()
    
    if user_role != 'dap':
        flash("Access denied. Redirecting to your dashboard.", "warning")
        return redirect_by_role(current_user.role)

    total_students = User.query.filter_by(role='student').count()
    total_courses = Course.query.count()
    return render_template('dap_dashboard.html',
                           total_students=total_students,
                           total_courses=total_courses)


@app.route('/dap_analytics')
@login_required
def dap_analytics():
    # 🚨 FIX: Safe role check
    user_role = (current_user.role or '').lower().strip()
    
    if user_role != 'dap':
        flash("Access denied. Redirecting to your dashboard.", "warning")
        return redirect_by_role(current_user.role)

    results = (
        db.session.query(Course.faculty, func.count(Attendance.id))
        .join(Attendance)
        .group_by(Course.faculty)
        .all()
    )
    labels = [row[0] for row in results]
    data = [row[1] for row in results]
    return render_template('analytics_dap.html', labels=labels, data=data)


# ============================================================
# AUTHORIZATION HELPERS
# ============================================================
# One place decides who may manage or read a course, so a new route cannot
# quietly invent a weaker rule than its neighbours.

def _is_coordinator():
    """True when the signed-in user holds the course-coordinator post."""
    return (current_user.role or '').lower().strip() == 'course coordinator'


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
    role = (current_user.role or '').lower().strip()
    if _is_course_authorized(course):
        return True
    # A supervisory post only reaches courses inside its own patch, and only
    # when that patch is actually recorded — a NULL department must never
    # match a course whose department is also NULL.
    if role == 'hod':
        return bool(current_user.department) and course.department == current_user.department
    if role == 'dean':
        return bool(current_user.faculty) and course.faculty == current_user.faculty
    if role == 'dap':
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

    code = (request.form.get('code') or '').strip()[:10]
    title = (request.form.get('title') or '').strip()[:100]

    if not code or not title:
        flash("Course code and title are required!", "error")
        return redirect(url_for('dashboard'))

    if Course.query.filter_by(code=code).first():
        flash(f"Course code {code} is already taken.", "error")
        return redirect(url_for('dashboard'))

    new_course = Course(
        code=code,
        title=title,
        coordinator_id=current_user.id,
        department=getattr(current_user, 'department', None),
        faculty=getattr(current_user, 'faculty', None),
    )
    db.session.add(new_course)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(f"Course code {code} is already taken.", "error")
        return redirect(url_for('dashboard'))
    flash(f"Course {code} created successfully!", "success")
    return redirect(url_for('dashboard'))


@app.route('/api/course/<int:course_id>/enrolled_students')
@login_required
@limiter.exempt
def get_enrolled_students(course_id):
    course = Course.query.get_or_404(course_id)

    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403

    # Grab all students who have registered for this specific course
    students = User.query.filter(User.enrolled_courses.any(id=course_id)).all()

    student_list = []
    for student in students:
        student_list.append({
            "name": student.full_name,
            "matric_no": student.matric_no or "N/A",
            "level": student.level or "N/A"
        })

    return jsonify({
        "status": "success",
        "total": len(student_list),
        "students": student_list
    })

# FIX #9: DELETE only via POST (removed GET)
@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)

    if course.coordinator_id != current_user.id:
        flash('Unauthorised: Only the course creator can delete it.', 'error')
        return redirect(url_for('dashboard'))

    Attendance.query.filter_by(course_id=course_id).delete()
    ClassSession.query.filter_by(course_id=course_id).delete()
    db.session.delete(course)
    db.session.commit()
    flash(f'Course "{course.code}" has been deleted.', 'success')
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
    if (current_user.role or '').lower().strip() != 'student':
        flash("Only students can register for a course.", "error")
        return redirect(url_for('dashboard'))

    course_code = (request.form.get('course_code') or '').strip()
    course = Course.query.filter_by(code=course_code).first()

    if not course:
        flash("Course not found!", "error")
        return redirect(url_for('student_dashboard'))

    if course in current_user.enrolled_courses:
        flash(f"You are already registered for {course.code}.", "info")
    else:
        current_user.enrolled_courses.append(course)
        try:
            db.session.commit()
            flash(f"✅ Successfully registered for {course.code}.", "success")
        except IntegrityError:
            db.session.rollback()
            flash(f"You are already registered for {course.code}.", "info")

    return redirect(url_for('student_dashboard'))


# ============================================================
# QR CODE ROUTES  (FIX #3, #5, #6)
# ============================================================

_daily_session_locks = {}
_daily_session_locks_guard = threading.Lock()


def _get_or_create_todays_session(course):
    """
    Return today's ClassSession for a course, creating it if the lecturer
    hasn't started one yet. Re-opening the QR page on the same day resumes
    the SAME session, so a refresh never fragments one class meeting into
    several record sets — while next week's class gets a brand-new session.
    """
    with _daily_session_locks_guard:
        course_lock = _daily_session_locks.setdefault(course.id, threading.Lock())

    with course_lock:
        now = _utcnow()
        day_start = datetime.combine(now.date(), datetime.min.time())
        day_end = day_start + timedelta(days=1)

        # The in-process lock covers threads and local SQLite.  The advisory
        # transaction lock serializes this decision across Gunicorn workers.
        if db.session.get_bind().dialect.name == 'postgresql':
            db.session.execute(
                db.text('SELECT pg_advisory_xact_lock(:namespace, :course_id)'),
                {'namespace': 835_211, 'course_id': course.id},
            )

        session_row = (ClassSession.query
                       .filter(ClassSession.course_id == course.id,
                               ClassSession.date_created >= day_start,
                               ClassSession.date_created < day_end)
                       .order_by(ClassSession.date_created.desc())
                       .first())
        if session_row:
            db.session.commit()
            return session_row

        session_row = ClassSession(
            course_id=course.id,
            title=f"Lecture on {now.strftime('%b %d, %Y')}",
            date_created=now,
        )
        db.session.add(session_row)
        db.session.commit()
        return session_row


@app.route('/generate_qr/<int:course_id>')
@login_required
def generate_qr(course_id):
    """Legacy entry point: opens (or resumes) today's session for the course."""
    course = Course.query.get_or_404(course_id)
    if not _is_course_authorized(course):
        flash('Unauthorised Access', 'error')
        return redirect(url_for('dashboard'))
    session_row = _get_or_create_todays_session(course)
    return redirect(url_for('session_qr', session_id=session_row.id))


@app.route('/session/<int:session_id>/qr')
@login_required
def session_qr(session_id):
    """Live QR projector page for ONE class session."""
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)
    if not _is_course_authorized(course):
        flash('Unauthorised Access', 'error')
        return redirect(url_for('dashboard'))
    return render_template('generate_qr.html', course=course, session=session_row,
                           qr_token_ttl=QR_TOKEN_TTL,
                           geofence_required=GEOFENCE_REQUIRED)


@app.route('/api/qr_data/<int:session_id>')
@login_required
@limiter.exempt
def get_qr_data(session_id):
    """
    FIX #6: Returns the same cached signed token as the image endpoint.
    FIX #3: Token is HMAC-signed so it cannot be forged.
    """
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)
    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403

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
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)
    if not _is_course_authorized(course):
        return "Unauthorised", 403

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
    if redis_client:
        cached = _redis_timed('get', redis_client.get, cache_key)
        if cached:
            try:
                summary = json.loads(cached)
                present = int(summary['present'])
                enrolled_total = int(summary['enrolled'])
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                present = enrolled_total = None

    if present is None:
        present = (db.session.query(func.count(Attendance.id))
                   .filter(Attendance.session_id == session_id)
                   .scalar()) or 0
        enrolled_total = _enrolled_count(course.id)
        if redis_client:
            _redis_timed('setex', redis_client.setex, cache_key, 2, json.dumps({
                'present': present,
                'enrolled': enrolled_total,
            }))

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
        "time": ts.strftime('%I:%M %p') if ts else "",
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


@app.route('/set_location/<int:course_id>', methods=['POST'])
@login_required
def set_location(course_id):
    course = Course.query.get_or_404(course_id)
    if not _is_course_authorized(course):
        return jsonify({"status": "error", "message": "Unauthorised"}), 403

    data = request.get_json(silent=True) or {}
    try:
        latitude = float(data['lat'])
        longitude = float(data['lon'])
    except (KeyError, TypeError, ValueError):
        return jsonify({"status": "error", "message": "Valid latitude and longitude are required."}), 400
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return jsonify({"status": "error", "message": "Latitude or longitude is out of range."}), 400

    # FIX #4: Persisted in Redis (not a local dict)
    set_class_location(course_id, latitude, longitude)
    app.logger.info('Class location set for course %s', course_id)
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


def _post_scan_notifications(app_instance, student_id, course_id, timestamp_str):
    """
    Everything that used to run inside /mark_attendance after the row was
    committed: confirmation email, WhatsApp + parent alerts, and the
    early-warning check. Runs on the executor so the scan response returns
    immediately — at 2000 scans per class these extra queries and template
    renders would otherwise hold the request workers hostage.
    """
    with app_instance.app_context():
        try:
            student = db.session.get(User, student_id)
            course = db.session.get(Course, course_id)
            if not student or not course:
                return

            pref = NotificationPreference.query.filter_by(user_id=student_id).first()

            # Send attendance confirmation email (honours the user's
            # email_alerts preference and the global kill switch).
            if SCAN_CONFIRMATION_EMAILS and (not pref or pref.email_alerts):
                send_attendance_confirmation(
                    user_email=student.email,
                    user_name=student.full_name,
                    course_code=course.code,
                    course_title=course.title,
                    timestamp=timestamp_str
                )

            # ── Real-time WhatsApp alert ──
            if pref and pref.whatsapp_alerts and pref.phone_number:
                send_attendance_whatsapp(
                    phone=pref.phone_number,
                    student_name=student.full_name,
                    course_code=course.code,
                    course_title=course.title,
                    timestamp_str=timestamp_str
                )

            # ── Parent/Guardian real-time alerts ──
            if pref and pref.notify_parent:
                parent_name = pref.parent_name or 'Parent/Guardian'
                # WhatsApp to parent
                if pref.parent_phone:
                    send_parent_attendance_whatsapp(
                        phone=pref.parent_phone,
                        parent_name=parent_name,
                        student_name=student.full_name,
                        course_code=course.code,
                        course_title=course.title,
                        timestamp_str=timestamp_str
                    )
                # Email to parent
                if pref.parent_email:
                    send_parent_attendance_email(
                        app_instance=app_instance,
                        mail_func=send_email,
                        pref=pref,
                        student_name=student.full_name,
                        course_code=course.code,
                        course_title=course.title,
                        timestamp_str=timestamp_str
                    )

            # ── Early-warning check (alerts student + parent if below threshold) ──
            # Hand over the preference row we already loaded: without it the
            # pipeline re-queries NotificationPreference twice more per scan,
            # which is 2000-4000 wasted queries across a full class.
            process_early_warning(
                student=student,
                course=course,
                app_instance=app_instance,
                mail_func=send_email,
                Attendance_model=Attendance,
                ClassSession_model=ClassSession,
                db_session=db.session,
                preference=pref,
            )
        except Exception:
            app_instance.logger.exception(
                'Post-scan notification failed for user id=%s', student_id
            )


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
      400  the token is malformed or expired  -> a fresh code may work
      403  not enrolled                       -> terminal
      404  the session no longer exists       -> terminal
      409  already marked, or a queued scan   -> terminal
           belonging to a different account
      422  location missing/stale/too far     -> retryable once they move
      429  rate limited (from the limiter)    -> back off
      5xx  server fault                       -> back off
    Returning 200 for all of these is what put rejected phones into an
    endless resubmit loop.
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
        stage_started = now

    def respond(status, message, http_status, outcome):
        total_ms = (time.perf_counter() - request_started) * 1000
        runtime_metrics.observe_ms('scan.response', total_ms)
        runtime_metrics.increment(f'scan.outcome.{outcome}')
        if status != 'success' or secrets.randbelow(10000) < int(SCAN_LOG_SAMPLE_RATE * 10000):
            app.logger.info('scan_performance %s', json.dumps({
                'outcome': outcome,
                'total_ms': round(total_ms, 2),
                'stages_ms': {key: round(value, 2) for key, value in stages.items()},
            }, separators=(',', ':')))
        response = jsonify({'status': status, 'message': message})
        if stages:
            response.headers['Server-Timing'] = ', '.join(
                f'{name};dur={value:.2f}' for name, value in stages.items()
            )
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
                Course.id.label('course_id'),
                Course.code.label('course_code'),
                Course.title.label('course_title'),
            )
            .join(Course, Course.id == ClassSession.course_id)
            .where(ClassSession.id == session_id)
        ).mappings().one_or_none()
        checkpoint('session_course')
        if target is None:
            return respond('error', 'Invalid QR Code: Class session not found.',
                           404, 'missing_session')

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

        class_loc = get_class_location(target['course_id'])
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
            location_age_ms = data.get('location_age_ms')
            if isinstance(location_age_ms, (int, float)) and location_age_ms > 30000:
                return respond('error', 'Location fix is stale. Please scan again.',
                               422, 'stale_location')
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

        # Drop the cached headcount so the lecturer's live counter moves with
        # the name list instead of lagging behind it.
        if redis_client:
            try:
                _redis_timed('delete', redis_client.delete,
                             f"attendees_summary:{target['session_id']}")
            except redis.RedisError:
                runtime_metrics.increment('redis.invalidation_errors')

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

        # Confirmation email, WhatsApp, parent alerts and the early-warning
        # check all run AFTER the response, on the executor.
        timestamp_str = datetime.now().strftime('%B %d, %Y at %I:%M %p')
        if notification_work_executor.submit(
            _post_scan_notifications,
            app,
            current_user.id,
            target['course_id'],
            timestamp_str,
        ) is None:
            app.logger.warning(
                'Notification queue full; no confirmation sent for attendance id %s',
                record_id)
        checkpoint('enqueue')

        return respond('success', 'Attendance marked successfully!', 200, 'success')

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
    course = Course.query.get_or_404(course_id)

    if not _attendance_authorized(course):  # FIX #8
        flash("Unauthorised access to attendance list.", "error")
        return redirect(url_for('dashboard'))

    # Eager-load each session's attendances AND their students: without this
    # the loop below fires one query per session plus one per attendance row
    # when the template prints student names (a semester of 2000-student
    # sessions = tens of thousands of queries on one page view).
    page = max(1, request.args.get('page', default=1, type=int) or 1)
    pagination = (ClassSession.query
                  .options(selectinload(ClassSession.attendances)
                           .selectinload(Attendance.student))
                  .filter_by(course_id=course_id)
                  .order_by(ClassSession.date_created.desc())
                  .paginate(page=page, per_page=10, error_out=False))
    sessions = pagination.items

    enrolled_total = _enrolled_count(course_id)

    sessions_data = []
    for sess in sessions:
        records = sorted(sess.attendances,
                         key=lambda r: r.timestamp or datetime.min)
        present = len(records)
        pct = round(present / enrolled_total * 100) if enrolled_total else None
        sessions_data.append({
            'session': sess,
            'records': records,
            'present': present,
            'pct': pct,
        })

    total_scans = (db.session.query(func.count(Attendance.id))
                   .filter(Attendance.course_id == course_id,
                           Attendance.session_id.isnot(None))
                   .scalar()) or 0
    avg_present = round(total_scans / pagination.total) if pagination.total else 0

    # Rows that never got adopted by the startup backfill (shouldn't happen)
    unassigned = Attendance.query.filter_by(course_id=course_id) \
                                 .filter(Attendance.session_id.is_(None)).count()

    return render_template('view_attendance.html',
                           course=course,
                           sessions_data=sessions_data,
                           enrolled_total=enrolled_total,
                           avg_present=avg_present,
                           unassigned=unassigned,
                           pagination=pagination,
                           can_manage=_is_course_authorized(course))


def _csv_cell(value):
    """Quote a value for CSV, escaping embedded double quotes."""
    return '"' + str(value if value is not None else "N/A").replace('"', '""') + '"'


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

    safe_code = (course.code or "course").replace(' ', '_')
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
        enrolled = list(course.students) if hasattr(course, 'students') else []

        csv_data = _StreamingCSVBuffer(
            "Matric Number,Full Name,Level,Status,Time Scanned,Device ID\n"
        )
        listed_ids = set()
        for student in sorted(enrolled, key=lambda s: (s.matric_no or '', s.full_name or '')):
            listed_ids.add(student.id)
            rec = records.get(student.id)
            if rec:
                time_str = rec.timestamp.strftime('%Y-%m-%d %I:%M %p') if rec.timestamp else "N/A"
                device = rec.device_id or "N/A"
                row = [student.matric_no, student.full_name, student.level, "Present", time_str, device]
            else:
                row = [student.matric_no, student.full_name, student.level, "Absent", "-", "-"]
            csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

        # Scans from students no longer enrolled (kept for the record)
        for rec in session_records:
            if rec.student_id in listed_ids:
                continue
            student = rec.student
            time_str = rec.timestamp.strftime('%Y-%m-%d %I:%M %p') if rec.timestamp else "N/A"
            row = [student.matric_no if student else "UNKNOWN",
                   (student.full_name if student else "Deleted User") + " (not enrolled)",
                   student.level if student else "N/A",
                   "Present", time_str, rec.device_id or "N/A"]
            csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

        date_tag = sess.date_created.strftime('%Y-%m-%d') if sess.date_created else "session"
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename={safe_code}_{date_tag}_attendance.csv"}
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

    session_labels = []
    for sess in sessions:
        date_str = sess.date_created.strftime('%Y-%m-%d') if sess.date_created else "?"
        session_labels.append(f"{sess.title} ({date_str})")

    header = ["Matric Number", "Full Name", "Level"] + session_labels + \
             ["Classes Attended", "Classes Held", "Attendance %"]
    csv_data = _StreamingCSVBuffer(",".join(_csv_cell(h) for h in header) + "\n")

    all_students = sorted(students_by_id.values(),
                          key=lambda s: (s.matric_no or '', s.full_name or ''))
    total_sessions = len(sessions)

    if not all_students:
        csv_data += _csv_cell("NO STUDENTS ENROLLED YET") + "\n"
    for student in all_students:
        attended = attended_map.get(student.id, set())
        name = student.full_name or "N/A"
        if student.id not in enrolled_ids:
            name += " (not enrolled)"
        row = [student.matric_no, name, student.level]
        row += ["Present" if sess.id in attended else "Absent" for sess in sessions]
        pct = round(len(attended) / total_sessions * 100) if total_sessions else 0
        row += [len(attended), total_sessions, f"{pct}%"]
        csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

    return Response(
        csv_data,
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename={safe_code}_attendance_register.csv"}
    )

    # ============================================================
# ANALYTICS
# ============================================================

@app.route('/course/<int:course_id>/analytics')
@login_required
def course_analytics(course_id):
    course = Course.query.get_or_404(course_id)

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

    # Format the data for Chart.js
    dates = [sess.date_created.strftime('%b %d') if sess.date_created else '?'
             for sess, _count in per_session]
    counts = [count for _sess, count in per_session]

    return render_template('analytics.html',
                           course=course,
                           dates=dates,
                           counts=counts)


@app.route('/course/<int:course_id>/start_session', methods=['POST'])
@login_required
def start_session(course_id):
    course = Course.query.get_or_404(course_id)

    # Security check: Ensure they are the lecturer
    if not _is_course_authorized(course):
        return "Unauthorised", 403

    # Open today's class meeting (or resume it if already started today),
    # then head to the live QR projector page for that session.
    session_row = _get_or_create_todays_session(course)
    return redirect(url_for('session_qr', session_id=session_row.id))


@app.route('/session/<int:session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    """Remove a class session started by mistake (and its scans), so it
    doesn't count as a 'class held' in every student's percentage."""
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)

    if not _is_course_authorized(course):
        flash("Unauthorised: only the course lecturers can delete a session.", "error")
        return redirect(url_for('dashboard'))

    db.session.delete(session_row)  # cascade removes its attendance records
    db.session.commit()
    flash(f'Session "{session_row.title}" and its records were deleted.', 'success')
    return redirect(url_for('view_attendance', course_id=course.id))

# ============================================================
# NOTIFICATION SETTINGS ROUTES
# ============================================================

@app.route('/notification_settings', methods=['GET', 'POST'])
@login_required
def notification_settings():
    pref = NotificationPreference.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        if not pref:
            pref = NotificationPreference(user_id=current_user.id)
            db.session.add(pref)

        # Update student preferences
        phone = request.form.get('phone_number', '').strip()
        if phone and not phone.startswith('+'):
            phone = '+234' + phone.lstrip('0')
        pref.phone_number = phone or None

        pref.whatsapp_alerts = bool(request.form.get('whatsapp_alerts'))
        pref.email_alerts = bool(request.form.get('email_alerts'))
        pref.weekly_report = bool(request.form.get('weekly_report'))

        threshold = request.form.get('warning_threshold', '75')
        try:
            pref.warning_threshold = max(10, min(100, int(threshold)))
        except ValueError:
            pref.warning_threshold = 75

        # Update parent/guardian preferences
        pref.parent_name = request.form.get('parent_name', '').strip() or None
        pref.parent_email = request.form.get('parent_email', '').strip() or None

        parent_phone = request.form.get('parent_phone', '').strip()
        if parent_phone and not parent_phone.startswith('+'):
            parent_phone = '+234' + parent_phone.lstrip('0')
        pref.parent_phone = parent_phone or None

        pref.notify_parent = bool(request.form.get('notify_parent'))

        db.session.commit()
        flash('Notification settings updated! ✅', 'success')
        return redirect(url_for('notification_settings'))

    return render_template('notification_settings.html', pref=pref)


# ============================================================
# WEEKLY REPORT SCHEDULER
# ============================================================

def run_weekly_reports():
    """Generate and email weekly PDF reports for all opted-in users."""
    with app.app_context():
        today = _utcnow().date()
        week_end = today
        week_start = today - timedelta(days=7)
        week_range = f"{week_start.strftime('%d %b')} — {week_end.strftime('%d %b %Y')}"

        print(f"\n📊 Running weekly reports for {week_range}...")

        # ── Batched aggregates (once, up front) ──
        # The old version ran two COUNT queries per (student, course) plus a
        # WeeklyReport lookup per user: with 2000 opted-in students that was
        # tens of thousands of queries every Monday. These few GROUP BY
        # queries replace all of them.
        sessions_per_course = dict(
            db.session.query(ClassSession.course_id, func.count(ClassSession.id))
            .group_by(ClassSession.course_id).all())
        attendance_per_course = dict(
            db.session.query(Attendance.course_id, func.count(Attendance.id))
            .group_by(Attendance.course_id).all())
        enrolled_per_course = dict(
            db.session.query(enrollments.c.course_id, func.count(enrollments.c.user_id))
            .group_by(enrollments.c.course_id).all())
        week_start_dt = datetime.combine(week_start, datetime.min.time())
        week_end_dt = datetime.combine(week_end, datetime.max.time())
        sessions_this_week_per_course = dict(
            db.session.query(ClassSession.course_id, func.count(ClassSession.id))
            .filter(ClassSession.date_created >= week_start_dt,
                    ClassSession.date_created <= week_end_dt)
            .group_by(ClassSession.course_id).all())
        # (student_id, course_id) -> classes attended, for opted-in students
        attended_map = {
            (sid, cid): n for sid, cid, n in (
                db.session.query(Attendance.student_id, Attendance.course_id,
                                 func.count(Attendance.id))
                .join(NotificationPreference,
                      NotificationPreference.user_id == Attendance.student_id)
                .filter(NotificationPreference.weekly_report == True)
                .group_by(Attendance.student_id, Attendance.course_id).all())
        }
        # Reports already sent this week, both types, in one query
        already_sent = {
            (r.user_id, r.report_type)
            for r in WeeklyReport.query.filter_by(week_start=week_start).all()
        }

        # ── Student Reports ──
        students_with_pref = (
            db.session.query(User, NotificationPreference)
            .join(NotificationPreference, NotificationPreference.user_id == User.id)
            # Roles are stored in mixed case ('Student'/'student' both exist —
            # see the lecturer filter below); the old exact match silently
            # skipped every 'Student'-cased user.
            .filter(func.lower(User.role) == 'student')
            .filter(NotificationPreference.weekly_report == True)
            .options(selectinload(User.enrolled_courses))
            .all()
        )

        for student, pref in students_with_pref:
            if (student.id, 'student') in already_sent:
                continue

            # Build course data from the precomputed aggregates
            courses_data = []
            for course in getattr(student, 'enrolled_courses', []):
                total_sessions = sessions_per_course.get(course.id, 0)
                attended = attended_map.get((student.id, course.id), 0)
                pct = (attended / total_sessions * 100) if total_sessions > 0 else 0
                courses_data.append({
                    'code': course.code,
                    'title': course.title,
                    'total_sessions': total_sessions,
                    'attended': attended,
                    'percentage': pct,
                })

            if not courses_data:
                continue

            pdf_buf = generate_student_weekly_pdf(
                student, courses_data,
                datetime.combine(week_start, datetime.min.time()),
                datetime.combine(week_end, datetime.min.time())
            )
            send_weekly_report_email(
                app, send_email, student.email, student.full_name,
                pdf_buf, 'student', week_range
            )

            # Also send a copy to parent/guardian if enabled
            if pref.notify_parent and pref.parent_email:
                parent_name = pref.parent_name or 'Parent/Guardian'
                pdf_buf.seek(0)  # reset buffer for re-read
                send_weekly_report_email(
                    app, send_email, pref.parent_email,
                    f"{parent_name} (re: {student.full_name})",
                    pdf_buf, 'parent', week_range
                )

            # Record
            db.session.add(WeeklyReport(
                user_id=student.id,
                week_start=week_start,
                week_end=week_end,
                report_type='student'
            ))

        # ── Lecturer Reports ──
        lecturers = (User.query
                     .filter(User.role.in_(['lecturer', 'Lecturer',
                                            'Course Coordinator', 'course coordinator']))
                     .options(selectinload(User.coordinated_courses),
                              selectinload(User.teaching_courses))
                     .all())

        lec_prefs = {
            p.user_id: p
            for p in NotificationPreference.query.filter(
                NotificationPreference.user_id.in_([l.id for l in lecturers])
            ).all()
        } if lecturers else {}

        for lecturer in lecturers:
            lec_pref = lec_prefs.get(lecturer.id)
            if lec_pref and not lec_pref.weekly_report:
                continue

            if (lecturer.id, 'lecturer') in already_sent:
                continue

            # Get courses this lecturer manages (eager-loaded above)
            coordinated = getattr(lecturer, 'coordinated_courses', [])
            teaching = getattr(lecturer, 'teaching_courses', [])
            all_courses = list(set(list(coordinated) + list(teaching)))

            if not all_courses:
                continue

            courses_data = []
            for course in all_courses:
                total_enrolled = enrolled_per_course.get(course.id, 0)
                sessions_week = sessions_this_week_per_course.get(course.id, 0)
                total_sessions = sessions_per_course.get(course.id, 0)

                # Average attendance
                if total_sessions > 0 and total_enrolled > 0:
                    total_att = attendance_per_course.get(course.id, 0)
                    avg_pct = (total_att / (total_sessions * total_enrolled)) * 100
                else:
                    avg_pct = 0

                courses_data.append({
                    'code': course.code,
                    'title': course.title,
                    'total_enrolled': total_enrolled,
                    'sessions_this_week': sessions_week,
                    'avg_attendance_pct': avg_pct,
                })

            pdf_buf = generate_lecturer_weekly_pdf(
                lecturer, courses_data,
                datetime.combine(week_start, datetime.min.time()),
                datetime.combine(week_end, datetime.min.time())
            )
            send_weekly_report_email(
                app, send_email, lecturer.email, lecturer.full_name,
                pdf_buf, 'lecturer', week_range
            )

            db.session.add(WeeklyReport(
                user_id=lecturer.id,
                week_start=week_start,
                week_end=week_end,
                report_type='lecturer'
            ))

        db.session.commit()
        print("✅ Weekly reports sent!")


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
    _migrations = [
        # Parent/guardian notification columns
        ("notification_preference", "parent_name",   "VARCHAR(100)"),
        ("notification_preference", "parent_email",  "VARCHAR(120)"),
        ("notification_preference", "parent_phone",  "VARCHAR(20)"),
        ("notification_preference", "notify_parent", "BOOLEAN DEFAULT FALSE"),
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
    ]
    database_inspector = inspect(db.engine)
    existing_columns = {
        table: {column['name'] for column in database_inspector.get_columns(table)}
        for table in {table for table, _column, _type in _migrations}
    }
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
            conn.execute(db.text(
                f"ALTER TABLE {quote(table)} {add_column} {quote(column)} {col_type}"
            ))
            conn.commit()
            existing_columns[table].add(column)
            print(f"[MIGRATION] Added {table}.{column}")

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
                day = (rec.timestamp or _utcnow()).date()
                by_course_day.setdefault((rec.course_id, day), []).append(rec)

            for (course_id, day), recs in sorted(by_course_day.items(),
                                                 key=lambda item: (item[0][0], item[0][1])):
                session_row = ClassSession.query.filter(
                    ClassSession.course_id == course_id,
                    func.date(ClassSession.date_created) == day
                ).first()
                if not session_row:
                    first_ts = min((r.timestamp for r in recs if r.timestamp),
                                   default=_utcnow())
                    session_row = ClassSession(
                        course_id=course_id,
                        title=f"Lecture on {day.strftime('%b %d, %Y')}",
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
        except Exception as e:
            conn.rollback()
            print(f"[MIGRATION] Duplicate-attendance cleanup failed: {e}")

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
        ):
            try:
                conn.execute(db.text(_index_sql))
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"[MIGRATION] Index creation failed (will retry next boot): {e}")

    # Release the scoped session before disposing preload connections.  This
    # also keeps in-memory SQLite smoke tests from tearing down a live session.
    db.session.remove()
    db.engine.dispose()  # Forces Gunicorn workers to create fresh connections
    print("[OK] Database initialized successfully!")

# APScheduler: Weekly reports every Monday at 7 AM
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = None
    if os.environ.get('SCANMARK_DISABLE_SCHEDULER', '').lower() not in {'1', 'true', 'yes'}:
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=run_weekly_reports,
            trigger='cron',
            day_of_week='mon',
            hour=7,
            minute=0,
            id='weekly_reports',
            replace_existing=True
        )
        scheduler.start()
        print("[OK] Weekly report scheduler active (Monday 07:00)")
except ImportError:
    print("⚠️  APScheduler not installed. Weekly reports won't run automatically.")
    print("   Install with: pip install APScheduler")

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
    print(f"📱 WhatsApp Alerts: {'Enabled' if os.environ.get('TWILIO_ACCOUNT_SID') else 'Disabled'}")
    print(f"📧 Email Verification: {'Required' if REQUIRE_EMAIL_VERIFICATION else 'Not required'}")
    print("📊 Weekly PDF Reports: Scheduled (Monday 7 AM)")
    print(f"⚠️  Early-Warning Threshold: {DEFAULT_ATTENDANCE_THRESHOLD}%")
    print("=" * 60 + "\n")

    # The reloader/debugger is opt-in rather than always-on: `debug=True` here
    # exposes the Werkzeug console to anything that can reach port 5000.
    app.run(host=os.environ.get('DEV_HOST', '127.0.0.1'), port=5000,
            debug=os.environ.get('FLASK_DEBUG', '').strip().lower()
            in ('1', 'true', 'yes', 'on'))
