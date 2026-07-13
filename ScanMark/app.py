import os
import io
import hmac
import hashlib
import secrets
import time
import math
import re
import json
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
load_dotenv()
from authlib.integrations.flask_client import OAuth
from flask import (Flask, render_template, redirect, url_for,
                   flash, request, send_file, jsonify, Response)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
import redis
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import send_from_directory
from flask_wtf.csrf import CSRFProtect
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

from models import db, User, Course, Attendance, ClassSession, NotificationPreference, WeeklyReport
from notifications import (
    send_attendance_whatsapp,
    send_warning_whatsapp,
    check_attendance_threshold,
    process_early_warning,
    generate_student_weekly_pdf,
    generate_lecturer_weekly_pdf,
    send_weekly_report_email,
    send_parent_attendance_whatsapp,
    send_parent_attendance_email,
    DEFAULT_ATTENDANCE_THRESHOLD,
)

# ============================================================
# SENTRY ERROR MONITORING
# ============================================================
sentry_dsn = os.environ.get('SENTRY_DSN')
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        
        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        traces_sample_rate=1.0,
        
        # Profiles sample rate helps you find CPU bottlenecks (like slow DB queries)
        profiles_sample_rate=1.0,
        
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
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError("CRITICAL: SECRET_KEY environment variable is not set! Refusing to start.")
    else:
        _secret = 'local_dev_fallback_key_do_not_use_in_prod'
        print("⚠️  WARNING: SECRET_KEY not set. Using insecure fallback for local dev only.")

app.config['SECRET_KEY'] = _secret
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 🚨 FIX: Silence SQLAlchemy warnings

# FIX #2: Enable CSRF protection globally
csrf = CSRFProtect(app)

def user_based_rate_limit_key():
    """
    If the user is logged in, use their unique database ID.
    If they are not logged in (e.g., on the signup page), fallback to their IP address.
    """
    if current_user.is_authenticated:
        return f"user_{current_user.id}"
    return request.remote_addr

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

limiter_storage = os.environ.get('REDIS_URL', 'memory://')
limiter = Limiter(
    app=app,
    key_func=user_based_rate_limit_key,
    default_limits=["5000 per day", "1000 per minute"] # Give them some breathing room!
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

# 🚨 THE FIX: Create a pool of 5 workers to handle all emails safely
email_executor = ThreadPoolExecutor(max_workers=5)

def send_async_email(app_instance, msg):
    """Send email asynchronously to avoid blocking"""
    with app_instance.app_context():
        try:
            mail.send(msg)
            print(f"✅ Email sent successfully to {msg.recipients}")
        except Exception as e:
            print(f"❌ Failed to send email: {str(e)}")


def send_email(subject, recipients, text_body, html_body, sender=None):
    msg = Message(
        subject=subject,
        recipients=recipients if isinstance(recipients, list) else [recipients],
        sender=sender or app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = text_body
    msg.html = html_body
    
    # 🚨 THE FIX: Hand the email to the bouncer instead of spawning an infinite thread
    email_executor.submit(send_async_email, app, msg)

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

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///scanmark_v2.db'
if db_url and db_url.startswith("postgresql://"):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_size": 10,          
        "max_overflow": 20,       
        "pool_recycle": 1800,     
        "pool_timeout": 30,
        "pool_pre_ping": True     # 🚨 THE FIX: Silently tests the connection before running a query
    }
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
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ============================================================
# FUNAAB EMAIL VALIDATION
# ============================================================

# Valid FUNAAB email domains
FUNAAB_DOMAINS = [
    'funaab.edu.ng',
    'student.funaab.edu.ng',
    'staff.funaab.edu.ng',
    'gmail.com'
]


def is_valid_funaab_email(email):
    """
    Check if email is a valid FUNAAB email address OR a standard Gmail
    """
    if not email:
        return False, "Email is required", None
    
    # Basic email format validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format", None
    
    email = email.lower().strip()
    
    is_valid = False
    role = None
    
    # Check domains and assign roles
    if email.endswith('@gmail.com'):
        is_valid = True
        role = 'student'
    elif email.endswith('@staff.funaab.edu.ng'):
        is_valid = True
        role = 'lecturer'  # Default for staff
    elif email.endswith('@funaab.edu.ng'):
        is_valid = True
        role = 'student'
    # 🚨 THE NEW GMAIL RULE: Allowed, but strictly as a student
    elif email.endswith('@gmail.com'):
        is_valid = True
        role = 'student'
    
    if is_valid:
        return True, "Valid email", role
    else:
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
    except:
        return ""


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

# Timestamps are stored in UTC; FUNAAB runs on West Africa Time (UTC+1).
# All display formatting and "what day is it" decisions use local time.
LOCAL_TZ = ZoneInfo(os.environ.get('APP_TIMEZONE', 'Africa/Lagos'))

# Label stamped on courses/sessions until the coordinator starts a new
# semester with their own name (e.g. "2026/2027 First Semester").
DEFAULT_SEMESTER = os.environ.get('DEFAULT_SEMESTER', '2025/2026')

# Max distance (metres) between lecturer and student for a scan to count as
# location-verified. Was hardcoded 500 while the message claimed 50.
GEOFENCE_RADIUS_M = int(os.environ.get('GEOFENCE_RADIUS_M', 100))


def to_local(dt):
    """Convert a stored UTC datetime to local (Africa/Lagos) time."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).astimezone(LOCAL_TZ)


@app.template_filter('localtime')
def localtime_filter(dt, fmt='%I:%M %p'):
    local = to_local(dt)
    return local.strftime(fmt) if local else ''


def _local_day_bounds_utc():
    """Return (start, end) naive-UTC datetimes spanning the current LOCAL day,
    for comparing against UTC-stored timestamps."""
    now_local = datetime.now(LOCAL_TZ)
    start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    start_utc = start_local.astimezone(timezone.utc).replace(tzinfo=None)
    return start_utc, start_utc + timedelta(days=1)


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

def set_class_location(course_id, lat, lon):
    """Store lecturer's class location in Redis (expires after 4 hours)."""
    if redis_client:
        redis_client.setex(f"class_location:{course_id}", 14400, f"{lat},{lon}")
    else:
        # Local-dev fallback: module-level dict (single process only)
        _local_locations[course_id] = {'lat': lat, 'lon': lon}


def get_class_location(course_id):
    """Retrieve the active class location for a course."""
    if redis_client:
        val = redis_client.get(f"class_location:{course_id}")
        if val:
            lat_str, lon_str = val.decode().split(',')
            return {'lat': float(lat_str), 'lon': float(lon_str)}
        return None
    else:
        return _local_locations.get(course_id)


# Local-dev fallback only (never used when Redis is available)
_local_locations = {}


# ------------------------------------------------------------------
# FIX #3 & #6: Signed, cached QR tokens
# ------------------------------------------------------------------

QR_TOKEN_TTL = 12   # seconds a single token stays valid in Redis
QR_CODE_WINDOW = 15  # seconds before the attendance endpoint rejects the token


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
        cached = redis_client.get(cache_key)
        if cached:
            return cached.decode()

    # Create a new token
    timestamp = int(time.time())
    message = f"S{session_id}|{timestamp}"
    sig = _make_signature(message)
    token = f"{message}|{sig}"

    if redis_client:
        redis_client.setex(cache_key, QR_TOKEN_TTL, token)

    return token


def verify_signed_qr(qr_text: str):
    """
    Verify the QR payload signature and expiry.
    Returns (session_id, timestamp) on success, or raises ValueError.
    """
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

    timestamp = int(timestamp_str)
    if int(time.time()) - timestamp > QR_CODE_WINDOW:
        raise ValueError("QR code has expired. Please scan again.")

    return int(session_part[1:]), timestamp


# ------------------------------------------------------------------
# FIX #11: Optimised analytics (single query, no N+1)
# ------------------------------------------------------------------

def get_course_analytics(course_id):
    """Return attendance stats for a single course."""
    course = Course.query.get(course_id)
    if not course:
        return None

    total_students = len(course.students) if hasattr(course, 'students') else 0
    if total_students == 0:
        return {"dates": [], "counts": [], "average": 0, "total_enrolled": 0}

    attendance_trends = (
        db.session.query(func.date(Attendance.timestamp), func.count(Attendance.id))
        .filter_by(course_id=course_id)
        .group_by(func.date(Attendance.timestamp))
        .all()
    )

    dates = [str(row[0]) for row in attendance_trends]
    counts = [row[1] for row in attendance_trends]
    avg = (sum(counts) / len(counts) / total_students * 100) if counts else 0

    return {
        "dates": dates,
        "counts": counts,
        "average": round(avg, 1),
        "total_enrolled": total_students,
    }


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
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')


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
    
    # Log for debugging (remove in production)
    print(f"🔀 Redirecting role '{role}' to '{target}'")
    
    if target == 'student_dashboard' and role not in mapping:
        flash(f"Role '{role}' not recognized. Defaulting to student view.", "warning")
    
    return redirect(url_for(target))


# ============================================================
# PASSWORD RESET
# ============================================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message(
                "Reset Your ScanMark Password",
                sender=app.config.get('MAIL_USERNAME'),
                recipients=[email]
            )
            msg.body = (
                f"Hello {user.full_name},\n\n"
                "We received a request to reset your ScanMark password.\n"
                f"Click the link below (valid for 15 minutes):\n\n{reset_url}\n\n"
                "If you did not make this request, ignore this email.\n"
            )
            # 🚨 FIX: Use email_executor instead of Thread to prevent crashes
            email_executor.submit(send_async_email, app, msg)

        # Always show the same message to prevent email enumeration
        flash("If an account with that email exists, a password reset link has been sent.", "info")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=900)
    except Exception:
        flash("The password reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            # FIX #1: Consistent hashing method (scrypt everywhere)
            user.password = generate_password_hash(new_password, method='scrypt')
            db.session.commit()
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


@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    email = user_info.get('email')
    full_name = user_info.get('name')

    # Validate FUNAAB email
    is_valid, message, auto_role = is_valid_funaab_email(email)
    if not is_valid:
        flash(f'Access Denied: {message}', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        # FIX #7: Use a cryptographically random dummy password (not a known string)
        user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(secrets.token_hex(32), method='scrypt'),
            role=auto_role or 'student',
            email_verified=True,  # Google already verified this address
        )
        db.session.add(user)
        db.session.commit()

        # Send welcome email
        send_welcome_email(email, full_name, auto_role or 'student')

        flash('Account created via Google! Check your email for confirmation.', 'success')
    elif not user.email_verified:
        # Signing in through Google proves ownership of the address
        user.email_verified = True
        db.session.commit()

    login_user(user)
    return redirect_by_role(user.role)


# ============================================================
# CAMPOS SSO HAND-OFF  (Single Sign-On from CampOS Core)
# ============================================================
# CampOS Core is the identity provider. When a student clicks "ScanMark"
# inside CampOS, Core mints a short-lived signed token carrying their CampOS
# identity and redirects here. We verify the token with the SHARED secret,
# trust the claims, find/create the local user, and log them in — so the
# student signs in once at CampOS and lands here already authenticated.
#
# The signing secret MUST match CampOS Core. Set SSO_JWT_SECRET to the same
# value in both apps (defaults mirror Core so local dev works out of the box).

SSO_ISSUER = 'campos-core'
SSO_AUDIENCE = 'scanmark'


def _sso_secret() -> str:
    return (
        os.environ.get('SSO_JWT_SECRET')
        or os.environ.get('JWT_SECRET')
        or 'campos-jwt-secret-change-in-production'
    )


def _sso_b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring missing padding."""
    padding = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _map_campos_role(roles) -> str:
    """Map CampOS roles onto ScanMark roles. Students are the default."""
    roles = [str(r).lower().strip() for r in (roles or [])]
    if any(r in ('lecturer', 'course coordinator', 'instructor') for r in roles):
        return 'lecturer'
    if 'hod' in roles:
        return 'hod'
    if 'dean' in roles:
        return 'dean'
    return 'student'


def verify_campos_sso_token(token: str) -> dict:
    """
    Verify an HS256 JWT minted by CampOS Core using the Python standard
    library (no extra dependencies). Checks the signature, expiry, issuer
    and audience, and returns the claims dict. Raises ValueError on failure.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        raise ValueError('malformed token')

    header = json.loads(_sso_b64url_decode(header_b64))
    if header.get('alg') != 'HS256':
        raise ValueError('unexpected signing algorithm')

    signing_input = f'{header_b64}.{payload_b64}'.encode('ascii')
    expected_sig = hmac.new(
        _sso_secret().encode('utf-8'), signing_input, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_sig, _sso_b64url_decode(sig_b64)):
        raise ValueError('bad signature')

    claims = json.loads(_sso_b64url_decode(payload_b64))

    now = int(time.time())
    if 'exp' in claims and now > int(claims['exp']) + 5:  # 5s clock leeway
        raise ValueError('token expired')
    if claims.get('iss') != SSO_ISSUER:
        raise ValueError('bad issuer')
    if claims.get('aud') != SSO_AUDIENCE:
        raise ValueError('bad audience')

    return claims


@app.route('/sso/callback')
@csrf.exempt
def campos_sso_callback():
    token = request.args.get('token')
    next_path = request.args.get('next')

    if not token:
        flash('Sign-in failed: missing SSO token.', 'error')
        return redirect(url_for('login'))

    try:
        claims = verify_campos_sso_token(token)
    except Exception as e:
        print(f'⚠️  CampOS SSO rejected: {e}')
        flash('Sign-in failed: the link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    email = (claims.get('email') or '').strip().lower()
    if not email:
        flash('Sign-in failed: no email in identity token.', 'error')
        return redirect(url_for('login'))

    full_name = ' '.join(
        filter(None, [claims.get('firstName'), claims.get('lastName')])
    ).strip() or email.split('@')[0]
    matric_no = claims.get('matricNumber')
    level = claims.get('level')
    role = _map_campos_role(claims.get('roles'))

    user = User.query.filter_by(email=email).first()
    if not user:
        # First arrival from CampOS — provision the local account.
        user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(secrets.token_hex(32), method='scrypt'),
            role=role,
            email_verified=True,  # CampOS is the identity provider
        )
        # CampOS is the source of truth for matric number (guard uniqueness).
        if matric_no and not User.query.filter_by(matric_no=matric_no).first():
            user.matric_no = matric_no
        if level:
            user.level = level
        db.session.add(user)
        db.session.commit()
        print(f'🟢 Created ScanMark user via CampOS SSO: {email}')
    else:
        # Keep identity fresh from the source of truth.
        changed = False
        if not user.email_verified:
            user.email_verified = True
            changed = True
        if full_name and user.full_name != full_name:
            user.full_name = full_name
            changed = True
        if matric_no and not user.matric_no and not User.query.filter_by(matric_no=matric_no).first():
            user.matric_no = matric_no
            changed = True
        if level and not user.level:
            user.level = level
            changed = True
        if changed:
            db.session.commit()

    login_user(user)

    # Only allow safe relative redirects (block open-redirect via ?next=).
    if next_path and next_path.startswith('/') and not next_path.startswith('//'):
        return redirect(next_path)
    return redirect_by_role(user.role)


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
@limiter.limit("5 per minute", error_message="Too many login attempts. Please try again later.")
def login():
    if current_user.is_authenticated:
        return redirect_by_role(current_user.role)

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                # Auto-resend so a lost email never locks anyone out
                send_verification_email(user.email, user.full_name)
                flash("Please verify your email first. We've just re-sent the "
                      "verification link — check your inbox.", 'warning')
                return render_template('login.html')
            login_user(user)
            return redirect_by_role(user.role)
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


def send_verification_email(user_email, user_name):
    """Email a signed link that activates the account (expires in 24h)."""
    token = serializer.dumps(user_email, salt='email-verify-salt')
    verify_url = url_for('verify_email', token=token, _external=True)
    text_body = (
        f"Hello {user_name},\n\n"
        "Confirm your email address to activate your ScanMark account "
        f"(link valid for 24 hours):\n\n{verify_url}\n\n"
        "If you did not sign up, you can ignore this email.\n"
    )
    html_body = (
        f"<p>Hello <strong>{user_name}</strong>,</p>"
        "<p>Confirm your email address to activate your ScanMark account "
        "(link valid for 24 hours):</p>"
        f'<p><a href="{verify_url}" style="display:inline-block;padding:12px 28px;'
        'background:#006838;color:#fff;text-decoration:none;border-radius:6px;'
        'font-weight:700;">Verify my email</a></p>'
        f"<p>Or paste this link into your browser:<br>{verify_url}</p>"
        "<p>If you did not sign up, you can ignore this email.</p>"
    )
    send_email("Verify your ScanMark email", user_email, text_body, html_body)


@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify-salt', max_age=86400)
    except Exception:
        flash("This verification link is invalid or has expired. "
              "Log in to receive a fresh one.", 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Account not found.", 'error')
        return redirect(url_for('signup'))

    if not user.email_verified:
        user.email_verified = True
        db.session.commit()
        send_welcome_email(user.email, user.full_name, user.role)
    flash("Email verified! You can now log in. ✅", 'success')
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = (request.form.get('full_name') or
                request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        matric_no = request.form.get('matric_no', '').strip()
        level = request.form.get('level', '').strip()
        staff_role = request.form.get('staff_role', '').strip()

        if not name:
            flash('Please enter your full name!', 'danger')
            return render_template('signup.html')
        if not email:
            flash('Please enter your email address!', 'danger')
            return render_template('signup.html')
        if not password:
            flash('Please enter a password!', 'danger')
            return render_template('signup.html')

        is_valid, message, auto_role = is_valid_funaab_email(email)
        if not is_valid:
            flash(message, 'danger')
            return render_template('signup.html')

        final_role = auto_role
        if email.endswith('@staff.funaab.edu.ng') and staff_role:
            final_role = staff_role
        elif email.endswith('@staff.funaab.edu.ng') and not staff_role:
            flash('Please select your role (Lecturer or Course Coordinator)', 'danger')
            return render_template('signup.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return render_template('signup.html')

        if User.query.filter_by(email=email).first():
            flash('This FUNAAB email is already registered!', 'warning')
            return redirect(url_for('login'))

        # Matric numbers identify one student — reject a second account
        # claiming the same one instead of failing with a server error.
        if matric_no and User.query.filter_by(matric_no=matric_no).first():
            flash('That matric number is already registered to another account. '
                  'Contact IT support if this is yours.', 'danger')
            return render_template('signup.html')

        new_user = User(
            full_name=name,
            email=email,
            password=generate_password_hash(password, method='scrypt'),
            role=final_role,
            matric_no=matric_no if matric_no else None,
            level=level if level else None,
            email_verified=False,
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            app.logger.info("New signup (id=%s, role=%s)", new_user.id, final_role)

            try:
                send_verification_email(email, name)
            except Exception:
                app.logger.exception("Verification email failed for user id=%s", new_user.id)

            flash('Account created! Check your email for the verification link '
                  'to activate it.', 'success')
            return redirect(url_for('login'))

        except Exception:
            db.session.rollback()
            app.logger.exception("Signup failed")
            flash('Error creating account. Please try again.', 'danger')
            return render_template('signup.html')

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

    enrolled_courses = getattr(current_user, 'enrolled_courses', [])
    attendance_data = []
    for course in enrolled_courses:
        # Stats are scoped to the course's CURRENT semester
        session_ids = [s.id for s in
                       _semester_sessions_query(course, _course_semester(course))
                       .with_entities(ClassSession.id).all()]
        total_sessions = len(session_ids)
        count = Attendance.query.filter(
            Attendance.student_id == current_user.id,
            Attendance.session_id.in_(session_ids)
        ).count() if session_ids else 0
        pct = round(count / total_sessions * 100) if total_sessions else None
        attendance_data.append({
            'course_id': course.id,
            'code': course.code,
            'title': course.title,
            'count': count,
            'total_sessions': total_sessions,
            'pct': pct,
        })

    return render_template('student_dashboard.html',
                           attendance_data=attendance_data,
                           enrolled_courses=enrolled_courses,
                           threshold=threshold)


@app.route('/my/course/<int:course_id>/history')
@login_required
def my_course_history(course_id):
    """A student's own class-by-class record: exactly which lectures they
    attended or missed, so disputes can be raised while memories are fresh."""
    course = Course.query.get_or_404(course_id)
    if course not in getattr(current_user, 'enrolled_courses', []):
        flash("You are not enrolled in that course.", "error")
        return redirect(url_for('student_dashboard'))

    semester = request.args.get('semester') or _course_semester(course)
    sessions = (_semester_sessions_query(course, semester)
                .order_by(ClassSession.date_created.desc())
                .all())

    my_records = {rec.session_id: rec for rec in Attendance.query.filter(
        Attendance.student_id == current_user.id,
        Attendance.course_id == course.id
    ).all()}

    history = [{'session': sess, 'record': my_records.get(sess.id)} for sess in sessions]
    attended = sum(1 for h in history if h['record'])
    pct = round(attended / len(history) * 100) if history else None

    pref = NotificationPreference.query.filter_by(user_id=current_user.id).first()
    threshold = pref.warning_threshold if pref and pref.warning_threshold else DEFAULT_ATTENDANCE_THRESHOLD

    return render_template('student_course_history.html',
                           course=course,
                           history=history,
                           attended=attended,
                           pct=pct,
                           threshold=threshold,
                           semester=semester,
                           semester_choices=_course_semester_choices(course))


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

    courses = Course.query.filter_by(department=current_user.department).all()
    return render_template('hod_dashboard.html', courses=courses, dept=current_user.department)


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

    courses = Course.query.filter_by(faculty=current_user.faculty).all()
    lecturers = User.query.filter_by(role='lecturer', faculty=current_user.faculty).all()
    return render_template('dean_dashboard.html',
                           faculty=current_user.faculty,
                           courses=courses,
                           lecturers=lecturers)


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
    all_courses = Course.query.all()
    return render_template('dap_dashboard.html',
                           total_students=total_students,
                           total_courses=total_courses,
                           courses=all_courses)


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
# COURSE MANAGEMENT
# ============================================================

@app.route('/add_course', methods=['POST'])
@login_required
def add_course():
    code = request.form.get('code')
    title = request.form.get('title')

    if not code or not title:
        flash("Course code and title are required!", "error")
        return redirect(url_for('dashboard'))

    new_course = Course(
        code=code,
        title=title,
        coordinator_id=current_user.id,
        department=getattr(current_user, 'department', None),
        faculty=getattr(current_user, 'faculty', None),
        current_semester=DEFAULT_SEMESTER,
    )
    db.session.add(new_course)
    db.session.commit()
    flash(f"Course {code} created successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/api/course/<int:course_id>/enrolled_students')
@login_required
@limiter.exempt 
def get_enrolled_students(course_id):
    course = Course.query.get_or_404(course_id)
    
    if course.coordinator_id != current_user.id and current_user not in getattr(course, 'instructors', []):
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
    if current_user.role.lower() != 'course coordinator':
        flash("Unauthorised", "error")
        return redirect(url_for('dashboard'))

    course_id = request.form.get('course_id')
    lecturer_email = request.form.get('lecturer_email')

    course = Course.query.get(course_id)
    lecturer = User.query.filter_by(email=lecturer_email).first()

    if course and lecturer:
        if hasattr(course, 'instructors'):
            if lecturer not in course.instructors:
                course.instructors.append(lecturer)
                db.session.commit()
                flash(f"Added {lecturer.full_name} to {course.code}.", "success")
            else:
                flash("User is already an instructor.", "info")
        else:
            flash("Course instructors relationship not configured.", "error")
    else:
        flash("Course or lecturer not found.", "error")

    return redirect(url_for('dashboard'))


@app.route('/register_course', methods=['POST'])
@login_required
def register_course():
    course_code = request.form.get('course_code')
    course = Course.query.filter_by(code=course_code).first()

    if not course:
        flash("Course not found!", "error")
        return redirect(url_for('student_dashboard'))

    if hasattr(current_user, 'enrolled_courses'):
        if course in current_user.enrolled_courses:
            flash(f"You are already registered for {course.code}.", "info")
        else:
            current_user.enrolled_courses.append(course)
            db.session.commit()
            flash(f"✅ Successfully registered for {course.code}.", "success")
    else:
        flash("Enrollment system not configured.", "error")

    return redirect(url_for('student_dashboard'))


# ============================================================
# QR CODE ROUTES  (FIX #3, #5, #6)
# ============================================================

def _is_course_authorized(course):
    """Return True if the current user may manage this course."""
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = hasattr(course, 'instructors') and (current_user in course.instructors)
    return is_coordinator or is_instructor


def _course_semester(course):
    """The semester a course is currently teaching."""
    return course.current_semester or DEFAULT_SEMESTER


def _get_or_create_todays_session(course, force_new=False):
    """
    Return today's ClassSession for a course, creating it if the lecturer
    hasn't started one yet. Re-opening the QR page on the same day resumes
    the SAME session, so a refresh never fragments one class meeting into
    several record sets — while next week's class gets a brand-new session.
    Pass force_new=True for a deliberate second class on the same day.
    """
    day_start, day_end = _local_day_bounds_utc()
    session_row = None
    if not force_new:
        # Only resume a session that belongs to the CURRENT semester — after
        # a rollover, an earlier same-day session stays with the old one.
        session_row = (ClassSession.query
                       .filter(ClassSession.course_id == course.id,
                               ClassSession.date_created >= day_start,
                               ClassSession.date_created < day_end,
                               db.or_(ClassSession.semester == _course_semester(course),
                                      ClassSession.semester.is_(None)))
                       .order_by(ClassSession.date_created.desc())
                       .first())
    if not session_row:
        local_day = datetime.now(LOCAL_TZ).strftime('%b %d, %Y')
        title = f"Lecture on {local_day}"
        if force_new:
            nth = (ClassSession.query
                   .filter(ClassSession.course_id == course.id,
                           ClassSession.date_created >= day_start,
                           ClassSession.date_created < day_end)
                   .count()) + 1
            title = f"Lecture on {local_day} (#{nth})"
        session_row = ClassSession(
            course_id=course.id,
            title=title,
            semester=_course_semester(course),
        )
        db.session.add(session_row)
        db.session.commit()
    return session_row


def _semester_sessions_query(course, semester):
    """Sessions of one course within one semester (legacy NULLs count as the
    course's current semester so pre-feature data stays visible)."""
    q = ClassSession.query.filter(ClassSession.course_id == course.id)
    if semester == _course_semester(course):
        q = q.filter(db.or_(ClassSession.semester == semester,
                            ClassSession.semester.is_(None)))
    else:
        q = q.filter(ClassSession.semester == semester)
    return q


def _course_semester_choices(course):
    """Distinct semester labels that have sessions, current one first."""
    rows = (db.session.query(ClassSession.semester)
            .filter(ClassSession.course_id == course.id)
            .distinct().all())
    labels = {row[0] or _course_semester(course) for row in rows}
    labels.add(_course_semester(course))
    current = _course_semester(course)
    return [current] + sorted(l for l in labels if l != current)


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
    return render_template('generate_qr.html', course=course, session=session_row)


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

    try:
        import qrcode
        img = qrcode.make(qr_text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype='image/png')
    except ImportError:
        return "QR code library not installed", 500


@app.route('/api/session/<int:session_id>/attendees')
@login_required
@limiter.exempt
def get_session_attendees(session_id):
    """Live roll-call feed for the projector page: who has scanned THIS session."""
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)
    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403

    records = (Attendance.query
               .filter_by(session_id=session_id)
               .order_by(Attendance.timestamp.desc())
               .all())
    attendees = []
    for rec in records:
        student = rec.student
        attendees.append({
            "name": student.full_name if student else "Unknown",
            "matric_no": (student.matric_no if student else None) or "N/A",
            "level": (student.level if student else None) or "N/A",
            "time": to_local(rec.timestamp).strftime('%I:%M %p') if rec.timestamp else "",
        })

    enrolled_total = len(course.students) if hasattr(course, 'students') else 0
    return jsonify({
        "status": "success",
        "present": len(attendees),
        "enrolled": enrolled_total,
        "attendees": attendees,
    })


@app.route('/scan_page')
@login_required
def scan_page():
    return render_template('scan.html')


@app.route('/set_location/<int:course_id>', methods=['POST'])
@login_required
def set_location(course_id):
    data = request.get_json()
    # FIX #4: Persisted in Redis (not a local dict)
    set_class_location(course_id, data['lat'], data['lon'])
    print(f"📍 Location set for Course {course_id} at ({data['lat']}, {data['lon']})")
    return jsonify({"status": "ok"})


# ============================================================
# ATTENDANCE ROUTES
# ============================================================

# ============================================================
# CAMPOS ATTENDANCE REPORTING
# ============================================================
# After attendance is recorded locally, report it to CampOS Core so it appears
# on the student's CampOS dashboard. Keyed by the shared identity (matric/email).
# Best-effort and fully isolated — never affects attendance marking. Configure
# CAMPOS_API_URL and CAMPOS_API_KEY in the environment to enable it.

def report_attendance_to_campos(matric_no, email, course_code, course_title, external_id, scanned_at_iso):
    import requests
    base = os.environ.get('CAMPOS_API_URL')
    api_key = os.environ.get('CAMPOS_API_KEY')
    if not base or not api_key:
        return  # CampOS reporting not configured
    try:
        resp = requests.post(
            f"{base.rstrip('/')}/api/modules/attendance",
            json={
                'matricNumber': matric_no,
                'email': email,
                'courseCode': course_code,
                'courseTitle': course_title,
                'status': 'present',
                'externalId': str(external_id),
                'scannedAt': scanned_at_iso,
            },
            headers={'X-API-Key': api_key},
            timeout=8,
        )
        if resp.status_code >= 300:
            print(f"⚠️ CampOS attendance report failed ({resp.status_code}): {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️ CampOS attendance report error: {e}")


@app.route('/mark_attendance', methods=['POST'])
@limiter.limit("10 per minute", error_message="Too many scan attempts. Please wait.")
@login_required
def mark_attendance():
    data = request.get_json()
    qr_text = data.get('qr_data')
    student_lat = data.get('lat')
    student_lon = data.get('lon')

    try:
        if not qr_text:
            return jsonify({"status": "error", "message": "No QR data provided."})

        # FIX #3 & #5: Verify the signed token (3-part format: S<id>|ts|sig)
        try:
            session_id, timestamp = verify_signed_qr(qr_text)
        except ValueError as ve:
            return jsonify({"status": "error", "message": str(ve)})

        class_session = ClassSession.query.get(session_id)
        if not class_session:
            return jsonify({"status": "error", "message": "Invalid QR Code: Class session not found."})

        course = Course.query.get(class_session.course_id)
        course_id = class_session.course_id
        if not course:
            return jsonify({"status": "error", "message": "Invalid QR Code: Course not found."})

        # Enrolment check
        if hasattr(current_user, 'enrolled_courses'):
            if course not in current_user.enrolled_courses:
                return jsonify({
                    "status": "error",
                    "message": f"🚫 Access Denied: You are not registered for {course.code}."
                })

        # Duplicate check: one scan per student per CLASS SESSION.
        # Next week's lecture is a new session, so scanning again then is fine.
        existing = Attendance.query.filter_by(
            student_id=current_user.id,
            session_id=session_id
        ).first()

        if existing:
            return jsonify({
                "status": "error",
                "message": "You are already marked present for this class! Double-scanning is not allowed."
            })

        # Anti buddy-punching: one physical device marks ONE student per class.
        device_id = (data.get('device_id') or '').strip()
        if device_id and device_id != 'browser':
            same_device = Attendance.query.filter(
                Attendance.session_id == session_id,
                Attendance.device_id == device_id,
                Attendance.student_id != current_user.id
            ).first()
            if same_device:
                return jsonify({
                    "status": "error",
                    "message": "🚫 This device already marked attendance for another student in this class."
                })

        # FIX #4: Retrieve location from Redis
        location_verified = False
        class_loc = get_class_location(course_id)
        if class_loc:
            if not student_lat or not student_lon:
                return jsonify({"status": "error", "message": "Location required! Please allow GPS access."})

            dist = calculate_distance(
                class_loc['lat'], class_loc['lon'],
                float(student_lat), float(student_lon)
            )
            if dist > GEOFENCE_RADIUS_M:
                return jsonify({
                    "status": "error",
                    "message": f"Too far from classroom. You are {int(dist)}m away (max {GEOFENCE_RADIUS_M}m)."
                })
            location_verified = True
        # If the lecturer has no live location (e.g. desktop projector without
        # GPS) the scan is still accepted, but stored as location-UNVERIFIED so
        # it is visibly flagged on the records page instead of silently equal.

        new_record = Attendance(
            student_id=current_user.id,
            course_id=course_id,
            session_id=session_id,
            device_id=device_id or 'browser',
            location_verified=location_verified,
        )
        db.session.add(new_record)
        try:
            db.session.commit()
        except IntegrityError:
            # Two simultaneous scans raced past the duplicate check; the DB
            # unique constraint (student, session) is the final referee.
            db.session.rollback()
            return jsonify({
                "status": "error",
                "message": "You are already marked present for this class!"
            })

        # Report to CampOS Core (best-effort, async — never blocks the scan).
        try:
            scanned_iso = (new_record.timestamp.isoformat() + "Z") if new_record.timestamp else None
            email_executor.submit(
                report_attendance_to_campos,
                current_user.matric_no,
                current_user.email,
                course.code,
                course.title,
                new_record.id,
                scanned_iso,
            )
        except Exception as e:
            print(f"⚠️ Could not queue CampOS attendance report: {e}")

        # Send attendance confirmation email
        timestamp_str = datetime.now(LOCAL_TZ).strftime('%B %d, %Y at %I:%M %p')
        send_attendance_confirmation(
            user_email=current_user.email,
            user_name=current_user.full_name,
            course_code=course.code,
            course_title=course.title,
            timestamp=timestamp_str
        )

        # ── Real-time WhatsApp alert ──
        pref = NotificationPreference.query.filter_by(user_id=current_user.id).first()
        if pref and pref.whatsapp_alerts and pref.phone_number:
            send_attendance_whatsapp(
                phone=pref.phone_number,
                student_name=current_user.full_name,
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
                    student_name=current_user.full_name,
                    course_code=course.code,
                    course_title=course.title,
                    timestamp_str=timestamp_str
                )
            # Email to parent
            if pref.parent_email:
                send_parent_attendance_email(
                    app_instance=app,
                    mail_func=send_email,
                    pref=pref,
                    student_name=current_user.full_name,
                    course_code=course.code,
                    course_title=course.title,
                    timestamp_str=timestamp_str
                )

        # ── Early-warning check (alerts student + parent if below threshold) ──
        process_early_warning(
            student=current_user,
            course=course,
            app_instance=app,
            mail_func=send_email,
            Attendance_model=Attendance,
            ClassSession_model=ClassSession,
            db_session=db.session
        )

        return jsonify({"status": "success", "message": "Attendance marked successfully! ✅"})

    except Exception as e:
        print(f"❌ Server error in mark_attendance: {e}")
        return jsonify({"status": "error", "message": "An unexpected server error occurred."})


def _attendance_authorized(course):
    """
    FIX #8: Extended to allow HOD, Dean, and DAP to view attendance
    in addition to coordinators and instructors.
    """
    role = (current_user.role or '').lower()
    if course.coordinator_id == current_user.id:
        return True
    if hasattr(course, 'instructors') and current_user in course.instructors:
        return True
    if role == 'hod' and course.department == getattr(current_user, 'department', None):
        return True
    if role == 'dean' and course.faculty == getattr(current_user, 'faculty', None):
        return True
    if role == 'dap':
        return True
    return False


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

    semester = request.args.get('semester') or _course_semester(course)
    sessions = (_semester_sessions_query(course, semester)
                .order_by(ClassSession.date_created.desc())
                .all())

    enrolled_total = len(course.students) if hasattr(course, 'students') else 0

    sessions_data = []
    for sess in sessions:
        records = sorted(sess.attendances,
                         key=lambda r: r.timestamp or datetime.min)
        # Devices used by more than one student in this class = buddy-punching
        # suspects (older scans predate blocking, and IDs can be spoofed).
        device_counts = {}
        for r in records:
            if r.device_id and r.device_id not in ('browser', 'manual'):
                device_counts[r.device_id] = device_counts.get(r.device_id, 0) + 1
        shared_devices = {d for d, n in device_counts.items() if n > 1}

        present = len(records)
        pct = round(present / enrolled_total * 100) if enrolled_total else None
        sessions_data.append({
            'session': sess,
            'records': records,
            'present': present,
            'pct': pct,
            'shared_devices': shared_devices,
        })

    total_scans = sum(s['present'] for s in sessions_data)
    avg_present = round(total_scans / len(sessions_data)) if sessions_data else 0

    # Rows that never got adopted by the startup backfill (shouldn't happen)
    unassigned = Attendance.query.filter_by(course_id=course_id) \
                                 .filter(Attendance.session_id.is_(None)).count()

    return render_template('view_attendance.html',
                           course=course,
                           sessions_data=sessions_data,
                           enrolled_total=enrolled_total,
                           avg_present=avg_present,
                           unassigned=unassigned,
                           semester=semester,
                           semester_choices=_course_semester_choices(course),
                           roster=sorted(course.students,
                                         key=lambda s: (s.matric_no or '', s.full_name or ''))
                                  if hasattr(course, 'students') else [],
                           is_coordinator=(course.coordinator_id == current_user.id),
                           can_manage=_is_course_authorized(course))


def _csv_cell(value):
    """Quote a value for CSV, escaping embedded double quotes."""
    return '"' + str(value if value is not None else "N/A").replace('"', '""') + '"'


@app.route('/course/<int:course_id>/download_csv')
@login_required
def download_csv(course_id):
    """
    Without ?session_id: the SEMESTER REGISTER — one row per student, one
    column per class session held, plus attended/total/% columns.
    With ?session_id=<id>: the sheet for that single class meeting.
    """
    course = Course.query.get_or_404(course_id)

    if not _attendance_authorized(course):  # same policy as the records page
        return "Unauthorised", 403

    safe_code = (course.code or "course").replace(' ', '_')
    session_id = request.args.get('session_id', type=int)

    def _rec_meta(rec):
        time_str = to_local(rec.timestamp).strftime('%Y-%m-%d %I:%M %p') if rec.timestamp else "N/A"
        gps = "Yes" if rec.location_verified else "No"
        device = rec.device_id or "N/A"
        if rec.marked_by:
            device = f"manual (by {rec.marked_by})"
        return time_str, gps, device

    # ── Single-session sheet ──
    if session_id:
        sess = ClassSession.query.filter_by(id=session_id, course_id=course_id).first_or_404()
        records = {rec.student_id: rec for rec in sess.attendances}
        enrolled = list(course.students) if hasattr(course, 'students') else []

        csv_data = "Matric Number,Full Name,Level,Status,Time Scanned,GPS Verified,Device ID\n"
        listed_ids = set()
        for student in sorted(enrolled, key=lambda s: (s.matric_no or '', s.full_name or '')):
            listed_ids.add(student.id)
            rec = records.get(student.id)
            if rec:
                time_str, gps, device = _rec_meta(rec)
                row = [student.matric_no, student.full_name, student.level, "Present", time_str, gps, device]
            else:
                row = [student.matric_no, student.full_name, student.level, "Absent", "-", "-", "-"]
            csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

        # Scans from students no longer enrolled (kept for the record)
        for rec in sess.attendances:
            if rec.student_id in listed_ids:
                continue
            student = rec.student
            time_str, gps, device = _rec_meta(rec)
            row = [student.matric_no if student else "UNKNOWN",
                   (student.full_name if student else "Deleted User") + " (not enrolled)",
                   student.level if student else "N/A",
                   "Present", time_str, gps, device]
            csv_data += ",".join(_csv_cell(v) for v in row) + "\n"

        date_tag = to_local(sess.date_created).strftime('%Y-%m-%d') if sess.date_created else "session"
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename={safe_code}_{date_tag}_attendance.csv"}
        )

    # ── Full semester register ──
    semester = request.args.get('semester') or _course_semester(course)
    sessions = (_semester_sessions_query(course, semester)
                .order_by(ClassSession.date_created.asc())
                .all())

    # student_id -> set of session_ids attended
    attended_map = {}
    students_by_id = {}
    for sess in sessions:
        for rec in sess.attendances:
            attended_map.setdefault(rec.student_id, set()).add(sess.id)
            if rec.student:
                students_by_id[rec.student_id] = rec.student

    enrolled = list(course.students) if hasattr(course, 'students') else []
    enrolled_ids = {s.id for s in enrolled}
    for s in enrolled:
        students_by_id[s.id] = s

    session_labels = []
    for sess in sessions:
        date_str = to_local(sess.date_created).strftime('%Y-%m-%d') if sess.date_created else "?"
        session_labels.append(f"{sess.title} ({date_str})")

    header = ["Matric Number", "Full Name", "Level"] + session_labels + \
             ["Classes Attended", "Classes Held", "Attendance %"]
    csv_data = ",".join(_csv_cell(h) for h in header) + "\n"

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

    semester_tag = semester.replace('/', '-').replace(' ', '_')
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename={safe_code}_{semester_tag}_attendance_register.csv"}
    )

    # ============================================================
# ANALYTICS
# ============================================================

@app.route('/course/<int:course_id>/analytics')
@login_required
def course_analytics(course_id):
    course = Course.query.get_or_404(course_id)

    if not _attendance_authorized(course):  # same policy as the records page
        return "Unauthorised", 403

    semester = request.args.get('semester') or _course_semester(course)
    sessions = (_semester_sessions_query(course, semester)
                .order_by(ClassSession.date_created.asc())
                .all())
    session_ids = {s.id for s in sessions}
    total_sessions = len(sessions)

    # One data point PER CLASS SESSION (a session nobody scanned still shows
    # as 0, which a plain group-by-date of scans could never reveal).
    counts_by_session = {}
    for sess in sessions:
        counts_by_session[sess.id] = len(sess.attendances)

    dates = [to_local(sess.date_created).strftime('%b %d') if sess.date_created else '?'
             for sess in sessions]
    counts = [counts_by_session[s.id] for s in sessions]

    # Per-student standing: who is at risk of missing exam eligibility?
    attended_by_student = {}
    for sess in sessions:
        for rec in sess.attendances:
            attended_by_student[rec.student_id] = attended_by_student.get(rec.student_id, 0) + 1

    standing = []
    for student in getattr(course, 'students', []):
        attended = attended_by_student.get(student.id, 0)
        pct = round(attended / total_sessions * 100) if total_sessions else 0
        standing.append({
            'name': student.full_name,
            'matric_no': student.matric_no or 'N/A',
            'level': student.level or 'N/A',
            'attended': attended,
            'total': total_sessions,
            'pct': pct,
            'at_risk': total_sessions > 0 and pct < DEFAULT_ATTENDANCE_THRESHOLD,
        })
    standing.sort(key=lambda s: (s['pct'], s['name']))
    at_risk_count = sum(1 for s in standing if s['at_risk'])

    return render_template('analytics.html',
                           course=course,
                           dates=dates,
                           counts=counts,
                           standing=standing,
                           at_risk_count=at_risk_count,
                           threshold=DEFAULT_ATTENDANCE_THRESHOLD,
                           semester=semester,
                           semester_choices=_course_semester_choices(course))


@app.route('/course/<int:course_id>/start_session', methods=['POST'])
@login_required
def start_session(course_id):
    course = Course.query.get_or_404(course_id)

    # Security check: Ensure they are the lecturer
    if not getattr(course, 'coordinator_id') == current_user.id and current_user not in getattr(course, 'instructors', []):
        return "Unauthorised", 403

    # Open today's class meeting (or resume it if already started today),
    # then head to the live QR projector page for that session.
    # extra=1 deliberately opens a SECOND session today (double lectures).
    force_new = request.form.get('extra') == '1'
    session_row = _get_or_create_todays_session(course, force_new=force_new)
    return redirect(url_for('session_qr', session_id=session_row.id))


@app.route('/session/<int:session_id>/rename', methods=['POST'])
@login_required
def rename_session(session_id):
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)
    if not _is_course_authorized(course):
        flash("Unauthorised.", "error")
        return redirect(url_for('dashboard'))

    title = (request.form.get('title') or '').strip()
    if title:
        session_row.title = title[:100]
        db.session.commit()
        flash("Session renamed.", "success")
    return redirect(url_for('view_attendance', course_id=course.id))


@app.route('/session/<int:session_id>/manual_mark', methods=['POST'])
@login_required
def manual_mark(session_id):
    """Lecturer marks a student present by matric number — for dead phone
    batteries and students without smartphones. Tagged with who added it."""
    session_row = ClassSession.query.get_or_404(session_id)
    course = Course.query.get_or_404(session_row.course_id)
    if not _is_course_authorized(course):
        flash("Unauthorised.", "error")
        return redirect(url_for('dashboard'))

    matric_no = (request.form.get('matric_no') or '').strip()
    student = User.query.filter_by(matric_no=matric_no).first() if matric_no else None
    if not student:
        flash(f'No student found with matric number "{matric_no}".', 'error')
        return redirect(url_for('view_attendance', course_id=course.id))

    if course not in getattr(student, 'enrolled_courses', []):
        flash(f'{student.full_name} is not enrolled in {course.code}.', 'error')
        return redirect(url_for('view_attendance', course_id=course.id))

    if Attendance.query.filter_by(student_id=student.id, session_id=session_id).first():
        flash(f'{student.full_name} is already marked for this class.', 'info')
        return redirect(url_for('view_attendance', course_id=course.id))

    db.session.add(Attendance(
        student_id=student.id,
        course_id=course.id,
        session_id=session_id,
        device_id='manual',
        marked_by=current_user.full_name,
        location_verified=False,
    ))
    db.session.commit()
    flash(f'{student.full_name} marked present (manual entry).', 'success')
    return redirect(url_for('view_attendance', course_id=course.id))


@app.route('/attendance/<int:record_id>/remove', methods=['POST'])
@login_required
def remove_attendance(record_id):
    """Remove an erroneous record (wrong person marked, admitted proxy scan)."""
    record = Attendance.query.get_or_404(record_id)
    course = Course.query.get_or_404(record.course_id)
    if not _is_course_authorized(course):
        flash("Unauthorised.", "error")
        return redirect(url_for('dashboard'))

    db.session.delete(record)
    db.session.commit()
    flash("Attendance record removed.", "success")
    return redirect(url_for('view_attendance', course_id=course.id))


@app.route('/course/<int:course_id>/new_semester', methods=['POST'])
@login_required
def start_new_semester(course_id):
    """Coordinator rolls the course into a new semester. Old sessions keep
    their label and stay viewable; new sessions and stats start clean.
    Optionally clears the roster so the new cohort re-registers."""
    course = Course.query.get_or_404(course_id)
    if course.coordinator_id != current_user.id:
        flash("Only the course coordinator can start a new semester.", "error")
        return redirect(url_for('dashboard'))

    name = (request.form.get('semester_name') or '').strip()
    if not name:
        flash("Please give the new semester a name (e.g. 2026/2027 First Semester).", "error")
        return redirect(url_for('view_attendance', course_id=course.id))
    if name == _course_semester(course):
        flash(f'"{name}" is already the current semester.', 'info')
        return redirect(url_for('view_attendance', course_id=course.id))

    # Stamp any legacy unlabelled sessions with the OLD semester before switching
    ClassSession.query.filter_by(course_id=course.id, semester=None) \
                      .update({'semester': _course_semester(course)})
    course.current_semester = name

    if request.form.get('clear_roster'):
        course.students.clear()

    db.session.commit()
    flash(f'Started "{name}" for {course.code}. Previous records remain '
          'available under their own semester.', 'success')
    return redirect(url_for('view_attendance', course_id=course.id))


@app.route('/course/<int:course_id>/remove_student/<int:student_id>', methods=['POST'])
@login_required
def remove_student(course_id, student_id):
    """Un-enroll a student (left the course) so they stop diluting stats."""
    course = Course.query.get_or_404(course_id)
    if not _is_course_authorized(course):
        flash("Unauthorised.", "error")
        return redirect(url_for('dashboard'))

    student = User.query.get_or_404(student_id)
    if student in course.students:
        course.students.remove(student)
        db.session.commit()
        flash(f'{student.full_name} removed from {course.code}. Their past '
              'attendance records are kept.', 'success')
    return redirect(url_for('view_attendance', course_id=course.id))


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
        today = datetime.utcnow().date()
        week_end = today
        week_start = today - timedelta(days=7)
        week_range = f"{week_start.strftime('%d %b')} — {week_end.strftime('%d %b %Y')}"

        print(f"\n📊 Running weekly reports for {week_range}...")

        # ── Student Reports ──
        students_with_pref = (
            db.session.query(User, NotificationPreference)
            .join(NotificationPreference, NotificationPreference.user_id == User.id)
            .filter(User.role == 'student')
            .filter(NotificationPreference.weekly_report == True)
            .all()
        )

        for student, pref in students_with_pref:
            # Check if already sent this week
            existing = WeeklyReport.query.filter_by(
                user_id=student.id,
                week_start=week_start,
                report_type='student'
            ).first()
            if existing:
                continue

            # Build course data
            courses_data = []
            for course in getattr(student, 'enrolled_courses', []):
                session_ids = [s.id for s in
                               _semester_sessions_query(course, _course_semester(course))
                               .with_entities(ClassSession.id).all()]
                total_sessions = len(session_ids)
                attended = Attendance.query.filter(
                    Attendance.student_id == student.id,
                    Attendance.session_id.in_(session_ids)
                ).count() if session_ids else 0
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
        lecturers = User.query.filter(
            User.role.in_(['lecturer', 'Lecturer', 'Course Coordinator', 'course coordinator'])
        ).all()

        for lecturer in lecturers:
            lec_pref = NotificationPreference.query.filter_by(user_id=lecturer.id).first()
            if lec_pref and not lec_pref.weekly_report:
                continue

            existing = WeeklyReport.query.filter_by(
                user_id=lecturer.id,
                week_start=week_start,
                report_type='lecturer'
            ).first()
            if existing:
                continue

            # Get courses this lecturer manages
            coordinated = Course.query.filter_by(coordinator_id=lecturer.id).all()
            teaching = getattr(lecturer, 'teaching_courses', [])
            all_courses = list(set(list(coordinated) + list(teaching)))

            if not all_courses:
                continue

            courses_data = []
            for course in all_courses:
                total_enrolled = len(course.students) if hasattr(course, 'students') else 0
                sessions_week = ClassSession.query.filter(
                    ClassSession.course_id == course.id,
                    ClassSession.date_created >= datetime.combine(week_start, datetime.min.time()),
                    ClassSession.date_created <= datetime.combine(week_end, datetime.max.time())
                ).count()
                session_ids = [s.id for s in
                               _semester_sessions_query(course, _course_semester(course))
                               .with_entities(ClassSession.id).all()]
                total_sessions = len(session_ids)

                # Average attendance (current semester only)
                if total_sessions > 0 and total_enrolled > 0:
                    total_att = Attendance.query.filter(
                        Attendance.session_id.in_(session_ids)
                    ).count()
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
    
    # 🚨 STOPS THE LOOP BY RENDERING HTML DIRECTLY
    return f"<h2>Too Many Requests!</h2><p>Please wait a minute and <a href='{url_for('dashboard')}'>try again</a>.</p>", 429

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
        ("attendance", "location_verified", "BOOLEAN DEFAULT FALSE"),
        ("attendance", "marked_by", "VARCHAR(100)"),
        # Email verification (accounts existing before the feature stay valid)
        ("user", "email_verified", "BOOLEAN DEFAULT FALSE"),
        # Semester scoping
        ("course", "current_semester", "VARCHAR(50)"),
        ("class_session", "semester", "VARCHAR(50)"),
    ]
    with db.engine.connect() as conn:
        for table, column, col_type in _migrations:
            try:
                conn.execute(db.text(
                    f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
                ))
                conn.commit()
                print(f"[MIGRATION] Added {table}.{column}")
                if (table, column) == ("user", "email_verified"):
                    # Grandfather every account that predates verification —
                    # runs exactly once, when the column is first created.
                    conn.execute(db.text('UPDATE "user" SET email_verified = TRUE'))
                    conn.commit()
                    print("[MIGRATION] Marked pre-existing accounts as verified")
            except Exception:
                conn.rollback()  # Column already exists — skip

        # Label anything unlabelled with the default semester
        try:
            conn.execute(db.text(
                "UPDATE course SET current_semester = :sem WHERE current_semester IS NULL"
            ), {"sem": DEFAULT_SEMESTER})
            conn.commit()
        except Exception:
            conn.rollback()

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
                day = (rec.timestamp or datetime.utcnow()).date()
                by_course_day.setdefault((rec.course_id, day), []).append(rec)

            for (course_id, day), recs in sorted(by_course_day.items(),
                                                 key=lambda item: (item[0][0], item[0][1])):
                session_row = ClassSession.query.filter(
                    ClassSession.course_id == course_id,
                    func.date(ClassSession.date_created) == day
                ).first()
                if not session_row:
                    first_ts = min((r.timestamp for r in recs if r.timestamp),
                                   default=datetime.utcnow())
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

    # ── Enforce one record per (student, session) at the DB level ──
    # First remove duplicates left over from the pre-session era, then add a
    # unique index so concurrent double-scans can never slip through again.
    try:
        dupes = (db.session.query(Attendance.student_id, Attendance.session_id,
                                  func.count(Attendance.id))
                 .filter(Attendance.session_id.isnot(None))
                 .group_by(Attendance.student_id, Attendance.session_id)
                 .having(func.count(Attendance.id) > 1)
                 .all())
        removed = 0
        for student_id, sess_id, _n in dupes:
            rows = (Attendance.query
                    .filter_by(student_id=student_id, session_id=sess_id)
                    .order_by(Attendance.timestamp.asc())
                    .all())
            for extra in rows[1:]:  # keep the earliest scan
                db.session.delete(extra)
                removed += 1
        if removed:
            db.session.commit()
            print(f"[MIGRATION] Removed {removed} duplicate attendance rows")
        with db.engine.connect() as conn:
            conn.execute(db.text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_attendance_student_session "
                "ON attendance (student_id, session_id)"
            ))
            conn.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[MIGRATION] Unique-index step skipped: {e}")

    db.engine.dispose()  # Forces Gunicorn workers to create fresh connections
    print("[OK] Database initialized successfully!")

# APScheduler: Weekly reports every Monday at 7 AM
try:
    from apscheduler.schedulers.background import BackgroundScheduler
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
    print("📅 Weekly Report Scheduler Active (Every Monday @ 7:00 AM)")
except ImportError:
    print("⚠️  APScheduler not installed. Weekly reports won't run automatically.")
    print("   Install with: pip install APScheduler")

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎓 FUNAAB ATTENDANCE SYSTEM STARTING")
    print("="*60)
    print(f"📧 Mail Server: {app.config['MAIL_SERVER']}")
    print(f"📧 Mail Username: {app.config['MAIL_USERNAME']}")
    print(f"🔐 CSRF Protection: Enabled")
    print(f"🛡️  Rate Limiting: Enabled")
    print(f"📱 WhatsApp Alerts: {'Enabled' if os.environ.get('TWILIO_ACCOUNT_SID') else 'Disabled'}")
    print(f"📊 Weekly PDF Reports: Scheduled (Monday 7 AM)")
    print(f"⚠️  Early-Warning Threshold: {DEFAULT_ATTENDANCE_THRESHOLD}%")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
