import os
import io
import hmac
import hashlib
import secrets
import time
import math
import re
from threading import Thread
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()
from authlib.integrations.flask_client import OAuth
from flask import (Flask, render_template, redirect, url_for,
                   flash, request, send_file, jsonify, Response)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
import redis
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import send_from_directory
from flask_wtf.csrf import CSRFProtect

from models import db, User, Course, Attendance


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

# FIX #2: Enable CSRF protection globally
csrf = CSRFProtect(app)


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
    get_remote_address,
    app=app,
    storage_uri=limiter_storage,
    default_limits=["200 per day", "50 per hour"]
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

def send_async_email(app_instance, msg):
    """Send email asynchronously to avoid blocking"""
    with app_instance.app_context():
        try:
            mail.send(msg)
            print(f"✅ Email sent successfully to {msg.recipients}")
        except Exception as e:
            print(f"❌ Failed to send email: {str(e)}")


def send_email(subject, recipients, text_body, html_body, sender=None):
    """
    Send email with both text and HTML versions
    
    Args:
        subject: Email subject
        recipients: List of recipient email addresses
        text_body: Plain text version
        html_body: HTML version
        sender: Optional sender email (uses default if not provided)
    """
    msg = Message(
        subject=subject,
        recipients=recipients if isinstance(recipients, list) else [recipients],
        sender=sender or app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = text_body
    msg.html = html_body
    
    # Send asynchronously
    Thread(target=send_async_email, args=(app, msg), daemon=True).start()


def send_welcome_email(user_email, user_name, user_role='student'):
    """Send welcome email to new FUNAAB user"""
    subject = "Welcome to FUNAAB Attendance System!"
    
    # Format role for display
    role_display_map = {
        'student': 'Student',
        'lecturer': 'Lecturer',
        'Lecturer': 'Lecturer',
        'Course Coordinator': 'Course Coordinator',
        'course coordinator': 'Course Coordinator',
        'hod': 'Head of Department',
        'dean': 'Dean',
        'dap': 'Dean of Academic Planning'
    }
    
    role_display = role_display_map.get(user_role, user_role.title() if user_role else 'Student')
    
    # Plain text version
    text_body = f"""
Hello {user_name},

Welcome to the FUNAAB Attendance Management System!

Your account has been successfully created with your FUNAAB email: {user_email}
Role: {role_display}

You can now:
- Mark attendance by scanning QR codes in class
- View your attendance history and records
- Track your course participation
- Receive real-time attendance confirmations

If you have any questions or need support, please contact the IT department.

Best regards,
FUNAAB Attendance System Team
Federal University of Agriculture, Abeokuta
    """
    # HTML version
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
            background: linear-gradient(135deg, #006838 0%, #198754 100%);
            color: white;
            padding: 30px;
            text-align: center;
            border-radius: 10px 10px 0 0;
        }}
        .logo {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .content {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 0 0 10px 10px;
        }}
        .welcome-box {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .info-box {{
            background: #e7f5e9;
            border-left: 4px solid #198754;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        .feature-list {{
            list-style: none;
            padding: 0;
        }}
        .feature-list li {{
            padding: 12px 0;
            border-bottom: 1px solid #e9ecef;
        }}
        .feature-list li:before {{
            content: "✓ ";
            color: #198754;
            font-weight: bold;
            margin-right: 10px;
            font-size: 18px;
        }}
        .button {{
            display: inline-block;
            padding: 14px 35px;
            background: #198754;
            color: white !important;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 12px;
            border-top: 1px solid #dee2e6;
            margin-top: 20px;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            background: #ffc107;
            color: #000;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🎓</div>
        <h1>Welcome to FUNAAB!</h1>
        <p style="margin: 0;">Attendance Management System</p>
    </div>
    
    <div class="content">
        <div class="welcome-box">
            <h2>Hello {user_name}! 👋</h2>
            <p>Your account has been successfully created. We're excited to have you in the FUNAAB digital ecosystem!</p>
            
            <div class="info-box">
                <strong>📧 Your FUNAAB Email:</strong> {user_email}<br>
                <strong>👤 Role:</strong> <span class="badge">{role_display}</span>
            </div>
            
            <h3>What you can do now:</h3>
            <ul class="feature-list">
                <li>Mark attendance by scanning QR codes during lectures</li>
                <li>View your complete attendance history across all courses</li>
                <li>Track your participation and attendance percentage</li>
                <li>Receive instant email confirmations for each attendance</li>
                <li>Access attendance records anytime, anywhere</li>
            </ul>
            
            <center>
                <a href="{url_for('login', _external=True)}" class="button">Login to Your Account →</a>
            </center>
        </div>
        
        <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0;">
            <strong>⚠️ Important Security Note:</strong><br>
            Keep your login credentials secure. Never share your password with anyone.
            If you didn't create this account, please contact IT support immediately.
        </div>
        
        <p style="text-align: center;">
            <strong>Need Help?</strong><br>
            Contact FUNAAB IT Support or your course coordinator for assistance.
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanmark_v2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
    'staff.funaab.edu.ng'
]


def is_valid_funaab_email(email):
    """
    Check if email is a valid FUNAAB email address
    
    Args:
        email: Email address to validate
    
    Returns:
        tuple: (is_valid, message, role)
    """
    if not email:
        return False, "Email is required", None
    
    # Basic email format validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format", None
    
    email = email.lower().strip()
    
    # Check if email ends with any valid FUNAAB domain
    is_valid = False
    role = None
    
    if email.endswith('@student.funaab.edu.ng'):
        is_valid = True
        role = 'student'
    elif email.endswith('@staff.funaab.edu.ng'):
        is_valid = True
        role = 'lecturer'  # Default for staff, can be overridden to Course Coordinator
    elif email.endswith('@funaab.edu.ng'):
        is_valid = True
        role = 'student'  # Default role
    
    if is_valid:
        return True, "Valid FUNAAB email", role
    else:
        return False, "Only FUNAAB email addresses (@funaab.edu.ng, @student.funaab.edu.ng, @staff.funaab.edu.ng) are allowed", None


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


def generate_signed_qr(course_id: int) -> str:
    """
    Generate a signed QR payload and cache it in Redis so that
    /api/qr_data and the live image endpoint always return the SAME token.
    Format: "course_id|timestamp|hmac_sig"
    """
    cache_key = f"qr_token:{course_id}"

    if redis_client:
        cached = redis_client.get(cache_key)
        if cached:
            return cached.decode()

    # Create a new token
    timestamp = int(time.time())
    message = f"{course_id}|{timestamp}"
    sig = _make_signature(message)
    token = f"{message}|{sig}"

    if redis_client:
        redis_client.setex(cache_key, QR_TOKEN_TTL, token)

    return token


def verify_signed_qr(qr_text: str):
    """
    Verify the QR payload signature and expiry.
    Returns (course_id, timestamp) on success, or raises ValueError.
    """
    parts = qr_text.split('|')
    if len(parts) != 3:
        raise ValueError("Invalid QR code format.")

    course_id_str, timestamp_str, received_sig = parts
    message = f"{course_id_str}|{timestamp_str}"
    expected_sig = _make_signature(message)

    if not hmac.compare_digest(received_sig, expected_sig):
        raise ValueError("QR code signature is invalid.")

    timestamp = int(timestamp_str)
    if int(time.time()) - timestamp > QR_CODE_WINDOW:
        raise ValueError("QR code has expired. Please scan again.")

    return int(course_id_str), timestamp


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

@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')


# ============================================================
# USER LOADER  (FIX #12: use db.session.get instead of Query.get)
# ============================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))   # FIX #12


# ============================================================
# HELPER: role-based redirect
# ============================================================

def redirect_by_role(role: str):
    role = (role or '').lower()
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
        flash(f"Role '{role}' not recognised. Defaulting to student view.", "warning")
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
            Thread(target=send_async_email, args=(app, msg), daemon=True).start()

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
# DEBUG ENDPOINT (Remove in production)
# ============================================================

@app.route('/test_signup', methods=['GET', 'POST'])
@csrf.exempt
def test_signup():
    """Simple signup test page"""
    if request.method == 'POST':
        print("\n" + "="*60)
        print("TEST SIGNUP - Form Submitted")
        print("="*60)
        print(f"Form Data: {dict(request.form)}")
        print(f"Method: {request.method}")
        print(f"Content-Type: {request.content_type}")
        
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        
        print(f"\nExtracted Values:")
        print(f"  Name: '{name}'")
        print(f"  Email: '{email}'")
        print(f"  Password: {'*' * len(password) if password else 'EMPTY'}")
        print("="*60 + "\n")
        
        return f"""
        <h2>Form Received Successfully!</h2>
        <ul>
            <li>Name: {name}</li>
            <li>Email: {email}</li>
            <li>Password: {'*' * len(password)}</li>
        </ul>
        <a href="/test_signup">Back to form</a>
        """
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Signup</title>
        <style>
            body { font-family: Arial; max-width: 500px; margin: 50px auto; padding: 20px; }
            input { width: 100%; padding: 10px; margin: 10px 0; }
            button { width: 100%; padding: 12px; background: #28a745; color: white; border: none; cursor: pointer; }
            button:hover { background: #218838; }
        </style>
    </head>
    <body>
        <h2>Test Signup Form</h2>
        <form method="POST" onsubmit="console.log('Form submitting...'); return true;">
            <label>Name:</label>
            <input type="text" name="name" value="Test User" required>
            
            <label>Email:</label>
            <input type="email" name="email" value="test@student.funaab.edu.ng" required>
            
            <label>Password:</label>
            <input type="password" name="password" value="test123456" required>
            
            <button type="submit">Test Submit</button>
        </form>
        <hr>
        <p><a href="/signup">Go to Real Signup Page</a></p>
    </body>
    </html>
    '''


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
            role=auto_role or 'student'
        )
        db.session.add(user)
        db.session.commit()
        
        # Send welcome email
        send_welcome_email(email, full_name, auto_role or 'student')
        
        flash('Account created via Google! Check your email for confirmation.', 'success')

    login_user(user)
    return redirect_by_role(user.role)


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
            login_user(user)
            return redirect_by_role(user.role)
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
@csrf.exempt  # Temporarily exempt for debugging
def signup():
    print(f"\n{'='*60}")
    print(f"SIGNUP REQUEST - Method: {request.method}")
    print(f"{'='*60}")
    
    if request.method == 'POST':
        # Get all form data
        print("\n📋 FORM DATA RECEIVED:")
        print(f"Raw form keys: {list(request.form.keys())}")
        print(f"Raw form: {dict(request.form)}")
        
        # Get main fields
        name = (request.form.get('full_name') or 
                request.form.get('name') or '').strip()
        
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        
        # Get optional student fields
        matric_no = request.form.get('matric_no', '').strip()
        level = request.form.get('level', '').strip()
        
        # Get staff role selection (if provided)
        staff_role = request.form.get('staff_role', '').strip()
        
        print(f"\n📝 PARSED VALUES:")
        print(f"  Name: '{name}' (length: {len(name)})")
        print(f"  Email: '{email}' (length: {len(email)})")
        print(f"  Password: {'*' * len(password)} (length: {len(password)})")
        print(f"  Staff Role Selection: '{staff_role}'")
        print(f"  Matric No: '{matric_no}'")
        print(f"  Level: '{level}'")
        
        # Step 1: Check if all required fields are provided
        if not name:
            print("❌ VALIDATION FAILED: Name is empty")
            flash('Please enter your full name!', 'danger')
            return render_template('signup.html')
            
        if not email:
            print("❌ VALIDATION FAILED: Email is empty")
            flash('Please enter your email address!', 'danger')
            return render_template('signup.html')
            
        if not password:
            print("❌ VALIDATION FAILED: Password is empty")
            flash('Please enter a password!', 'danger')
            return render_template('signup.html')
        
        print("✅ All required fields have values")
        
        # Step 2: Validate FUNAAB email
        print(f"\n🔍 Validating email: {email}")
        is_valid, message, auto_role = is_valid_funaab_email(email)
        print(f"  Valid: {is_valid}")
        print(f"  Message: {message}")
        print(f"  Auto Role: {auto_role}")
        
        if not is_valid:
            print(f"❌ EMAIL VALIDATION FAILED: {message}")
            flash(message, 'danger')
            return render_template('signup.html')
        
        # Step 2.5: Override role if staff selected a specific role
        final_role = auto_role
        if email.endswith('@staff.funaab.edu.ng') and staff_role:
            # Staff member selected their specific role
            final_role = staff_role
            print(f"  Staff role override: {staff_role}")
        elif email.endswith('@staff.funaab.edu.ng') and not staff_role:
            # Staff email but no role selected
            print("❌ VALIDATION FAILED: Staff must select a role")
            flash('Please select your role (Lecturer or Course Coordinator)', 'danger')
            return render_template('signup.html')
        
        print(f"✅ Email validated - Final Role: {final_role}")
        
        # Step 3: Password strength check
        if len(password) < 6:
            print(f"❌ VALIDATION FAILED: Password too short ({len(password)} chars)")
            flash('Password must be at least 6 characters long!', 'danger')
            return render_template('signup.html')
        
        print("✅ Password validated")
        
        # Step 4: Check if user already exists
        print(f"\n🔍 Checking if user exists...")
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"❌ USER EXISTS: {email}")
            flash('This FUNAAB email is already registered!', 'warning')
            return redirect(url_for('login'))
        
        print("✅ Email is available")
        
        # Step 5: Create new user
        print(f"\n👤 Creating new user...")
        print(f"  Name: {name}")
        print(f"  Email: {email}")
        print(f"  Role: {final_role}")
        print(f"  Matric No: {matric_no or 'N/A'}")
        print(f"  Level: {level or 'N/A'}")
        
        hashed_password = generate_password_hash(password, method='scrypt')
        print(f"  Password hashed: {hashed_password[:20]}...")
        
        new_user = User(
            full_name=name,
            email=email,
            password=hashed_password,
            role=final_role,
            matric_no=matric_no if matric_no else None,
            level=level if level else None
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            print("✅ User saved to database")
            
            # Step 6: Send welcome email
            print(f"\n📧 Sending welcome email to {email}...")
            try:
                send_welcome_email(email, name, final_role)
                print("✅ Welcome email sent successfully")
            except Exception as email_error:
                print(f"⚠️ Email sending failed: {email_error}")
                # Don't fail the signup if email fails
            
            print(f"\n{'='*60}")
            print(f"🎉 SIGNUP SUCCESSFUL!")
            print(f"{'='*60}\n")
            
            flash(f'Account created successfully! Welcome to FUNAAB Attendance System.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ DATABASE ERROR: {e}")
            import traceback
            traceback.print_exc()
            print(f"{'='*60}\n")
            flash(f'Error creating account. Please try again.', 'danger')
            return render_template('signup.html')
    
    # GET request
    print("📄 Rendering signup form\n")
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
    if current_user.role.lower() != 'student':
        return redirect(url_for('dashboard'))

    # FIX #10: Only iterate over the student's own enrolled courses
    enrolled_courses = getattr(current_user, 'enrolled_courses', [])
    attendance_data = []
    for course in enrolled_courses:
        count = Attendance.query.filter_by(
            student_id=current_user.id,
            course_id=course.id
        ).count()
        attendance_data.append({
            'code': course.code,
            'title': course.title,
            'count': count,
        })

    return render_template('student_dashboard.html',
                           attendance_data=attendance_data,
                           enrolled_courses=enrolled_courses)


@app.route('/lecturer_dashboard')
@login_required
def lecturer_dashboard():
    role = (current_user.role or '').lower()
    if role not in ['lecturer', 'course coordinator']:
        return redirect(url_for('dashboard'))

    if role == 'course coordinator':
        my_courses = Course.query.filter_by(coordinator_id=current_user.id).all()
        can_create = True
    else:
        my_courses = getattr(current_user, 'teaching_courses', [])
        can_create = False

    return render_template('lecturer_dashboard.html', courses=my_courses, can_create=can_create)


@app.route('/hod_dashboard')
@login_required
def hod_dashboard():
    if current_user.role.lower() != 'hod':
        return redirect(url_for('login'))

    courses = Course.query.filter_by(department=current_user.department).all()
    return render_template('hod_dashboard.html', courses=courses, dept=current_user.department)


@app.route('/hod_analytics')
@login_required
def hod_analytics():
    if current_user.role.lower() != 'hod':
        return redirect(url_for('login'))

    data = get_department_analytics(current_user.department)
    return render_template('analytics_hod.html', dept=current_user.department, data=data)


@app.route('/dean_dashboard')
@login_required
def dean_dashboard():
    if current_user.role.lower() != 'dean':
        return redirect(url_for('login'))

    courses = Course.query.filter_by(faculty=current_user.faculty).all()
    lecturers = User.query.filter_by(role='lecturer', faculty=current_user.faculty).all()
    return render_template('dean_dashboard.html',
                           faculty=current_user.faculty,
                           courses=courses,
                           lecturers=lecturers)


@app.route('/dap_dashboard')
@login_required
def dap_dashboard():
    if current_user.role.lower() != 'dap':
        return redirect(url_for('login'))

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
    if current_user.role.lower() != 'dap':
        return redirect(url_for('login'))

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
    )
    db.session.add(new_course)
    db.session.commit()
    flash(f"Course {code} created successfully!", "success")
    return redirect(url_for('dashboard'))


# FIX #9: DELETE only via POST (removed GET)
@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)

    if course.coordinator_id != current_user.id:
        flash('Unauthorised: Only the course creator can delete it.', 'error')
        return redirect(url_for('dashboard'))

    Attendance.query.filter_by(course_id=course_id).delete()
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


@app.route('/generate_qr/<int:course_id>')
@login_required
def generate_qr(course_id):
    course = Course.query.get_or_404(course_id)
    if not _is_course_authorized(course):
        flash('Unauthorised Access', 'error')
        return redirect(url_for('dashboard'))
    return render_template('generate_qr.html', course=course)


@app.route('/api/qr_data/<int:course_id>')
@login_required
@limiter.exempt
def get_qr_data(course_id):
    """
    FIX #6: Returns the same cached signed token as the image endpoint.
    FIX #3: Token is HMAC-signed so it cannot be forged.
    """
    course = Course.query.get_or_404(course_id)
    if not _is_course_authorized(course):
        return jsonify({"error": "Unauthorised"}), 403

    qr_text = generate_signed_qr(course_id)
    return jsonify({"qr_text": qr_text})


@app.route('/course/<int:course_id>/live')
@login_required
@limiter.exempt
def get_qr_image(course_id):
    """
    FIX #6: Uses the same shared cached token as /api/qr_data.
    FIX #3: Token is HMAC-signed.
    """
    course = Course.query.get_or_404(course_id)
    if not _is_course_authorized(course):
        return "Unauthorised", 403

    qr_text = generate_signed_qr(course_id)

    try:
        import qrcode
        img = qrcode.make(qr_text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype='image/png')
    except ImportError:
        return "QR code library not installed", 500


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

        # FIX #3 & #5: Verify the signed token (3-part format: id|ts|sig)
        try:
            course_id, timestamp = verify_signed_qr(qr_text)
        except ValueError as ve:
            return jsonify({"status": "error", "message": str(ve)})

        course = Course.query.get(course_id)
        if not course:
            return jsonify({"status": "error", "message": "Invalid QR Code: Course not found."})

        # Enrolment check
        if hasattr(current_user, 'enrolled_courses'):
            if course not in current_user.enrolled_courses:
                return jsonify({
                    "status": "error",
                    "message": f"🚫 Access Denied: You are not registered for {course.code}."
                })

        # Duplicate entry check (2-hour window)
        time_limit = datetime.utcnow() - timedelta(hours=2)
        existing = Attendance.query.filter(
            Attendance.student_id == current_user.id,
            Attendance.course_id == course_id,
            Attendance.timestamp > time_limit
        ).first()

        if existing:
            return jsonify({
                "status": "error",
                "message": "You are already marked present! Double-scanning is not allowed."
            })

        # FIX #4: Retrieve location from Redis
        class_loc = get_class_location(course_id)
        if class_loc:
            if not student_lat or not student_lon:
                return jsonify({"status": "error", "message": "Location required! Please allow GPS access."})

            dist = calculate_distance(
                class_loc['lat'], class_loc['lon'],
                float(student_lat), float(student_lon)
            )
            if dist > 50:  # 50 meters
                return jsonify({
                    "status": "error",
                    "message": f"Too far from classroom. You are {int(dist)}m away (max 50m)."
                })

        new_record = Attendance(
            student_id=current_user.id,
            course_id=course_id,
            device_id=data.get('device_id', 'browser')
        )
        db.session.add(new_record)
        db.session.commit()
        
        # Send attendance confirmation email
        timestamp_str = datetime.now().strftime('%B %d, %Y at %I:%M %p')
        send_attendance_confirmation(
            user_email=current_user.email,
            user_name=current_user.full_name,
            course_code=course.code,
            course_title=course.title,
            timestamp=timestamp_str
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
    course = Course.query.get_or_404(course_id)

    if not _attendance_authorized(course):  # FIX #8
        flash("Unauthorised access to attendance list.", "error")
        return redirect(url_for('dashboard'))

    records = (Attendance.query
               .filter_by(course_id=course_id)
               .order_by(Attendance.timestamp.desc())
               .all())
    return render_template('view_attendance.html', course=course, attendees=records)


@app.route('/course/<int:course_id>/download_csv')
@login_required
def download_csv(course_id):
    course = Course.query.get_or_404(course_id)

    if not _attendance_authorized(course):  # FIX #8
        return "Unauthorised", 403

    records = (Attendance.query
               .filter_by(course_id=course_id)
               .order_by(Attendance.timestamp.desc())
               .all())

    def generate():
        yield "Matric Number,Full Name,Level,Time Scanned,Device ID\n"
        for rec in records:
            time_str = rec.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            matric = rec.student.matric_no or "N/A"
            level = rec.student.level or "N/A"
            full_name = rec.student.full_name or "N/A"
            device = rec.device_id or "N/A"
            yield f"{matric},{full_name},{level},{time_str},{device}\n"

    return Response(
        generate(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename={course.code}_attendance.csv"}
    )


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
    flash(f"Too many requests! Please slow down. ({e.description})", "error")
    return redirect(url_for('login'))


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

with app.app_context():
    db.create_all()
    print("✅ Database initialized successfully!")

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎓 FUNAAB ATTENDANCE SYSTEM STARTING")
    print("="*60)
    print(f"📧 Mail Server: {app.config['MAIL_SERVER']}")
    print(f"📧 Mail Username: {app.config['MAIL_USERNAME']}")
    print(f"🔐 CSRF Protection: Enabled")
    print(f"🛡️  Rate Limiting: Enabled")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)