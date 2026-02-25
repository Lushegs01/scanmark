import os
import io
import hmac
import hashlib
import secrets
import time
import math
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
from flask_wtf.csrf import CSRFProtect   # FIX #2: CSRF Protection

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

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
mail = Mail(app)


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
# FIX #13: Async email helper
# ------------------------------------------------------------------

def send_async_email(flask_app, msg):
    with flask_app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            print(f"[Email Error] {e}")


def send_email_async(msg):
    Thread(target=send_async_email, args=(app, msg), daemon=True).start()


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
            send_email_async(msg)   # FIX #13: non-blocking

        # FIX: Always show the same message to prevent email enumeration
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

    allowed_domains = ['funaab.edu.ng', 'student.funaab.edu.ng']
    if not any(email.endswith(d) for d in allowed_domains):
        flash('Access Denied: You must use your official FUNAAB email address.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        # FIX #7: Use a cryptographically random dummy password (not a known string)
        user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(secrets.token_hex(32), method='scrypt'),
            role='student'
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created via Google!', 'success')

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
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        allowed_domains = ['funaab.edu.ng', 'student.funaab.edu.ng']
        if not any(email.endswith(d) for d in allowed_domains):
            flash('Access Denied: You must use a FUNAAB email address.', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('signup'))

        # FIX #1: Consistent hashing (scrypt everywhere)
        hashed_pw = generate_password_hash(password, method='scrypt')
        new_user = User(full_name=full_name, email=email, password=hashed_pw, role=role)

        if role.lower() == 'student':
            new_user.matric_no = request.form.get('matric_no')
            new_user.level = request.form.get('level')

        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
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
    print(f"--- LOCATION SET: Course {course_id} at {data['lat']}, {data['lon']} ---")
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
            if dist > 50:
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

        return jsonify({"status": "success", "message": "Attendance marked successfully! ✅"})

    except Exception as e:
        print(f"--- SERVER ERROR in mark_attendance: {e} ---")
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)