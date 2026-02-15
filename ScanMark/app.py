import os
import io
import csv
import time
import math
import pyotp
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

from models import db, User, Course, Attendance

# Initialize Flask App
app = Flask(__name__)

# Store active class locations: { course_id: {'lat': x, 'lon': y} }
active_class_locations = {}

# CONFIGURATION
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local_fallback_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanmark_v2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ========== UTILITY FUNCTIONS ==========

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates using Haversine formula"""
    R = 6371000  # Radius of Earth in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2)**2 + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c  # Distance in meters


def get_course_analytics(course_id):
    """Returns attendance stats for a single course"""
    course = Course.query.get(course_id)
    if not course:
        return None

    # Total Enrolled Students
    total_students = len(course.students) if hasattr(course, 'students') else 0
    if total_students == 0:
        return {"dates": [], "counts": [], "average": 0, "total_enrolled": 0}

    # Get Attendance per Date
    attendance_trends = db.session.query(
        func.date(Attendance.timestamp), func.count(Attendance.id)
    ).filter_by(course_id=course_id).group_by(func.date(Attendance.timestamp)).all()

    dates = [str(day[0]) for day in attendance_trends]
    counts = [day[1] for day in attendance_trends]

    # Calculate Average Attendance %
    avg_attendance = 0
    if counts:
        avg_attendance = (sum(counts) / len(counts) / total_students) * 100

    return {
        "dates": dates,
        "counts": counts,
        "average": round(avg_attendance, 1),
        "total_enrolled": total_students
    }


def get_department_analytics(dept_name):
    """Returns comparative stats for HOD"""
    courses = Course.query.filter_by(department=dept_name).all()

    course_codes = []
    attendance_rates = []

    for course in courses:
        stats = get_course_analytics(course.id)
        if stats:
            course_codes.append(course.code)
            attendance_rates.append(stats['average'])

    return {
        "labels": course_codes,
        "data": attendance_rates
    }


# ========== AUTHENTICATION ROUTES ==========

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        role = current_user.role.lower() if current_user.role else 'student'

        if role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'lecturer':
            return redirect(url_for('lecturer_dashboard'))
        elif role == 'course coordinator':
            return redirect(url_for('lecturer_dashboard'))
        elif role == 'hod':
            return redirect(url_for('hod_dashboard'))
        elif role == 'dean':
            return redirect(url_for('dean_dashboard'))
        elif role == 'dap':
            return redirect(url_for('dap_dashboard'))
        else:
            flash(f"Role '{role}' not recognized. Defaulting to Student view.", "warning")
            return redirect(url_for('student_dashboard'))

    # Handle login form submission
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            role = user.role.lower() if user.role else 'student'

            if role == 'student':
                return redirect(url_for('student_dashboard'))
            elif role == 'lecturer':
                return redirect(url_for('lecturer_dashboard'))
            elif role == 'course coordinator':
                return redirect(url_for('lecturer_dashboard'))
            elif role == 'hod':
                return redirect(url_for('hod_dashboard'))
            elif role == 'dean':
                return redirect(url_for('dean_dashboard'))
            elif role == 'dap':
                return redirect(url_for('dap_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Enforce School Email
        allowed_domains = ['funaab.edu.ng', 'student.funaab.edu.ng']
        if not any(email.endswith(domain) for domain in allowed_domains):
            flash('Access Denied: You must use a FUNAAB email address.', 'error')
            return redirect(url_for('signup'))

        # Check if user already exists
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already exists!', 'error')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password, method='scrypt')
        new_user = User(full_name=full_name, email=email, password=hashed_pw, role=role)

        # Add student-specific fields
        if role.lower() == 'student':
            new_user.matric_no = request.form.get('matric_no')
            new_user.level = request.form.get('level')

        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ========== DASHBOARD ROUTES ==========

@app.route('/dashboard')
@login_required
def dashboard():
    """Generic dashboard - redirects to role-specific dashboard"""
    role = current_user.role.lower() if current_user.role else 'student'

    if role == 'student':
        return redirect(url_for('student_dashboard'))
    elif role in ['lecturer', 'course coordinator']:
        return redirect(url_for('lecturer_dashboard'))
    elif role == 'hod':
        return redirect(url_for('hod_dashboard'))
    elif role == 'dean':
        return redirect(url_for('dean_dashboard'))
    elif role == 'dap':
        return redirect(url_for('dap_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))


@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role.lower() != 'student':
        return redirect(url_for('dashboard'))

    # Get all courses and attendance data
    all_courses = Course.query.all()
    attendance_data = []

    for course in all_courses:
        my_count = Attendance.query.filter_by(
            student_id=current_user.id,
            course_id=course.id
        ).count()

        if my_count > 0:
            attendance_data.append({
                'code': course.code,
                'title': course.title,
                'count': my_count
            })

    # Get enrolled courses
    enrolled_courses = current_user.enrolled_courses if hasattr(current_user, 'enrolled_courses') else []

    return render_template('student_dashboard.html',
                           attendance_data=attendance_data,
                           enrolled_courses=enrolled_courses)


@app.route('/lecturer_dashboard')
@login_required
def lecturer_dashboard():
    role = current_user.role.lower() if current_user.role else ''

    if role not in ['lecturer', 'course coordinator']:
        return redirect(url_for('dashboard'))

    # Course Coordinators can create courses
    if role == 'course coordinator':
        my_courses = Course.query.filter_by(coordinator_id=current_user.id).all()
        can_create = True
    else:
        # Lecturers see courses they are assigned to
        my_courses = current_user.teaching_courses if hasattr(current_user, 'teaching_courses') else []
        can_create = False

    return render_template('lecturer_dashboard.html', courses=my_courses, can_create=can_create)


@app.route('/hod_dashboard')
@login_required
def hod_dashboard():
    if current_user.role.lower() != 'hod':
        return redirect(url_for('login'))

    # Show only courses in the HOD's department
    my_dept = current_user.department
    courses = Course.query.filter_by(department=my_dept).all()

    return render_template('hod_dashboard.html', courses=courses, dept=my_dept)


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

    # Find all courses in this Dean's Faculty
    my_faculty = current_user.faculty
    courses = Course.query.filter_by(faculty=my_faculty).all()

    # Get total lecturers in this faculty
    lecturers = User.query.filter_by(role='lecturer', faculty=my_faculty).all()

    return render_template('dean_dashboard.html',
                           faculty=my_faculty,
                           courses=courses,
                           lecturers=lecturers)


@app.route('/dap_dashboard')
@login_required
def dap_dashboard():
    if current_user.role.lower() != 'dap':
        return redirect(url_for('login'))

    # DAP sees everything
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

    # Count attendance grouped by Faculty
    results = db.session.query(
        Course.faculty, func.count(Attendance.id)
    ).join(Attendance).group_by(Course.faculty).all()

    labels = [row[0] for row in results]
    data = [row[1] for row in results]

    return render_template('analytics_dap.html', labels=labels, data=data)


# ========== COURSE MANAGEMENT ROUTES ==========

@app.route('/add_course', methods=['POST'])
@login_required
def add_course():
    # Get Form Data
    code = request.form.get('code')
    title = request.form.get('title')

    # Validation
    if not code or not title:
        flash("Course code and title are required!", "error")
        return redirect(url_for('dashboard'))

    # Create the Course
    new_course = Course(
        code=code,
        title=title,
        coordinator_id=current_user.id,
        department=current_user.department if hasattr(current_user, 'department') else None,
        faculty=current_user.faculty if hasattr(current_user, 'faculty') else None
    )

    db.session.add(new_course)
    db.session.commit()

    flash(f"Course {code} created successfully!", "success")
    return redirect(url_for('dashboard'))


@app.route('/delete_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)

    # Security check: Only coordinator can delete
    if course.coordinator_id != current_user.id:
        flash('Unauthorized Action! Only the creator can delete this course.', 'error')
        return redirect(url_for('dashboard'))

    # Delete all attendance records first
    Attendance.query.filter_by(course_id=course_id).delete()

    # Delete the course
    db.session.delete(course)
    db.session.commit()

    flash(f'Course "{course.code}" has been deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/add_instructor', methods=['POST'])
@login_required
def add_instructor():
    # Security: Only Course Coordinator can add instructors
    if current_user.role.lower() != 'course coordinator':
        flash("Unauthorized", "error")
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
                flash(f"Added {lecturer.full_name} to {course.code}", "success")
            else:
                flash("User is already an instructor", "info")
        else:
            flash("Course instructors relationship not configured", "error")
    else:
        flash("Course or lecturer not found", "error")

    return redirect(url_for('dashboard'))


@app.route('/register_course', methods=['POST'])
@login_required
def register_course():
    course_code = request.form.get('course_code')
    course = Course.query.filter_by(code=course_code).first()

    if not course:
        flash("Course not found!", "error")
        return redirect(url_for('student_dashboard'))

    # Check if already registered
    if hasattr(current_user, 'enrolled_courses'):
        if course in current_user.enrolled_courses:
            flash(f"You are already registered for {course.code}", "info")
        else:
            current_user.enrolled_courses.append(course)
            db.session.commit()
            flash(f"✅ Successfully registered for {course.code}", "success")
    else:
        flash("Enrollment system not configured", "error")

    return redirect(url_for('student_dashboard'))


# ========== QR CODE ROUTES ==========

@app.route('/generate_qr/<int:course_id>')
@login_required
def generate_qr(course_id):
    course = Course.query.get_or_404(course_id)

    # Check authorization
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = hasattr(course, 'instructors') and (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        flash('Unauthorized Access', 'error')
        return redirect(url_for('dashboard'))

    return render_template('generate_qr.html', course=course)


@app.route('/api/qr_data/<int:course_id>')
@login_required
def get_qr_data(course_id):
    course = Course.query.get_or_404(course_id)

    # Check authorization
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = hasattr(course, 'instructors') and (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        return jsonify({"error": "Unauthorized"}), 403

    timestamp = int(time.time())
    qr_text = f"{course_id}|{timestamp}"
    return jsonify({"qr_text": qr_text})


@app.route('/course/<int:course_id>/live')
@login_required
def get_qr_image(course_id):
    course = Course.query.get_or_404(course_id)

    # Security check
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = hasattr(course, 'instructors') and (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        return "Unauthorized", 403

    # Create QR code
    timestamp = int(time.time())
    data = f"{course_id}|{timestamp}"

    try:
        import qrcode
        img = qrcode.make(data)
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
    # Save the lecturer's location for this course
    active_class_locations[course_id] = {
        'lat': data['lat'],
        'lon': data['lon']
    }
    print(f"--- LOCATION SET: Course {course_id} is at {data['lat']}, {data['lon']} ---")
    return jsonify({"status": "ok"})


# ========== ATTENDANCE ROUTES ==========

@app.route('/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    data = request.get_json()
    qr_text = data.get('qr_data')
    student_lat = data.get('lat')
    student_lon = data.get('lon')

    try:
        if not qr_text:
            return jsonify({"status": "error", "message": "No QR data provided"})

        # Parse QR code
        parts = qr_text.split('|')
        if len(parts) != 2:
            return jsonify({"status": "error", "message": "Invalid QR code format"})

        course_id = int(parts[0])
        timestamp = int(parts[1])

        # Find the course
        course = Course.query.get(course_id)
        if not course:
            return jsonify({"status": "error", "message": "Invalid QR Code: Course not found"})

        # Check if student is registered for this course
        if hasattr(current_user, 'enrolled_courses'):
            if course not in current_user.enrolled_courses:
                return jsonify({
                    "status": "error",
                    "message": f"🚫 Access Denied: You are not registered for {course.code}"
                })

        # CHECK 1: EXPIRATION (15 Seconds)
        if int(time.time()) - timestamp > 15:
            return jsonify({"status": "error", "message": "Code expired! Scan faster."})

        # CHECK 2: DUPLICATE ENTRY (One-Scan Rule)
        time_limit = datetime.utcnow() - timedelta(hours=2)
        existing_record = Attendance.query.filter(
            Attendance.student_id == current_user.id,
            Attendance.course_id == course_id,
            Attendance.timestamp > time_limit
        ).first()

        if existing_record:
            return jsonify({
                "status": "error",
                "message": "You are already marked present! Double-scanning is not allowed."
            })

        # CHECK 3: GEO-FENCING (50 Meters)
        if course_id in active_class_locations:
            target = active_class_locations[course_id]
            if not student_lat or not student_lon:
                return jsonify({"status": "error", "message": "Location required! Allow GPS."})

            dist = calculate_distance(
                target['lat'], target['lon'],
                float(student_lat), float(student_lon)
            )

            if dist > 50:  # 50 Meters Limit
                return jsonify({
                    "status": "error",
                    "message": f"Too far! You are {int(dist)}m away from the classroom."
                })

        # SAVE ATTENDANCE RECORD
        new_record = Attendance(
            student_id=current_user.id,
            course_id=course_id,
            device_id=data.get('device_id', 'browser')
        )
        db.session.add(new_record)
        db.session.commit()

        return jsonify({"status": "success", "message": "Attendance marked successfully! ✅"})

    except ValueError as e:
        return jsonify({"status": "error", "message": f"Invalid data format: {str(e)}"})
    except Exception as e:
        print(f"--- SERVER ERROR: {e} ---")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"})


@app.route('/course/<int:course_id>/attendance')
@login_required
def view_attendance(course_id):
    course = Course.query.get_or_404(course_id)

    # Security check
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = hasattr(course, 'instructors') and (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        flash("Unauthorized access to attendance list.", "error")
        return redirect(url_for('dashboard'))

    records = Attendance.query.filter_by(course_id=course_id).order_by(Attendance.timestamp.desc()).all()
    return render_template('view_attendance.html', course=course, attendees=records)


@app.route('/course/<int:course_id>/download_csv')
@login_required
def download_csv(course_id):
    course = Course.query.get_or_404(course_id)

    # Security check
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = hasattr(course, 'instructors') and (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        return "Unauthorized", 403

    records = Attendance.query.filter_by(course_id=course_id).order_by(Attendance.timestamp.desc()).all()

    def generate():
        yield "Matric Number,Full Name,Level,Time Scanned,Device ID\n"
        for record in records:
            time_str = record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            matric = record.student.matric_no if record.student.matric_no else "N/A"
            level = record.student.level if record.student.level else "N/A"
            full_name = record.student.full_name if record.student.full_name else "N/A"
            device = record.device_id if record.device_id else "N/A"
            yield f"{matric},{full_name},{level},{time_str},{device}\n"

    return Response(
        generate(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename={course.code}_attendance.csv"}
    )


# ========== DATABASE INITIALIZATION ==========

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)