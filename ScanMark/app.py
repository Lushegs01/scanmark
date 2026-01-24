from flask import request # To get form data
from werkzeug.security import generate_password_hash, check_password_hash # Security
from flask_login import LoginManager
from models import db, User
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Course, Attendance # <--- Added Course here
import io # To handle images in memory
import qrcode
import time  
import os
import math 
import pyotp
from datetime import datetime, timedelta
from flask import send_file
from flask import Flask, jsonify  # <--- Make sure jsonify is here
from flask import Flask, Response # <--- Add Response here
import csv # Add this import at the very top too!

app = Flask(__name__)

# Store active class locations: { course_id: {'lat': x, 'lon': y} }
active_class_locations = {}

# CONFIGURATION
# Secret key is needed for sessions. In production, change this to a random string!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local_fallback_key') 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanmark.db' # Using SQLite for local dev
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Where to send users if they aren't logged in

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES (Placeholders for now) ---
# --- ROUTES ---
# --- AUTH ROUTES ---
@app.route('/')
def home():
    # If user is already logged in, skip login page
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, kick them to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard')) 
        else:
            flash('Invalid email or password')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # --- NEW SECURITY CHECK ---
        # 1. Enforce School Email
        allowed_domains = ['funaab.edu.ng', 'student.funaab.edu.ng']
        # check if email ends with any allowed domain
        if not any(email.endswith(domain) for domain in allowed_domains):
            flash('Access Denied: You must use a FUNAAB email address.')
            return redirect(url_for('signup'))
        # --------------------------
        
        # 2. Check if user already exists
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already exists!')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password, method='scrypt')
        new_user = User(full_name=full_name, email=email, password=hashed_pw, role=role)
        
        if role == 'Student':
            new_user.matric_no = request.form.get('matric_no')
            new_user.level = request.form.get('level')

        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html')
@app.route('/dashboard')
@login_required
def dashboard():
    # --- STUDENT VIEW ---
    if current_user.role == 'Student':
        # 1. Get all courses so the student can see everything
        all_courses = Course.query.all()
        attendance_data = []

        for course in all_courses:
            # 2. Count how many times THIS student marked attendance
            my_count = Attendance.query.filter_by(
                student_id=current_user.id, 
                course_id=course.id
            ).count()
            
            # 3. Only show courses they have actually attended at least once
            # (Or remove this 'if' to show zeros for missed classes)
            if my_count > 0:
                attendance_data.append({
                    'code': course.code,
                    'title': course.title,
                    'count': my_count
                })

        return render_template('student_dashboard.html', attendance_data=attendance_data)
    
    # --- STAFF VIEW (Coordinator & Lecturer) ---
    if current_user.role == 'Course Coordinator':
        my_courses = Course.query.filter_by(coordinator_id=current_user.id).all()
        can_create = True
    else:
        # Lecturers see courses they are ASSIGNED to
        my_courses = current_user.teaching_courses 
        can_create = False

    return render_template('lecturer_dashboard.html', courses=my_courses, can_create=can_create)

@app.route('/create_course', methods=['POST'])
@login_required
def create_course():
    if current_user.role != 'Course Coordinator':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    
    code = request.form.get('code')
    title = request.form.get('title')
    
    # Create Course & Add Creator as First Instructor
    new_course = Course(code=code, title=title, coordinator_id=current_user.id)
    new_course.instructors.append(current_user) # Important: You teach what you coordinate!
    
    db.session.add(new_course)
    db.session.commit()
    flash('Course created successfully!')
        
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 1. THE MISSING PAGE ROUTE (Fixes the BuildError)
@app.route('/generate_qr/<int:course_id>')
@login_required
def generate_qr(course_id):
    course = Course.query.get_or_404(course_id)
    
    # NEW HIERARCHY CHECK (Coordinator OR Instructor)
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = (current_user in course.instructors)
    
    if not (is_coordinator or is_instructor):
        flash('Unauthorized Access', 'error')
        return redirect(url_for('dashboard'))

    return render_template('generate_qr.html', course=course)

# 2. THE API ROUTE (Updated to fix the 'lecturer_id' crash)
@app.route('/api/qr_data/<int:course_id>')
@login_required
def get_qr_data(course_id):
    course = Course.query.get_or_404(course_id)
    
    # NEW HIERARCHY CHECK
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = (current_user in course.instructors)
    
    if not (is_coordinator or is_instructor):
        return jsonify({"error": "Unauthorized"}), 403

    timestamp = int(time.time()) 
    qr_text = f"{course_id}|{timestamp}"
    return jsonify({"qr_text": qr_text})



@app.route('/course/<int:course_id>/live')
@login_required
def get_qr_image(course_id):
    course = Course.query.get_or_404(course_id)

    # 1. SECURITY CHECK (Hierarchy Support)
    # Must be Coordinator OR Instructor
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        return "Unauthorized", 403

    # 2. CREATE THE QR DATA
    # We embed the Course ID and Time so it expires
    timestamp = int(time.time()) 
    data = f"{course_id}|{timestamp}"
    
    # 3. DRAW THE IMAGE IN MEMORY
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0) # Rewind the file so we can send it
    
    return send_file(buf, mimetype='image/png')

@app.route('/scan_page')
@login_required
def scan_page():
    return render_template('scan.html')

def calculate_distance(lat1, lon1, lat2, lon2):
    # The Haversine Formula (Math to calculate distance on a sphere)
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

@app.route('/add_instructor', methods=['POST'])
@login_required
def add_instructor():
    # Security: Only the Boss can add people
    if current_user.role != 'Course Coordinator':
        flash("Unauthorized", "error")
        return redirect(url_for('dashboard'))

    course_id = request.form.get('course_id')
    lecturer_email = request.form.get('lecturer_email')
    
    course = Course.query.get(course_id)
    # Find the lecturer (Must be staff)
    lecturer = User.query.filter((User.email == lecturer_email)).first()
    
    if course and lecturer:
        if lecturer not in course.instructors:
            course.instructors.append(lecturer)
            db.session.commit()
            flash(f"Added {lecturer.full_name} to {course.code}", "success")
        else:
            flash("User is already an instructor", "info")
    else:
        flash("User not found (or is a student)", "error")
        
    return redirect(url_for('dashboard'))

@app.route('/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    data = request.get_json()
    qr_text = data.get('qr_data')
    student_lat = data.get('lat')
    student_lon = data.get('lon')
    
    try:
        if not qr_text:
            return jsonify({"status": "error", "message": "No QR data"})

        parts = qr_text.split('|')
        if len(parts) != 2:
            raise ValueError("QR Format Invalid")

        course_id = int(parts[0])
        timestamp = int(parts[1])

        # --- CHECK 1: EXPIRATION (15 Seconds) ---
        if int(time.time()) - timestamp > 15:
            return jsonify({"status": "error", "message": "Code Expired! Scan faster."})

        # --- CHECK 2: DUPLICATE ENTRY (One-Scan Rule) ---
        # "Has this student already marked attendance for this course in the last 2 hours?"
        time_limit = datetime.utcnow() - timedelta(hours=2)
        existing_record = Attendance.query.filter(
            Attendance.student_id == current_user.id,
            Attendance.course_id == course_id,
            Attendance.timestamp > time_limit
        ).first()

        if existing_record:
            return jsonify({"status": "error", "message": "You are already marked Present! Double-scanning is not allowed."})

        # --- CHECK 3: GEO-FENCING (50 Meters) ---
        if course_id in active_class_locations:
            target = active_class_locations[course_id]
            if not student_lat or not student_lon:
                return jsonify({"status": "error", "message": "Location required! Allow GPS."})

            dist = calculate_distance(target['lat'], target['lon'], float(student_lat), float(student_lon))
            
            if dist > 50: # 50 Meters Limit
                return jsonify({"status": "error", "message": f"Too far! You are {int(dist)}m away."})

        # 💾 SAVE RECORD (Simple & Clean)
        new_record = Attendance(
            student_id=current_user.id,
            course_id=course_id,
            device_id="browser" 
        )
        db.session.add(new_record)
        db.session.commit()
        
        return jsonify({"status": "success", "message": "Attendance Verified Successfully! ✅"})

    except Exception as e:
        print(f"--- SERVER ERROR: {e} ---") 
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})
        
@app.route('/course/<int:course_id>/attendance')
@login_required
def view_attendance(course_id):
    course = Course.query.get_or_404(course_id)
    
    # SECURITY CHECK (Hierarchy Support)
    # Allow if Coordinator OR Instructor
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = (current_user in course.instructors)
    
    if not (is_coordinator or is_instructor):
        flash("Unauthorized access to attendance list.", "error")
        return redirect(url_for('dashboard'))
    
    records = Attendance.query.filter_by(course_id=course_id).order_by(Attendance.timestamp.desc()).all()
    return render_template('view_attendance.html', course=course, attendees=records)

@app.route('/course/<int:course_id>/download_csv')
@login_required
def download_csv(course_id):
    course = Course.query.get_or_404(course_id)
    
    # SECURITY CHECK (Hierarchy Support)
    is_coordinator = (course.coordinator_id == current_user.id)
    is_instructor = (current_user in course.instructors)

    if not (is_coordinator or is_instructor):
        return "Unauthorized", 403

    records = Attendance.query.filter_by(course_id=course_id).order_by(Attendance.timestamp.desc()).all()

    def generate():
        yield "Matric Number,Full Name,Level,Time Scanned,Device ID\n"
        for record in records:
            time_str = record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            # Handle potential None values safely
            matric = record.student.matric_no if record.student.matric_no else "N/A"
            level = record.student.level if record.student.level else "N/A"
            yield f"{matric},{record.student.full_name},{level},{time_str},{record.device_id}\n"

    return Response(generate(), mimetype='text/csv', 
                    headers={"Content-Disposition": f"attachment;filename={course.code}_attendance.csv"})

# --- PASTE THIS INTO APP.PY (Replacing the old delete_course) ---

@app.route('/delete_course/<int:course_id>', methods=['GET', 'POST']) # <--- FIX 1: Allow GET
@login_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # FIX 2: Check 'coordinator_id' (The New Hierarchy Rule)
    if course.coordinator_id != current_user.id:
        flash('Unauthorized Action! Only the Creator can delete this class.', 'error')
        return redirect(url_for('dashboard'))
    
    # 1. Delete all attendance records for this course first (Clean up)
    Attendance.query.filter_by(course_id=course_id).delete()
    
    # 2. Delete the course itself
    db.session.delete(course)
    db.session.commit()
    
    flash(f'Course "{course.code}" has been deleted.', 'success')
    return redirect(url_for('dashboard'))

# --- FIX FOR RENDER: NUKE THE OLD DB TO REBUILD IT ---
with app.app_context():
    import os
    # 1. Define the path to the database
    db_path = os.path.join(app.root_path, 'scanmark.db')
    
    # 2. Check if it exists and DELETE it (Force Reset)
    if os.path.exists(db_path):
        os.remove(db_path)
        print("--- DELETED OLD DATABASE FILE ---")

    # 3. Create a fresh new one with the correct columns
    db.create_all()
    print("--- CREATED FRESH DATABASE ---") 

# --- SETUP COMMAND ---
# This block creates the database if you run this file directly
if __name__ == '__main__':
    # host='0.0.0.0' allows other devices on the network to connect
    app.run(host='0.0.0.0', port=5000, debug=True)
    # --- QR CODE GENERATOR LOGIC ---

#