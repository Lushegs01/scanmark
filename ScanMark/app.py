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

        if user and check_password_hash(user.password_hash, password):
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
        new_user = User(full_name=full_name, email=email, password_hash=hashed_pw, role=role)
        
        if role == 'student':
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
    if current_user.role == 'lecturer':
        # Fetch courses created by THIS lecturer only
        my_courses = Course.query.filter_by(lecturer_id=current_user.id).all()
        return render_template('lecturer_dashboard.html', courses=my_courses)
    else:
        return render_template('student_dashboard.html')

@app.route('/add_course', methods=['POST'])
@login_required
def add_course():
    if current_user.role != 'lecturer':
        flash('Unauthorized')
        return redirect(url_for('dashboard'))
    
    code = request.form.get('code')
    title = request.form.get('title')
    
    # Check if course code exists (e.g. prevent duplicate CSC201)
    existing = Course.query.filter_by(code=code).first()
    if existing:
        flash('Course code already exists!')
    else:
        new_course = Course(code=code, title=title, lecturer_id=current_user.id)
        db.session.add(new_course)
        db.session.commit()
        flash('Course created successfully!')
        
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

 #1. The Page the Lecturer Sees
@app.route('/api/qr_data/<int:course_id>')
@login_required
def get_qr_data(course_id):
    course = Course.query.get_or_404(course_id)
    if course.lecturer_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    # Generate the secret text
    timestamp = int(time.time()) 
    qr_text = f"{course_id}|{timestamp}"
    
    # Return it as JSON text
    return jsonify({"qr_text": qr_text})

# 2. The Image Generator (Called by the browser every 5 seconds)
@app.route('/course/<int:course_id>/live')
@login_required
def get_qr_image(course_id):
    # Security: Ensure only the lecturer can generate this
    course = Course.query.get_or_404(course_id)
    if course.lecturer_id != current_user.id:
        return "Unauthorized", 403

    # Generate a Time-Based Token (Valid for approx 30 seconds usually)
    # We use the Course Code as part of the secret so it's unique per course
    secret = pyotp.random_base32() # In a real app, store this constant secret in the DB per course!
    # For this MVP, we will generate a token based on current time
    
    # We create a simple data string: "COURSE_ID | TIMESTAMP"
    # This is what the student's phone will read
    import time
    timestamp = int(time.time()) 
    data = f"{course_id}|{timestamp}"
    
    # Create the QR Image
    img = qrcode.make(data)
    
    # Save it to a memory buffer (not disk)
    buf = io.BytesIO()
    img.save(buf, format="PNG") # <--- We explicitly say "Make this a PNG"
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

from flask import jsonify # Ensure this is imported at the top

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
    if course.lecturer_id != current_user.id:
        return redirect(url_for('dashboard'))
    
    records = Attendance.query.filter_by(course_id=course_id).order_by(Attendance.timestamp.desc()).all()
    return render_template('view_attendance.html', course=course, attendees=records)

@app.route('/course/<int:course_id>/download_csv')
@login_required
def download_csv(course_id):
    course = Course.query.get_or_404(course_id)
    if course.lecturer_id != current_user.id:
        return "Unauthorized", 403

    # Get records
    records = Attendance.query.filter_by(course_id=course_id).order_by(Attendance.timestamp.desc()).all()

    # Create the CSV in memory
    def generate():
        yield "Matric Number,Full Name,Level,Time Scanned,Device ID\n" # Header
        for record in records:
            # Format time nicely
            time_str = record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            yield f"{record.student.matric_no},{record.student.full_name},{record.student.level},{time_str},{record.device_id}\n"

    return Response(generate(), mimetype='text/csv', 
                    headers={"Content-Disposition": f"attachment;filename={course.code}_attendance.csv"})

@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Security: Ensure only the creator can delete it
    if course.lecturer_id != current_user.id:
        flash('Unauthorized Action!')
        return redirect(url_for('dashboard'))
    
    # 1. Delete all attendance records for this course (Clean up)
    Attendance.query.filter_by(course_id=course_id).delete()
    
    # 2. Delete the course itself
    db.session.delete(course)
    db.session.commit()
    
    flash(f'Course "{course.code}" has been deleted.')
    return redirect(url_for('dashboard'))

# --- SETUP COMMAND ---
# This block creates the database if you run this file directly
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # host='0.0.0.0' allows other devices on the network to connect
    app.run(host='0.0.0.0', port=5000, debug=True)
    # --- QR CODE GENERATOR LOGIC ---

#