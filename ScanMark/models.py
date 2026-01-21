from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin # Needed for session management
from datetime import datetime

db = SQLAlchemy()

# 1. The User Table
class User(UserMixin, db.Model): # Inherit UserMixin for Flask-Login
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' or 'lecturer'
    
    # Student Specifics
    matric_no = db.Column(db.String(20), unique=True, nullable=True)
    department = db.Column(db.String(50), nullable=True)
    level = db.Column(db.String(10), nullable=True) # Added this! (e.g., "400L")
    
    attendance_records = db.relationship('Attendance', backref='student', lazy=True)

# 2. The Course Table
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    lecturer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attendances = db.relationship('Attendance', backref='course', lazy=True)

# 3. The Attendance Log
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.String(100))