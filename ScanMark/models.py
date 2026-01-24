from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# --- THE HIERARCHY LINK ---
# This table connects multiple lecturers to a single course
course_instructors = db.Table('course_instructors',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    # Roles: 'Student', 'Lecturer', 'Course Coordinator'
    role = db.Column(db.String(20), nullable=False) 
    
    # Student Specifics (Nullable for Staff)
    matric_no = db.Column(db.String(20), unique=True, nullable=True)
    level = db.Column(db.String(10), nullable=True)
    
    # Relationships
    attendance_records = db.relationship('Attendance', backref='student', lazy=True)
    
    # HIERARCHY:
    # 1. Courses I created (as Coordinator)
    coordinated_courses = db.relationship('Course', backref='coordinator', lazy=True)
    
    # 2. Courses I teach (as Invited Lecturer)
    teaching_courses = db.relationship('Course', secondary=course_instructors, backref=db.backref('instructors', lazy='dynamic'))

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False) # e.g. CSC201
    title = db.Column(db.String(100), nullable=False)
    
    # The Boss (Coordinator)
    coordinator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # The link to 'instructors' is handled by the backref in User
    attendance = db.relationship('Attendance', backref='course', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.String(100))