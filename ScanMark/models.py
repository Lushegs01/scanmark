from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

enrollments = db.Table('enrollments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True)
)

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

    # Set once the signup email link is clicked (SSO/Google users are
    # auto-verified since the identity provider already owns the email).
    email_verified = db.Column(db.Boolean, default=False)

    enrolled_courses = db.relationship('Course', secondary=enrollments, backref='students')
    
    # Roles: 'Student', 'Lecturer', 'Course Coordinator'
    role = db.Column(db.String(20), nullable=False) 
    
# NEW: Links HODs/Lecturers to a Department (e.g., "Computer Science")
    department = db.Column(db.String(50), nullable=True)

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

# NEW: Links HODs/Lecturers to a Faculty (e.g., "Physical Sciences")
    faculty = db.Column(db.String(50), nullable=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False) # e.g. CSC201
    title = db.Column(db.String(100), nullable=False)

    # The semester currently being taught (e.g. "2025/2026 First Semester").
    # Class sessions are stamped with it, so a course re-offered next year
    # starts a clean record set instead of inheriting old cohorts' data.
    current_semester = db.Column(db.String(50), nullable=True)

# NEW: Links a course to a department so the HOD can see it
    department = db.Column(db.String(50), nullable=True)

    # The Boss (Coordinator)
    coordinator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # The link to 'instructors' is handled by the backref in User
    attendance = db.relationship('Attendance', backref='course', lazy=True)

    # NEW: Links a course to a faculty so the Dean can see it
    faculty = db.Column(db.String(50), nullable=True)

class ClassSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)  # e.g., "Week 1", "Makeup Class"
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Stamped from Course.current_semester when the session is opened, so
    # records/analytics can be scoped to one academic semester.
    semester = db.Column(db.String(50), nullable=True)

    # This relationship links the session to all the students who scanned it
    attendances = db.relationship('Attendance', backref='session', lazy=True, cascade="all, delete-orphan")

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    # Nullable only for legacy rows created before sessions existed; the
    # startup backfill in app.py adopts those into per-day sessions.
    session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.String(200), nullable=True)

    # True only when the scan passed the GPS distance check; False means the
    # lecturer had no live location set, so the scan location is unverified.
    location_verified = db.Column(db.Boolean, default=False)

    # Lecturer's name when the record was added manually (phone died, etc.)
    # instead of via a QR scan. NULL for normal scans.
    marked_by = db.Column(db.String(100), nullable=True)

    # A student can only be marked once per class meeting (the app checks
    # first; this makes concurrent double-scans impossible at the DB level).
    __table_args__ = (
        db.UniqueConstraint('student_id', 'session_id', name='uq_attendance_student_session'),
    )


class NotificationPreference(db.Model):
    """Per-user notification settings for alerts and reports."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)

    # WhatsApp
    phone_number = db.Column(db.String(20), nullable=True)  # e.g. +2348012345678
    whatsapp_alerts = db.Column(db.Boolean, default=False)

    # Email
    email_alerts = db.Column(db.Boolean, default=True)

    # Weekly PDF reports
    weekly_report = db.Column(db.Boolean, default=True)

    # Early-warning threshold (percentage)
    warning_threshold = db.Column(db.Integer, default=75)

    # ── Parent / Guardian ──
    parent_name = db.Column(db.String(100), nullable=True)
    parent_email = db.Column(db.String(120), nullable=True)
    parent_phone = db.Column(db.String(20), nullable=True)   # e.g. +2348098765432
    notify_parent = db.Column(db.Boolean, default=False)      # master toggle

    # Relationship back to user
    user = db.relationship('User', backref=db.backref('notification_pref', uselist=False))


class WeeklyReport(db.Model):
    """Tracks sent weekly reports to avoid duplicates."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    week_start = db.Column(db.Date, nullable=False)
    week_end = db.Column(db.Date, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_type = db.Column(db.String(20), nullable=False)  # 'student' or 'lecturer'