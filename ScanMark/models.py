from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone


def utcnow_naive():
    """UTC compatible with the existing timezone-naive database columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

db = SQLAlchemy()

enrollments = db.Table('enrollments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True),
    # The composite PK starts with user_id, so course-side lookups (enrolled
    # counts, class rosters) need their own index.
    db.Index('ix_enrollments_course_id', 'course_id')
)

# --- THE HIERARCHY LINK ---
# This table connects multiple lecturers to a single course
course_instructors = db.Table('course_instructors',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True),
    db.Index('ix_course_instructors_course_id', 'course_id')
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campos_user_id = db.Column(db.String(100), unique=True, nullable=True, index=True)
    campos_institution_id = db.Column(db.String(100), nullable=True, index=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # Self-service signup can claim any address, including a @staff address the
    # registrant does not own, so a password account stays unusable until the
    # address is confirmed. Deliberately nullable: rows that predate this column
    # read back as NULL and are treated as already-verified, so a migration
    # never locks an existing user out. Identity-provider logins (CampOS SSO,
    # Google) set it True outright — the provider already proved the address.
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
    date_created = db.Column(db.DateTime, default=utcnow_naive)

    # This relationship links the session to all the students who scanned it
    attendances = db.relationship('Attendance', backref='session', lazy=True, cascade="all, delete-orphan")

    # Session counts/lookups are always per course
    __table_args__ = (
        db.Index('ix_class_session_course_id', 'course_id'),
    )

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    # Nullable only for legacy rows created before sessions existed; the
    # startup backfill in app.py adopts those into per-day sessions.
    session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=utcnow_naive)
    device_id = db.Column(db.String(200), nullable=True)

    __table_args__ = (
        # One scan per student per class session, enforced by the database so
        # concurrent duplicate requests can't both slip past the app-level
        # check. Legacy rows with session_id NULL never collide (SQL NULLs
        # are distinct for unique-index purposes on SQLite and Postgres).
        db.Index('uq_attendance_student_session', 'student_id', 'session_id',
                 unique=True),
        # The live attendee feed filters on session_id; the per-student
        # course totals on the dashboard filter on (course_id, student_id).
        db.Index('ix_attendance_session_id', 'session_id'),
        db.Index('ix_attendance_session_cursor', 'session_id', 'id'),
        db.Index('ix_attendance_course_student', 'course_id', 'student_id'),
    )
