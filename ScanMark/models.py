from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

from academic import current_academic_year, current_semester
from localtime import utcnow_naive

db = SQLAlchemy()

enrollments = db.Table('enrollments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True),
    # When this student joined the course. Sessions held before they enrolled
    # are not theirs to miss, so the register needs the date, not just the
    # membership. Nullable because rows written before this column existed
    # cannot be dated after the fact.
    db.Column('enrolled_at', db.DateTime, nullable=True, default=utcnow_naive),
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

    # Which university this person belongs to, as the domain their address
    # sits under ('funaab.edu.ng', 'unilag.edu.ng'). One deployment serves
    # several, so this is what keeps one university's courses, rosters and
    # dashboards out of another's. Derived from the address at signup.
    #
    # Empty string rather than NULL — a personal-email account has none until
    # it registers for its first course, and NULL would take it out of the
    # matric uniqueness rule below entirely, because SQL treats every NULL as
    # distinct from every other.
    institution = db.Column(db.String(120), nullable=False, default='',
                            server_default='', index=True)
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

    # Rotating this invalidates every issued credential that names this user:
    # server-side session records, the signed session cookie and the 30-day
    # remember-me cookie all carry it (see User.get_id), so a password change
    # or a recovered account signs the other party out instead of leaving
    # their existing logins working. NULL means "never rotated" and matches
    # the empty stamp legacy cookies carry.
    security_stamp = db.Column(db.String(32), nullable=True)

    enrolled_courses = db.relationship('Course', secondary=enrollments, backref='students')

    # Roles: 'Student', 'Lecturer', 'Course Coordinator'
    role = db.Column(db.String(20), nullable=False)

# NEW: Links HODs/Lecturers to a Department (e.g., "Computer Science")
    department = db.Column(db.String(50), nullable=True)

    # Student Specifics (Nullable for Staff)
    # NOT globally unique: a matric number identifies a student within their
    # own university, and two universities' numbering formats can collide.
    # The rule lives in __table_args__ as (institution, matric_no).
    matric_no = db.Column(db.String(20), nullable=True)
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

    __table_args__ = (
        # One matric number per student, within one university. Staff rows
        # hold NULL and are exempt: SQL treats NULLs as distinct, so any
        # number of them coexist.
        db.UniqueConstraint('institution', 'matric_no',
                            name='uq_user_matric_per_institution'),
    )

    def get_id(self):
        """
        Identify the session by user AND security stamp.

        Flask-Login writes this string into the session record and into the
        remember-me cookie, and hands it back to the user loader on every
        request. Carrying the stamp is what lets a password reset revoke
        credentials that were issued before it.
        """
        return f"{self.id}|{self.security_stamp or ''}"

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # NOT globally unique: the same code runs again every term. What must be
    # unique is one OFFERING — this code, in this year, in this semester, for
    # this section (see __table_args__).
    code = db.Column(db.String(10), nullable=False, index=True) # e.g. CSC201
    title = db.Column(db.String(100), nullable=False)

    # --- The offering this course row IS ---
    academic_year = db.Column(db.String(9), nullable=False,
                              default=lambda: current_academic_year())
    semester = db.Column(db.String(20), nullable=False,
                         default=lambda: current_semester())
    # Parallel streams of the same course. Empty string rather than NULL so the
    # uniqueness rule below actually bites (SQL treats NULLs as distinct, so a
    # nullable column would let the same offering be created twice).
    section = db.Column(db.String(20), nullable=False, default='')
    # A finished term is kept for the record but drops out of the working
    # dashboards, reports and code-reuse checks.
    archived = db.Column(db.Boolean, nullable=False, default=False)
    archived_at = db.Column(db.DateTime, nullable=True)

    # The university this offering belongs to, inherited from its
    # coordinator. Empty string rather than NULL for the same reason as
    # `section`: SQL treats NULLs as distinct, so a nullable column would let
    # the uniqueness rule below stop biting on unassigned rows.
    institution = db.Column(db.String(120), nullable=False, default='',
                            server_default='', index=True)

# NEW: Links a course to a department so the HOD can see it
    department = db.Column(db.String(50), nullable=True)

    # The Boss (Coordinator)
    coordinator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # The link to 'instructors' is handled by the backref in User
    attendance = db.relationship('Attendance', backref='course', lazy=True)

    # NEW: Links a course to a faculty so the Dean can see it
    faculty = db.Column(db.String(50), nullable=True)

    __table_args__ = (
        # Institution is part of the key: CSC101 at FUNAAB and CSC101 at
        # UNILAG are different courses, and without it the second university
        # to create one this term is told it already exists.
        db.UniqueConstraint('code', 'institution', 'academic_year', 'semester',
                            'section', name='uq_course_offering'),
        db.Index('ix_course_term', 'academic_year', 'semester'),
    )

    @property
    def term_label(self):
        base = f"{self.academic_year} {self.semester} Semester"
        return f"{base} · Section {self.section}" if self.section else base

class Classroom(db.Model):
    """
    A lecture hall, pinned once and reused every term.

    The alternative was pinning from the browser at the start of every class,
    and the machine driving the projector is a laptop: no GPS, so the fix comes
    from Wi-Fi or the IP address and can land tens of kilometres away. Every
    student in the room is then told they are too far from it. A room's
    coordinates do not change between Monday and Friday, so they belong in the
    database, captured once from a device that can actually see satellites.

    Institution-scoped like Course and User: "LT1" exists at more or less every
    university, and one of them must not be able to see — or pin a class
    against — another's rooms.
    """
    id = db.Column(db.Integer, primary_key=True)
    institution = db.Column(db.String(120), nullable=False, default='',
                            server_default='', index=True)
    name = db.Column(db.String(80), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    # How precise the fix was when the room was pinned, in metres, or NULL for
    # a set of coordinates typed in by hand (a map has no error radius to
    # report). Kept so the list can flag a room that was pinned badly, rather
    # than leaving a lecturer to work that out from students being refused.
    accuracy_m = db.Column(db.Float, nullable=True)

    # How close a student's scan must land to these coordinates to mark
    # attendance here, in metres. NULL means "use the server default"
    # (GEOFENCE_RADIUS_M) — most rooms never touch this. A lecture theatre
    # with a fenced-off overflow gallery, or a room a lecturer has found
    # needs slack for GPS drift near thick walls, is why it is a knob at
    # all rather than a single fixed number.
    radius_m = db.Column(db.Float, nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)

    __table_args__ = (
        # One "LT1" per university. Two rooms with the same name are a mistake
        # somebody will make at the start of term, and the wrong one being
        # picked from the dropdown fails silently at scan time.
        db.UniqueConstraint('institution', 'name',
                            name='uq_classroom_name_per_institution'),
    )


class ClassSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)

    # Which saved room this meeting is being held in, when one was chosen.
    # The live pin lives in Redis (it expires with the class), but Redis is a
    # cache: a restart or an eviction mid-lecture would drop the pin and, with
    # GEOFENCE_REQUIRED on, refuse every remaining scan. Recording the room
    # here means the pin can always be rebuilt from the database.
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'),
                             nullable=True)
    classroom = db.relationship('Classroom')
    title = db.Column(db.String(100), nullable=False)  # e.g., "Week 1", "Makeup Class"
    # When the meeting was opened. Naive UTC, like every other timestamp here.
    date_created = db.Column(db.DateTime, default=utcnow_naive)

    # --- Lifecycle ---
    # A meeting is open until somebody ends it. While `active` is False no
    # token for this session is redeemable, whatever its age, which is what
    # makes "End Class" mean something on the server rather than in the
    # browser's address bar.
    active = db.Column(db.Boolean, nullable=False, default=True)
    ended_at = db.Column(db.DateTime, nullable=True)
    ended_by_id = db.Column(db.Integer, nullable=True)

    # Two lectures, a tutorial and a makeup class can all happen on one day.
    # `sequence` numbers them within their local calendar day so their titles
    # stay distinguishable.
    kind = db.Column(db.String(20), nullable=False, default='Lecture')
    sequence = db.Column(db.Integer, nullable=False, default=1)

    # This relationship links the session to all the students who scanned it
    attendances = db.relationship('Attendance', backref='session', lazy=True, cascade="all, delete-orphan")
    roster = db.relationship('SessionRoster', backref='session', lazy=True,
                             cascade="all, delete-orphan")

    # Session counts/lookups are always per course
    __table_args__ = (
        db.Index('ix_class_session_course_id', 'course_id'),
        db.Index('ix_class_session_course_active', 'course_id', 'active'),
    )

    @property
    def is_open(self):
        return bool(self.active) and self.ended_at is None


class SessionRoster(db.Model):
    """
    Who was expected at one class meeting, frozen when the meeting opened.

    Percentages have to be computed against the roster as it stood at the
    time. Counting today's enrolment against a session held last month means a
    student who enrolled yesterday is marked absent for classes that happened
    before they joined, and a student who left makes everyone else's history
    read above 100%. The snapshot is the denominator; it never moves again.
    """
    __tablename__ = 'session_roster'

    session_id = db.Column(db.Integer, db.ForeignKey('class_session.id'),
                           primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    # Denormalised so "classes this student was expected at, in this course"
    # is one indexed single-table count instead of a join per dashboard row.
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)

    __table_args__ = (
        db.Index('ix_session_roster_student_course', 'student_id', 'course_id'),
        db.Index('ix_session_roster_course', 'course_id'),
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

    # --- CampOS delivery, as a transactional outbox ---
    #
    # The scan is the record; carrying it into CampOS is a separate,
    # optional, and FALLIBLE step. It used to live only in an in-process
    # thread pool, which meant three ways to lose it silently: the queue was
    # full, the delivery raised and was logged, or the process was replaced
    # mid-lecture by a deploy. Nothing anywhere remembered that a scan still
    # owed CampOS a record, so "did every attendance reach CampOS?" was not a
    # question the system could answer, let alone fix.
    #
    # Making the intent part of the same INSERT that records the attendance
    # is what fixes that, and it is free: no extra statement, no extra round
    # trip, nothing added to the request. The row itself is the queue, so it
    # survives a restart, a rolling deploy and a crash, and any instance can
    # pick up work any other instance dropped.
    #
    #   'skipped' — CampOS is not configured; nothing is owed
    #   'pending' — owed, and eligible from campos_next_attempt_at
    #   'sent'    — delivered
    #   'failed'  — dead-lettered after CAMPOS_MAX_ATTEMPTS; needs a human
    campos_state = db.Column(db.String(10), nullable=False, default='skipped',
                             server_default='skipped')
    campos_attempts = db.Column(db.Integer, nullable=False, default=0,
                                server_default='0')
    campos_next_attempt_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        # One scan per student per class session, enforced by the database so
        # concurrent duplicate requests can't both slip past the app-level
        # check. Legacy rows with session_id NULL never collide (SQL NULLs
        # are distinct for unique-index purposes on SQLite and Postgres).
        db.Index('uq_attendance_student_session', 'student_id', 'session_id',
                 unique=True),
        # The sweeper's claim query. PARTIAL on purpose: in a healthy system
        # essentially every row is 'sent', so a full index over the state
        # column would be almost entirely dead weight that every attendance
        # INSERT still has to maintain. This one only ever holds the rows
        # that are actually owed, so it stays small enough to be resident
        # however large the attendance table grows.
        db.Index('ix_attendance_campos_outbox', 'campos_next_attempt_at',
                 postgresql_where=db.text("campos_state = 'pending'"),
                 sqlite_where=db.text("campos_state = 'pending'")),
        # The live attendee feed filters on session_id; the per-student
        # course totals on the dashboard filter on (course_id, student_id).
        db.Index('ix_attendance_session_id', 'session_id'),
        db.Index('ix_attendance_session_cursor', 'session_id', 'id'),
        db.Index('ix_attendance_course_student', 'course_id', 'student_id'),
    )


class AuditLog(db.Model):
    """
    Append-only record of who destroyed what.

    Deliberately carries NO foreign keys: the whole point is to outlive the
    rows it describes, and a FK to course.id would either block the delete it
    is recording or be cascaded away with it. Nothing in the application ever
    updates or deletes a row here.
    """
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)

    actor_id = db.Column(db.Integer, nullable=True)
    actor_email = db.Column(db.String(120), nullable=True)
    actor_role = db.Column(db.String(20), nullable=True)

    action = db.Column(db.String(50), nullable=False)
    target_type = db.Column(db.String(50), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    # Which course the action concerned, so the per-course trail is an indexed
    # lookup rather than a LIKE over the JSON blob below. A plain integer, not
    # a foreign key: the entry has to outlive the course it names.
    course_id = db.Column(db.Integer, nullable=True)
    # A readable name for something that no longer exists to be looked up.
    target_label = db.Column(db.String(200), nullable=True)
    # JSON blob of whatever context the action needs (row counts, term, etc).
    details = db.Column(db.Text, nullable=True)

    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)

    __table_args__ = (
        db.Index('ix_audit_log_created_at', 'created_at'),
        db.Index('ix_audit_log_target', 'target_type', 'target_id'),
        db.Index('ix_audit_log_actor', 'actor_id'),
        db.Index('ix_audit_log_course', 'course_id', 'created_at'),
    )
