"""End-to-end tests for the session-based attendance flow.

Tests run in file order and build on each other (signup → course → sessions →
scans → reports), mirroring one real semester of use. Each test logs in with
a FRESH client, and app contexts are opened only around direct DB access —
never around client requests (an outer app context makes Flask reuse it across
requests, leaking Flask-Login's per-request current_user cache).
"""
import re

from app import app as flask_app, db, serializer
from models import User, Course, Attendance, ClassSession

FUNAAB = (7.2233, 3.4403)      # lecturer's classroom
FAR_AWAY = (7.3200, 3.5400)    # ~15 km off campus

LECTURER = 'jagboola@staff.funaab.edu.ng'
ADA, BOLA, CHIDI = 'ada@gmail.com', 'bola@gmail.com', 'chidi@gmail.com'
HOD = 'hod@staff.funaab.edu.ng'

course_id = None
week1_id = None


def db_ctx():
    return flask_app.app_context()


def signup(email, name, **fields):
    c = flask_app.test_client()
    r = c.post('/signup', data={'full_name': name, 'email': email,
                                'password': 'secret123', **fields},
               follow_redirects=True)
    assert r.status_code == 200
    r = c.get(f"/verify_email/{serializer.dumps(email, salt='email-verify-salt')}",
              follow_redirects=True)
    assert b'verified' in r.data


def as_(email):
    """A fresh client logged in as the given user."""
    c = flask_app.test_client()
    r = c.post('/login', data={'email': email, 'password': 'secret123'})
    assert r.status_code == 302 and 'dashboard' in r.location, \
        f"login failed for {email}: {r.location}"
    return c


def scan(client, token, lat=None, lon=None, device_id=None):
    payload = {'qr_data': token}
    if lat is not None:
        payload.update(lat=lat, lon=lon)
    if device_id:
        payload['device_id'] = device_id
    return client.post('/mark_attendance', json=payload).get_json()


def qr_token(session_id):
    return as_(LECTURER).get(f'/api/qr_data/{session_id}').get_json()['qr_text']


# ── Signup, verification & debug-endpoint removal ──

def test_debug_endpoint_removed():
    assert flask_app.test_client().get('/test_signup').status_code == 404


def test_unverified_login_blocked():
    c = flask_app.test_client()
    r = c.post('/signup', data={'full_name': 'Pending User',
                                'email': 'pending@gmail.com',
                                'password': 'secret123',
                                'matric_no': '20239999', 'level': '100'},
               follow_redirects=True)
    assert b'verification link' in r.data
    r = c.post('/login', data={'email': 'pending@gmail.com',
                               'password': 'secret123'}, follow_redirects=True)
    assert b'verify your email' in r.data
    # After clicking the link, login works
    c.get(f"/verify_email/{serializer.dumps('pending@gmail.com', salt='email-verify-salt')}")
    r = c.post('/login', data={'email': 'pending@gmail.com',
                               'password': 'secret123'})
    assert r.status_code == 302 and 'student_dashboard' in r.location


def test_signups():
    signup(LECTURER, 'Dr John Agboola', staff_role='Course Coordinator')
    signup(ADA, 'Ada Student', matric_no='20230001', level='300')
    signup(BOLA, 'Bola Student', matric_no='20230002', level='300')
    signup(CHIDI, 'Chidi Student', matric_no='20230003', level='300')

    from werkzeug.security import generate_password_hash
    with db_ctx():
        db.session.add(User(full_name='Prof HOD', email=HOD,
                            password=generate_password_hash('secret123', method='scrypt'),
                            role='hod', email_verified=True))
        db.session.commit()
    as_(HOD)  # HOD can log in


def test_duplicate_matric_rejected():
    r = flask_app.test_client().post('/signup', data={
        'full_name': 'Imposter', 'email': 'imposter@gmail.com',
        'password': 'secret123', 'matric_no': '20230001'}, follow_redirects=True)
    assert b'already registered to another account' in r.data


# ── Course setup ──

def test_course_and_enrollment():
    global course_id
    r = as_(LECTURER).post('/add_course', data={'code': 'MTS 318',
                                                'title': 'Linear Manipulation'},
                           follow_redirects=True)
    assert b'MTS 318' in r.data
    with db_ctx():
        course = Course.query.filter_by(code='MTS 318').first()
        course_id = course.id
        assert course.current_semester  # stamped at creation

    for email in (ADA, BOLA, CHIDI):
        r = as_(email).post('/register_course', data={'course_code': 'MTS 318'},
                            follow_redirects=True)
        assert b'Successfully registered' in r.data


# ── Sessions & scanning ──

def test_start_session_resumes_same_day():
    global week1_id
    lect = as_(LECTURER)
    r = lect.post(f'/course/{course_id}/start_session')
    week1_id = int(re.search(r'/session/(\d+)/qr', r.location).group(1))
    r = lect.post(f'/course/{course_id}/start_session')
    assert int(re.search(r'/session/(\d+)/qr', r.location).group(1)) == week1_id
    with db_ctx():
        sess = db.session.get(ClassSession, week1_id)
        assert sess.semester == db.session.get(Course, course_id).current_semester


def test_scan_without_lecturer_location_is_unverified():
    j = scan(as_(ADA), qr_token(week1_id), device_id='device-A')
    assert j['status'] == 'success', j
    with db_ctx():
        rec = Attendance.query.filter_by(session_id=week1_id).first()
        assert rec.location_verified is False


def test_double_scan_rejected():
    j = scan(as_(ADA), qr_token(week1_id), device_id='device-A')
    assert j['status'] == 'error' and 'this class' in j['message']


def test_geofence():
    r = as_(LECTURER).post(f'/set_location/{course_id}',
                           json={'lat': FUNAAB[0], 'lon': FUNAAB[1]})
    assert r.get_json()['status'] == 'ok'

    bola = as_(BOLA)
    j = scan(bola, qr_token(week1_id), lat=FAR_AWAY[0], lon=FAR_AWAY[1],
             device_id='device-B')
    assert j['status'] == 'error' and 'Too far' in j['message'] and '100m' in j['message']

    j = scan(bola, qr_token(week1_id), lat=FUNAAB[0], lon=FUNAAB[1],
             device_id='device-B')
    assert j['status'] == 'success', j
    with db_ctx():
        rec = Attendance.query.join(User, Attendance.student_id == User.id) \
                              .filter(User.matric_no == '20230002').first()
        assert rec.location_verified is True


def test_shared_device_blocked():
    j = scan(as_(CHIDI), qr_token(week1_id), lat=FUNAAB[0], lon=FUNAAB[1],
             device_id='device-B')  # same phone as Bola
    assert j['status'] == 'error' and 'another student' in j['message']


def test_attendees_feed():
    lect = as_(LECTURER)
    j = lect.get(f'/api/session/{week1_id}/attendees').get_json()
    assert j['present'] == 2 and j['enrolled'] == 3          # Ada & Bola scanned
    assert j['showing'] == 2 and len(j['attendees']) == 2
    assert {a['matric_no'] for a in j['attendees']} == {'20230001', '20230002'}
    # Cheap "nothing changed" shortcut used by the projector's poll loop
    j = lect.get(f'/api/session/{week1_id}/attendees?known=2').get_json()
    assert j.get('unchanged') is True and 'attendees' not in j
    # Students can't read the feed
    assert as_(ADA).get(f'/api/session/{week1_id}/attendees').status_code == 403


def test_manual_mark_and_remove():
    lect = as_(LECTURER)
    r = lect.post(f'/session/{week1_id}/manual_mark',
                  data={'matric_no': '20230003'}, follow_redirects=True)
    assert b'manual entry' in r.data
    with db_ctx():
        rec = Attendance.query.join(User, Attendance.student_id == User.id) \
                              .filter(User.matric_no == '20230003').first()
        assert rec.marked_by == 'Dr John Agboola' and rec.device_id == 'manual'
        rec_id = rec.id

    # Unknown matric numbers are rejected cleanly
    r = lect.post(f'/session/{week1_id}/manual_mark',
                  data={'matric_no': '99999999'}, follow_redirects=True)
    assert b'No student found' in r.data

    r = lect.post(f'/attendance/{rec_id}/remove', follow_redirects=True)
    assert b'record removed' in r.data
    with db_ctx():
        assert db.session.get(Attendance, rec_id) is None


def test_rename_and_extra_session():
    lect = as_(LECTURER)
    r = lect.post(f'/session/{week1_id}/rename', data={'title': 'Week 1'},
                  follow_redirects=True)
    assert b'renamed' in r.data

    r = lect.post(f'/course/{course_id}/start_session', data={'extra': '1'})
    extra_id = int(re.search(r'/session/(\d+)/qr', r.location).group(1))
    assert extra_id != week1_id
    with db_ctx():
        assert db.session.get(ClassSession, week1_id).title == 'Week 1'
        assert '#2' in db.session.get(ClassSession, extra_id).title
    # Clean up so later counts stay predictable
    lect.post(f'/session/{extra_id}/delete')


# ── Records, CSV, analytics & who can see them ──

def test_records_page_flags():
    html = as_(LECTURER).get(f'/course/{course_id}/attendance').data.decode()
    assert 'Week 1' in html
    assert 'GPS ✓' in html and 'GPS —' in html  # verified and unverified scans


def test_hod_can_view_records_csv_and_analytics():
    hod = as_(HOD)
    assert hod.get(f'/course/{course_id}/attendance').status_code == 200
    assert hod.get(f'/course/{course_id}/download_csv').status_code == 200
    assert hod.get(f'/course/{course_id}/analytics').status_code == 200


def test_student_cannot_view_records():
    ada = as_(ADA)
    assert ada.get(f'/course/{course_id}/download_csv').status_code == 403
    assert ada.get(f'/course/{course_id}/analytics').status_code == 403


def test_register_csv():
    csv_text = as_(LECTURER).get(f'/course/{course_id}/download_csv').data.decode()
    lines = csv_text.strip().split('\n')
    assert lines[0].count('Week 1') == 1
    ada = next(l for l in lines if 'Ada' in l)
    assert '"1","1","100%"' in ada
    chidi = next(l for l in lines if 'Chidi' in l)
    assert '"Absent"' in chidi and '"0%"' in chidi


def test_single_session_csv():
    csv_text = as_(LECTURER).get(
        f'/course/{course_id}/download_csv?session_id={week1_id}').data.decode()
    assert 'GPS Verified' in csv_text
    assert '"Absent"' in csv_text  # absentees listed too


def test_analytics_at_risk():
    html = as_(LECTURER).get(f'/course/{course_id}/analytics').data.decode()
    assert 'Class Standing' in html
    assert 'At Risk' in html      # Chidi missed the only class
    assert 'On Track' in html     # Ada & Bola attended


def test_student_history_page():
    html = as_(CHIDI).get(f'/my/course/{course_id}/history').data.decode()
    assert 'Week 1' in html and 'Absent' in html
    html = as_(ADA).get(f'/my/course/{course_id}/history').data.decode()
    assert 'Present' in html


# ── Semester rollover ──

def test_semester_rollover():
    lect = as_(LECTURER)
    with db_ctx():
        old_sem = db.session.get(Course, course_id).current_semester
    r = lect.post(f'/course/{course_id}/new_semester',
                  data={'semester_name': '2026/2027 First Semester'},
                  follow_redirects=True)
    assert b'2026/2027 First Semester' in r.data

    with db_ctx():
        course = db.session.get(Course, course_id)
        assert course.current_semester == '2026/2027 First Semester'
        # Old sessions keep their original label
        assert db.session.get(ClassSession, week1_id).semester == old_sem

    # Fresh register: zero classes held in the new semester
    csv_text = lect.get(f'/course/{course_id}/download_csv').data.decode()
    assert 'Week 1' not in csv_text

    # Old semester still fully viewable
    csv_text = lect.get(
        f'/course/{course_id}/download_csv?semester={old_sem}').data.decode()
    assert 'Week 1' in csv_text

    # New sessions are stamped with the new semester and scans work
    r = lect.post(f'/course/{course_id}/start_session')
    new_id = int(re.search(r'/session/(\d+)/qr', r.location).group(1))
    with db_ctx():
        assert db.session.get(ClassSession, new_id).semester == '2026/2027 First Semester'
    j = scan(as_(ADA), qr_token(new_id), lat=FUNAAB[0], lon=FUNAAB[1],
             device_id='device-A')
    assert j['status'] == 'success', j


def test_roster_removal():
    with db_ctx():
        chidi_id = User.query.filter_by(matric_no='20230003').first().id
    r = as_(LECTURER).post(f'/course/{course_id}/remove_student/{chidi_id}',
                           follow_redirects=True)
    assert b'removed from' in r.data
    with db_ctx():
        students = db.session.get(Course, course_id).students
        assert chidi_id not in [s.id for s in students]
