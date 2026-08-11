"""
Route-level tests for ScanMark.

Every bug this suite was written for shipped to main because nothing ever
executed app.py. The first class below is the cheap generic guard that would
have caught all six undefined names on its own; the rest pin down the specific
behaviours that were wrong.
"""
import time

import pytest

from conftest import VALID_PASSWORD, qr_token


# ============================================================
# THE GENERIC GUARD
# ============================================================

class TestNoRouteExplodes:
    """
    Undefined names (selectinload, joinedload, json, enrollments, IntegrityError,
    event) sat in main because no test ever executed the lines holding them.
    Walking every GET route and asserting it does not 500 is what catches that
    class of mistake regardless of which name goes missing next.
    """

    def test_every_get_route_responds_without_a_server_error(self, appmod, seed, login):
        c = login(seed['coordinator_email'])
        skip = {'static', 'serve_sw', 'logout'}
        checked = []

        for rule in appmod.app.url_map.iter_rules():
            if rule.endpoint in skip or 'GET' not in rule.methods:
                continue
            args = {}
            for arg in rule.arguments:
                if arg.endswith('course_id'):
                    args[arg] = seed['course_id']
                elif arg.endswith('session_id'):
                    args[arg] = seed['session_id']
                elif arg == 'token':
                    args[arg] = 'not-a-real-token'
                else:
                    args[arg] = 1
            with appmod.app.test_request_context():
                from flask import url_for
                path = url_for(rule.endpoint, **args)
            response = c.get(path, follow_redirects=False)
            checked.append((path, response.status_code))
            assert response.status_code < 500, f"{path} returned {response.status_code}"

        assert len(checked) > 15, f"expected to walk the whole map, saw {checked}"

    def test_the_lecturer_can_actually_read_and_export_attendance(self, appmod, seed, login):
        """
        The three endpoints that were 500ing: without them a class can scan all
        day and the lecturer never sees a single name.
        """
        student = login(seed['student_email'])
        student.post('/mark_attendance',
                     json={'qr_data': qr_token(appmod, seed['session_id'])})

        lecturer = login(seed['coordinator_email'])

        feed = lecturer.get(f"/api/session/{seed['session_id']}/attendees")
        assert feed.status_code == 200
        payload = feed.get_json()
        assert payload['present'] == 1
        assert payload['enrolled'] == 1
        # The feed is cursor-based: each poll returns only rows newer than
        # `after`, so a first poll carries the whole roll call in new_attendees.
        assert payload['new_attendees'][0]['matric_no'] == '20200001'
        assert payload['has_more'] is False

        page = lecturer.get(f"/course/{seed['course_id']}/attendance")
        assert page.status_code == 200
        assert b'Kemi Student' in page.data

        register = lecturer.get(f"/course/{seed['course_id']}/download_csv")
        assert register.status_code == 200
        assert b'20200001' in register.data
        assert b'Attendance %' in register.data

        sheet = lecturer.get(
            f"/course/{seed['course_id']}/download_csv?session_id={seed['session_id']}")
        assert sheet.status_code == 200
        assert b'Present' in sheet.data

    def test_weekly_reports_run_and_dedupe(self, appmod, seed):
        """run_weekly_reports() died on its first aggregate query."""
        from models import db, NotificationPreference, WeeklyReport

        with appmod.app.app_context():
            db.session.add(NotificationPreference(
                user_id=seed['student_id'], weekly_report=True, email_alerts=True))
            db.session.commit()

            appmod.run_weekly_reports()
            first = WeeklyReport.query.count()
            assert first >= 1

            # Second run in the same week must not re-send.
            appmod.run_weekly_reports()
            assert WeeklyReport.query.count() == first


# ============================================================
# SIGNUP: ROLE ESCALATION, CSRF, VERIFICATION
# ============================================================

class TestSignupCannotMintPrivilege:

    @pytest.mark.parametrize('requested', ['dap', 'dean', 'hod', 'DAP', 'Dean',
                                           'admin', 'super_admin', 'Course Coordinator; dap'])
    def test_a_staff_address_cannot_choose_a_privileged_role(
            self, appmod, client, requested):
        """
        `final_role = staff_role` took the form value verbatim, so posting
        staff_role=dap minted an account that reads every course's attendance
        in the institution.
        """
        from models import User

        response = client.post('/signup', data={
            'full_name': 'Mallory', 'email': 'mallory@staff.funaab.edu.ng',
            'password': VALID_PASSWORD, 'staff_role': requested,
        })
        assert response.status_code == 200   # re-rendered form, not a redirect

        with appmod.app.app_context():
            assert User.query.filter_by(email='mallory@staff.funaab.edu.ng').first() is None

    @pytest.mark.parametrize('requested,stored', [
        ('Lecturer', 'Lecturer'),
        ('lecturer', 'Lecturer'),
        ('Course Coordinator', 'Course Coordinator'),
        ('course coordinator', 'Course Coordinator'),
    ])
    def test_the_two_self_service_staff_roles_still_work(
            self, appmod, client, requested, stored):
        from models import User

        client.post('/signup', data={
            'full_name': 'Real Staff', 'email': 'real@staff.funaab.edu.ng',
            'password': VALID_PASSWORD, 'staff_role': requested,
        })
        with appmod.app.app_context():
            user = User.query.filter_by(email='real@staff.funaab.edu.ng').first()
            assert user is not None
            assert user.role == stored

    def test_a_staff_address_must_choose_a_role(self, appmod, client):
        from models import User
        client.post('/signup', data={
            'full_name': 'No Role', 'email': 'norole@staff.funaab.edu.ng',
            'password': VALID_PASSWORD,
        })
        with appmod.app.app_context():
            assert User.query.filter_by(email='norole@staff.funaab.edu.ng').first() is None

    def test_signup_requires_a_csrf_token(self, appmod):
        """The route carried @csrf.exempt 'temporarily, for debugging'."""
        from models import User

        appmod.app.config['WTF_CSRF_ENABLED'] = True
        try:
            c = appmod.app.test_client()
            response = c.post('/signup', data={
                'full_name': 'No Token', 'email': 'notoken@student.funaab.edu.ng',
                'password': VALID_PASSWORD,
            })
            assert response.status_code == 400
            with appmod.app.app_context():
                assert User.query.filter_by(
                    email='notoken@student.funaab.edu.ng').first() is None
        finally:
            appmod.app.config['WTF_CSRF_ENABLED'] = False

    def test_the_signup_form_actually_ships_a_usable_csrf_token(self, appmod):
        """
        The form had no csrf_token field while CSRFProtect was global, so
        every real registration got 400 and nobody could create an account.
        The suite could not see it: conftest turns CSRF off. This test turns
        it back on and drives the form the way a browser does.
        """
        import re
        from models import User

        appmod.app.config['WTF_CSRF_ENABLED'] = True
        try:
            c = appmod.app.test_client()
            page = c.get('/signup')
            assert page.status_code == 200
            match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
            assert match, 'signup.html renders no csrf_token field'

            response = c.post('/signup', data={
                'csrf_token': match.group(1).decode(),
                'full_name': 'Real Person',
                'email': 'realperson@student.funaab.edu.ng',
                'password': VALID_PASSWORD,
                'matric_no': '20200099',
                'level': '300',
            })
            assert response.status_code in (200, 302), response.status_code
            with appmod.app.app_context():
                assert User.query.filter_by(
                    email='realperson@student.funaab.edu.ng').first() is not None
        finally:
            appmod.app.config['WTF_CSRF_ENABLED'] = False

    def test_signup_survives_sending_the_verification_email(self, appmod):
        """
        send_verification_email() referenced a pool name that no longer
        existed, so signup raised NameError AFTER committing the user — an
        account that existed but could never be confirmed or signed into.
        """
        from models import User

        appmod.REQUIRE_EMAIL_VERIFICATION = True
        try:
            c = appmod.app.test_client()
            response = c.post('/signup', data={
                'full_name': 'Needs Confirming',
                'email': 'confirmme@student.funaab.edu.ng',
                'password': VALID_PASSWORD,
                'matric_no': '20200098', 'level': '300',
            }, follow_redirects=False)
            assert response.status_code != 500
            with appmod.app.app_context():
                user = User.query.filter_by(
                    email='confirmme@student.funaab.edu.ng').first()
                assert user is not None and user.email_verified is False
        finally:
            appmod.REQUIRE_EMAIL_VERIFICATION = False

    def test_signup_is_rate_limited_per_network(self, appmod):
        """Only the 1000/minute default stood between one host and bulk accounts."""
        appmod.limiter.enabled = True
        try:
            c = appmod.app.test_client()
            codes = []
            for n in range(8):
                r = c.post('/signup', data={
                    'full_name': f'Bulk {n}', 'email': f'bulk{n}@student.funaab.edu.ng',
                    'password': VALID_PASSWORD,
                })
                codes.append(r.status_code)
            assert 429 in codes, codes
        finally:
            appmod.limiter.enabled = False
            appmod.limiter.reset()


class TestEmailVerification:

    def test_an_unconfirmed_account_cannot_sign_in(self, appmod, client):
        from models import db, User

        appmod.REQUIRE_EMAIL_VERIFICATION = True
        try:
            client.post('/signup', data={
                'full_name': 'Pending', 'email': 'pending@student.funaab.edu.ng',
                'password': VALID_PASSWORD,
            })
            with appmod.app.app_context():
                user = User.query.filter_by(email='pending@student.funaab.edu.ng').first()
                assert user.email_verified is False

            c = appmod.app.test_client()
            response = c.post('/login', data={'email': 'pending@student.funaab.edu.ng',
                                              'password': VALID_PASSWORD})
            assert response.status_code == 200            # stayed on the login page
            assert b'confirm your email' in response.data.lower()

            # The dashboard is still closed to them.
            assert c.get('/student_dashboard').status_code == 302

            with appmod.app.app_context():
                token = appmod.serializer.dumps(user.email, salt='email-verify-salt')
            assert c.get(f'/verify_email/{token}').status_code == 302
            with appmod.app.app_context():
                assert db.session.get(User, user.id).email_verified is True

            response = c.post('/login', data={'email': 'pending@student.funaab.edu.ng',
                                              'password': VALID_PASSWORD})
            assert response.status_code == 302
        finally:
            appmod.REQUIRE_EMAIL_VERIFICATION = False

    def test_a_bad_verification_token_is_refused(self, client):
        response = client.get('/verify_email/rubbish', follow_redirects=True)
        assert response.status_code == 200
        assert b'invalid or has expired' in response.data

    def test_legacy_rows_with_no_flag_are_treated_as_verified(self, appmod, seed):
        """A migration must never lock out someone who could sign in yesterday."""
        from models import db, User

        appmod.REQUIRE_EMAIL_VERIFICATION = True
        try:
            with appmod.app.app_context():
                user = db.session.get(User, seed['student_id'])
                user.email_verified = None          # what the pre-migration row reads as
                db.session.commit()

            c = appmod.app.test_client()
            response = c.post('/login', data={'email': seed['student_email'],
                                              'password': VALID_PASSWORD})
            assert response.status_code == 302
        finally:
            appmod.REQUIRE_EMAIL_VERIFICATION = False

    def test_sso_retires_the_password_on_an_unconfirmed_squatted_account(
            self, appmod, seed):
        """
        Somebody can register an address they do not own. If the real owner
        later arrives through CampOS, adopting the row as-is would leave the
        squatter's password working.
        """
        from models import db, User
        from werkzeug.security import check_password_hash

        with appmod.app.app_context():
            squatted = User(full_name='Squatter', email='victim@staff.funaab.edu.ng',
                            password=appmod.generate_password_hash('squatter-pw-1',
                                                                   method='scrypt'),
                            role='Lecturer', email_verified=False)
            db.session.add(squatted)
            db.session.commit()
            squatted_id = squatted.id

            # What campos_sso_callback does when it adopts the row.
            user = db.session.get(User, squatted_id)
            if user.email_verified is False:
                user.password = appmod.generate_password_hash(
                    appmod.secrets.token_hex(32), method='scrypt')
            user.email_verified = True
            db.session.commit()

            refreshed = db.session.get(User, squatted_id)
            assert not check_password_hash(refreshed.password, 'squatter-pw-1')


class TestGoogleOAuthCallback:

    def test_an_interrupted_round_trip_lands_on_login_not_a_500(self, client):
        """
        A stale state cookie, a back button, or someone opening the callback
        directly all raise out of authlib. Unhandled that is a 500 on a route
        real users land on.
        """
        response = client.get('/authorize/google', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']

    def test_an_unconfirmed_google_address_is_refused(self, appmod, monkeypatch):
        from models import User

        monkeypatch.setattr(appmod.google, 'authorize_access_token',
                            lambda: {'userinfo': {'email': 'nope@gmail.com',
                                                  'name': 'Nope',
                                                  'email_verified': False}})
        c = appmod.app.test_client()
        response = c.get('/authorize/google', follow_redirects=False)
        assert response.status_code == 302
        with appmod.app.app_context():
            assert User.query.filter_by(email='nope@gmail.com').first() is None

    def test_a_confirmed_google_address_signs_in_pre_verified(self, appmod, monkeypatch):
        from models import User

        monkeypatch.setattr(appmod.google, 'authorize_access_token',
                            lambda: {'userinfo': {'email': 'new@gmail.com',
                                                  'name': 'New Person',
                                                  'email_verified': True}})
        c = appmod.app.test_client()
        assert c.get('/authorize/google').status_code == 302
        with appmod.app.app_context():
            user = User.query.filter_by(email='new@gmail.com').first()
            assert user is not None
            assert user.email_verified is True
            assert user.role == 'student'


class TestPasswordPolicy:

    @pytest.mark.parametrize('password', ['short1', 'abcdefghijkl', '123456789012'])
    def test_weak_passwords_are_refused_at_signup(self, appmod, client, password):
        from models import User
        client.post('/signup', data={
            'full_name': 'Weak', 'email': 'weak@student.funaab.edu.ng',
            'password': password,
        })
        with appmod.app.app_context():
            assert User.query.filter_by(email='weak@student.funaab.edu.ng').first() is None

    def test_reset_enforces_the_same_policy(self, appmod, seed):
        with appmod.app.app_context():
            token = appmod.serializer.dumps(
                {'email': seed['student_email'],
                 'pw': appmod._password_fingerprint(
                     __import__('models').User.query.get(seed['student_id']).password)},
                salt='password-reset-salt')

        c = appmod.app.test_client()
        response = c.post(f'/reset_password/{token}', data={'password': 'weak'})
        assert response.status_code == 200
        assert b'at least' in response.data

    def test_a_reset_link_works_once(self, appmod, seed):
        """
        The old token named only an email and stayed live for its whole
        15-minute window, so the same link could be replayed.
        """
        from models import db, User
        from werkzeug.security import check_password_hash

        with appmod.app.app_context():
            user = db.session.get(User, seed['student_id'])
            token = appmod.serializer.dumps(
                {'email': user.email, 'pw': appmod._password_fingerprint(user.password)},
                salt='password-reset-salt')

        c = appmod.app.test_client()
        first = c.post(f'/reset_password/{token}', data={'password': 'first-change-1'})
        assert first.status_code == 302
        with appmod.app.app_context():
            assert check_password_hash(
                db.session.get(User, seed['student_id']).password, 'first-change-1')

        # Replaying the same link must not take.
        second = c.post(f'/reset_password/{token}', data={'password': 'second-change-2'},
                        follow_redirects=True)
        assert b'invalid or has expired' in second.data
        with appmod.app.app_context():
            assert check_password_hash(
                db.session.get(User, seed['student_id']).password, 'first-change-1')

    def test_forgot_password_does_not_reveal_whether_an_account_exists(self, client):
        known = client.post('/forgot_password', data={'email': 'kemi@student.funaab.edu.ng'},
                            follow_redirects=True)
        unknown = client.post('/forgot_password', data={'email': 'nobody@student.funaab.edu.ng'},
                              follow_redirects=True)
        assert b'If an account with that email exists' in known.data
        assert b'If an account with that email exists' in unknown.data


class TestEmailDomainRules:

    @pytest.mark.parametrize('email,role', [
        ('a@funaab.edu.ng', 'student'),
        ('b@student.funaab.edu.ng', 'student'),      # the address most students hold
        ('c@gmail.com', 'student'),
        ('d@staff.funaab.edu.ng', 'lecturer'),
    ])
    def test_accepted_domains(self, appmod, email, role):
        valid, _message, default_role = appmod.is_valid_funaab_email(email)
        assert valid is True
        assert default_role == role

    @pytest.mark.parametrize('email', [
        'e@evilfunaab.edu.ng',        # lookalike domain
        'f@funaab.edu.ng.attacker.com',
        'g@example.com',
        'not-an-email',
        '',
    ])
    def test_rejected_domains(self, appmod, email):
        valid, _message, _role = appmod.is_valid_funaab_email(email)
        assert valid is False


# ============================================================
# ACCESS CONTROL
# ============================================================

class TestCourseAccessControl:

    def test_a_coordinator_cannot_join_a_course_they_do_not_own(self, appmod, seed, login):
        """
        add_instructor only checked that you HELD the coordinator role, so any
        coordinator could add themselves to someone else's course and inherit
        its roster, its live QR tokens and its attendance register.
        """
        eve = login(seed['outsider_email'])

        assert eve.get(f"/api/course/{seed['course_id']}/enrolled_students").status_code == 403

        eve.post('/add_instructor', data={'course_id': seed['course_id'],
                                          'lecturer_email': seed['outsider_email']})

        assert eve.get(f"/api/course/{seed['course_id']}/enrolled_students").status_code == 403
        assert eve.get(f"/api/qr_data/{seed['session_id']}").status_code == 403
        assert eve.get(f"/course/{seed['course_id']}/download_csv").status_code == 403

    def test_the_real_coordinator_can_still_add_an_instructor(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        ada.post('/add_instructor', data={'course_id': seed['course_id'],
                                          'lecturer_email': seed['lecturer_email']})

        grace = login(seed['lecturer_email'])
        assert grace.get(f"/api/course/{seed['course_id']}/enrolled_students").status_code == 200
        assert grace.get(f"/api/qr_data/{seed['session_id']}").status_code == 200

    def test_a_student_cannot_be_added_as_an_instructor(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        ada.post('/add_instructor', data={'course_id': seed['course_id'],
                                          'lecturer_email': seed['student_email']})
        kemi = login(seed['student_email'])
        assert kemi.get(f"/api/qr_data/{seed['session_id']}").status_code == 403

    def test_a_student_cannot_create_a_course(self, appmod, seed, login):
        from models import Course
        kemi = login(seed['student_email'])
        kemi.post('/add_course', data={'code': 'FAKE101', 'title': 'Mine Now'})
        with appmod.app.app_context():
            assert Course.query.filter_by(code='FAKE101').first() is None

    def test_a_lecturer_cannot_create_a_course(self, appmod, seed, login):
        from models import Course
        grace = login(seed['lecturer_email'])
        grace.post('/add_course', data={'code': 'FAKE102', 'title': 'Mine Now'})
        with appmod.app.app_context():
            assert Course.query.filter_by(code='FAKE102').first() is None

    def test_a_coordinator_can_create_a_course(self, appmod, seed, login):
        from models import Course
        ada = login(seed['coordinator_email'])
        ada.post('/add_course', data={'code': 'CSC301', 'title': 'Algorithms'})
        with appmod.app.app_context():
            assert Course.query.filter_by(code='CSC301').first() is not None

    def test_duplicate_course_codes_are_refused(self, appmod, seed, login):
        from models import Course
        ada = login(seed['coordinator_email'])
        ada.post('/add_course', data={'code': 'CSC201', 'title': 'Clashing Code'})
        with appmod.app.app_context():
            assert Course.query.filter_by(code='CSC201').count() == 1

    def test_staff_cannot_enrol_themselves_as_students(self, appmod, seed, login):
        from models import db, User
        grace = login(seed['lecturer_email'])
        grace.post('/register_course', data={'course_code': 'CSC201'})
        with appmod.app.app_context():
            assert db.session.get(User, seed['lecturer_id']).enrolled_courses == []

    def test_only_the_creator_can_delete_a_course(self, appmod, seed, login):
        from models import Course
        eve = login(seed['outsider_email'])
        eve.post(f"/delete_course/{seed['course_id']}")
        with appmod.app.app_context():
            assert Course.query.get(seed['course_id']) is not None


class TestSupervisoryAccess:

    def _promote(self, appmod, user_id, role, department=None, faculty=None):
        from models import db, User
        with appmod.app.app_context():
            user = db.session.get(User, user_id)
            user.role = role
            user.department = department
            user.faculty = faculty
            db.session.commit()

    def test_an_hod_reads_only_their_own_department(self, appmod, seed, login):
        self._promote(appmod, seed['outsider_id'], 'hod', department='Computer Science')
        hod = login(seed['outsider_email'])
        assert hod.get(f"/course/{seed['course_id']}/attendance").status_code == 200

        self._promote(appmod, seed['outsider_id'], 'hod', department='Physics')
        hod = login(seed['outsider_email'])
        assert hod.get(f"/course/{seed['course_id']}/attendance").status_code == 302

    def test_an_hod_with_no_department_matches_nothing(self, appmod, seed, login):
        """A NULL department must not silently match a NULL course department."""
        from models import db, Course
        with appmod.app.app_context():
            course = db.session.get(Course, seed['course_id'])
            course.department = None
            db.session.commit()

        self._promote(appmod, seed['outsider_id'], 'hod', department=None)
        hod = login(seed['outsider_email'])
        assert hod.get(f"/course/{seed['course_id']}/attendance").status_code == 302

    def test_a_dean_reads_only_their_own_faculty(self, appmod, seed, login):
        self._promote(appmod, seed['outsider_id'], 'dean', faculty='Physical Sciences')
        dean = login(seed['outsider_email'])
        assert dean.get(f"/course/{seed['course_id']}/attendance").status_code == 200

        self._promote(appmod, seed['outsider_id'], 'dean', faculty='Arts')
        dean = login(seed['outsider_email'])
        assert dean.get(f"/course/{seed['course_id']}/attendance").status_code == 302

    def test_a_dap_reads_across_the_institution(self, appmod, seed, login):
        self._promote(appmod, seed['outsider_id'], 'dap')
        dap = login(seed['outsider_email'])
        assert dap.get(f"/course/{seed['course_id']}/attendance").status_code == 200
        assert dap.get(f"/course/{seed['course_id']}/download_csv").status_code == 200

    def test_a_student_cannot_reach_a_staff_dashboard(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        for path in ('/lecturer_dashboard', '/hod_dashboard', '/dean_dashboard',
                     '/dap_dashboard', '/dap_analytics', '/hod_analytics'):
            assert kemi.get(path).status_code == 302, path

    def test_an_anonymous_visitor_is_sent_to_login(self, client, seed):
        for path in ('/student_dashboard', '/dap_dashboard',
                     f"/course/{seed['course_id']}/attendance",
                     f"/api/session/{seed['session_id']}/attendees"):
            assert client.get(path).status_code in (302, 401), path


# ============================================================
# THE SCAN PATH
# ============================================================

class TestScanning:

    def test_a_happy_scan_is_recorded_once(self, appmod, seed, login):
        from models import Attendance
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert response.get_json()['status'] == 'success'
        with appmod.app.app_context():
            assert Attendance.query.count() == 1

    def test_a_second_scan_is_refused_politely(self, appmod, seed, login):
        from models import Attendance
        kemi = login(seed['student_email'])
        token = qr_token(appmod, seed['session_id'])
        kemi.post('/mark_attendance', json={'qr_data': token})
        response = kemi.post('/mark_attendance', json={'qr_data': token})
        body = response.get_json()
        assert body['status'] == 'error'
        assert 'already marked present' in body['message']
        with appmod.app.app_context():
            assert Attendance.query.count() == 1

    def test_concurrent_duplicates_leave_exactly_one_row(self, appmod, seed):
        """
        The database unique index is the real guard. IntegrityError was never
        imported, so the handler for it raised NameError and the student saw
        'An unexpected server error occurred' while actually being marked
        present — a message that invites them to scan again.
        """
        from concurrent.futures import ThreadPoolExecutor
        from models import Attendance

        token = qr_token(appmod, seed['session_id'])

        def scan(_):
            c = appmod.app.test_client()
            c.post('/login', data={'email': seed['student_email'],
                                   'password': VALID_PASSWORD})
            return c.post('/mark_attendance', json={'qr_data': token}).get_json()

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(scan, range(6)))

        with appmod.app.app_context():
            assert Attendance.query.count() == 1

        successes = [r for r in results if r['status'] == 'success']
        assert len(successes) == 1
        for failure in [r for r in results if r['status'] != 'success']:
            assert 'already marked present' in failure['message'], failure

    def test_an_unenrolled_student_is_turned_away(self, appmod, seed, login):
        from models import Attendance
        tayo = login(seed['other_student_email'])
        response = tayo.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert 'not registered' in response.get_json()['message']
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_a_stale_token_is_refused(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        stale = qr_token(appmod, seed['session_id'],
                         age_seconds=appmod.QR_CODE_WINDOW + 5)
        response = kemi.post('/mark_attendance', json={'qr_data': stale})
        assert 'expired' in response.get_json()['message'].lower()

    def test_a_token_still_inside_the_window_is_accepted(self, appmod, seed, login):
        """Queued scans must survive the wait, or clients retry and amplify."""
        kemi = login(seed['student_email'])
        nearly = qr_token(appmod, seed['session_id'],
                          age_seconds=appmod.QR_CODE_WINDOW - 5)
        assert kemi.post('/mark_attendance',
                         json={'qr_data': nearly}).get_json()['status'] == 'success'

    @pytest.mark.parametrize('forged', [
        'S1|9999999999|deadbeefdeadbeef',
        'S1|not-a-number|deadbeefdeadbeef',
        'nonsense',
        'S1|1|',
        '|||',
    ])
    def test_a_forged_or_malformed_token_is_refused(self, appmod, seed, login, forged):
        from models import Attendance
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={'qr_data': forged})
        assert response.get_json()['status'] == 'error'
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_a_token_for_another_session_does_not_mark_this_one(self, appmod, seed, login):
        from models import db, Attendance, ClassSession
        with appmod.app.app_context():
            other = ClassSession(course_id=seed['course_id'], title='Week 2')
            db.session.add(other)
            db.session.commit()
            other_id = other.id

        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance', json={'qr_data': qr_token(appmod, other_id)})
        with appmod.app.app_context():
            row = Attendance.query.one()
            assert row.session_id == other_id

    def test_scanning_is_rate_limited(self, appmod, seed, login):
        appmod.limiter.enabled = True
        try:
            kemi = login(seed['student_email'])
            codes = []
            for _ in range(14):
                r = kemi.post('/mark_attendance', json={'qr_data': 'nonsense'})
                codes.append(r.status_code)
            assert 429 in codes, codes
        finally:
            appmod.limiter.enabled = False
            appmod.limiter.reset()


class TestGeofence:

    def _pin(self, appmod, course_id, lat=7.22, lon=3.44):
        with appmod.app.app_context():
            appmod.set_class_location(course_id, lat, lon)

    def _scan_at_metres(self, appmod, seed, client, metres):
        lat = 7.22 + (metres / 111320.0)
        return client.post('/mark_attendance', json={
            'qr_data': qr_token(appmod, seed['session_id']),
            'lat': lat, 'lon': 3.44,
        }).get_json()

    def test_the_configured_radius_is_what_is_enforced(self, appmod, seed, login):
        """
        The check was a hardcoded `dist > 50` while the message quoted
        GEOFENCE_RADIUS_M, so students were refused at 50m by an app telling
        them the limit was 100m — and raising the env var changed nothing.
        Indoor GPS drifts 20-50m, so this rejected people sitting in the hall.
        """
        assert appmod.GEOFENCE_RADIUS_M == 100
        self._pin(appmod, seed['course_id'])
        kemi = login(seed['student_email'])
        assert self._scan_at_metres(appmod, seed, kemi, 80)['status'] == 'success'

    def test_beyond_the_radius_is_refused(self, appmod, seed, login):
        self._pin(appmod, seed['course_id'])
        kemi = login(seed['student_email'])
        result = self._scan_at_metres(appmod, seed, kemi, 250)
        assert result['status'] == 'error'
        assert 'max 100m' in result['message']

    def test_a_missing_reading_is_refused_when_a_class_is_pinned(
            self, appmod, seed, login):
        self._pin(appmod, seed['course_id'])
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert 'Location required' in response.get_json()['message']

    def test_a_zero_coordinate_is_a_reading_not_a_missing_value(
            self, appmod, seed, login):
        """`not student_lat` also rejected a legitimate 0.0."""
        self._pin(appmod, seed['course_id'], lat=0.0, lon=0.0)
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={
            'qr_data': qr_token(appmod, seed['session_id']), 'lat': 0.0, 'lon': 0.0})
        assert response.get_json()['status'] == 'success'

    def test_no_pin_means_no_geofence(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert response.get_json()['status'] == 'success'

    def test_only_a_course_lecturer_can_pin_the_class(self, appmod, seed, login):
        eve = login(seed['outsider_email'])
        assert eve.post(f"/set_location/{seed['course_id']}",
                        json={'lat': 7.22, 'lon': 3.44}).status_code == 403

    @pytest.mark.parametrize('payload', [
        {'lat': 200, 'lon': 3.44}, {'lat': 7.22, 'lon': 400},
        {'lat': 'abc', 'lon': 3.44}, {},
    ])
    def test_a_nonsense_pin_is_refused(self, appmod, seed, login, payload):
        ada = login(seed['coordinator_email'])
        assert ada.post(f"/set_location/{seed['course_id']}",
                        json=payload).status_code == 400


class TestQrTokens:

    def test_the_projector_and_the_json_endpoint_share_one_token(
            self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        first = ada.get(f"/api/qr_data/{seed['session_id']}").get_json()['qr_text']
        second = ada.get(f"/api/qr_data/{seed['session_id']}").get_json()['qr_text']
        # Without Redis each call mints a fresh token; both must still verify.
        for token in (first, second):
            with appmod.app.app_context():
                session_id, _ts = appmod.verify_signed_qr(token)
            assert session_id == seed['session_id']

    def test_a_token_signed_with_another_key_is_refused(self, appmod, seed):
        import hmac
        import hashlib
        with appmod.app.app_context():
            message = f"S{seed['session_id']}|{int(time.time())}"
            bad_sig = hmac.new(b'not-the-app-key', message.encode(),
                               hashlib.sha256).hexdigest()[:16]
            with pytest.raises(ValueError):
                appmod.verify_signed_qr(f"{message}|{bad_sig}")


# ============================================================
# HARDENING
# ============================================================

class TestSecurityHeaders:

    @pytest.mark.parametrize('header,expected', [
        ('X-Content-Type-Options', 'nosniff'),
        ('X-Frame-Options', 'DENY'),
        ('Referrer-Policy', 'strict-origin-when-cross-origin'),
    ])
    def test_baseline_headers_are_present(self, client, header, expected):
        response = client.get('/login')
        assert response.headers.get(header) == expected

    def test_a_content_security_policy_is_sent(self, client):
        csp = client.get('/login').headers.get('Content-Security-Policy')
        assert csp is not None
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp

    def test_hsts_only_outside_development(self, appmod, client, monkeypatch):
        assert client.get('/login').headers.get('Strict-Transport-Security') is None
        monkeypatch.setenv('FLASK_ENV', 'production')
        response = appmod.app.test_client().get('/login')
        assert 'max-age=' in response.headers.get('Strict-Transport-Security', '')


class TestOperationalGuards:

    def test_healthz_is_credential_free_and_cheap(self, client):
        assert client.get('/healthz').status_code == 204
        assert client.head('/healthz').status_code == 204

    def test_the_background_queue_sheds_instead_of_growing_without_limit(self, appmod):
        from performance import BoundedExecutor, RuntimeMetrics

        metrics = RuntimeMetrics()
        executor = BoundedExecutor(name='shedtest', max_workers=1, max_queue=2,
                                   metrics=metrics)
        blocker = __import__('threading').Event()
        try:
            accepted = [executor.submit(blocker.wait, 5) for _ in range(6)]
            # Capacity is max_workers + max_queue = 3; the rest are refused
            # outright rather than queued, and refusal is observable.
            assert accepted.count(None) > 0
            assert metrics.snapshot()['counters']['shedtest.rejected'] > 0
        finally:
            blocker.set()
            executor.shutdown(wait=False)

    def test_the_migration_block_is_idempotent(self, appmod):
        """Booting twice on the same database must not fail."""
        from models import db
        with appmod.app.app_context():
            db.create_all()      # the second-boot path
            db.create_all()

    def test_csv_cells_with_quotes_and_commas_survive(self, appmod):
        assert appmod._csv_cell('Doe, John') == '"Doe, John"'
        assert appmod._csv_cell('He said "hi"') == '"He said ""hi"""'
        assert appmod._csv_cell(None) == '"N/A"'

    def test_a_rate_limited_html_response_does_not_reflect_markup(self, appmod, seed, login):
        appmod.limiter.enabled = True
        try:
            kemi = login(seed['student_email'])
            last = None
            for _ in range(14):
                last = kemi.post('/mark_attendance', data={'qr_data': 'x'})
            if last.status_code == 429:
                assert b'<script' not in last.data
        finally:
            appmod.limiter.enabled = False
            appmod.limiter.reset()


class TestScanResponseContract:
    """
    The phone scanner decides whether to stop, retry or back off from the
    HTTP status. When every rejection came back as 200 the scanner treated
    it as "try again", so a rejected phone re-read the projected code and
    resubmitted roughly every 1.2s for the rest of the lecture.
    """

    def test_a_duplicate_scan_is_a_409_not_a_200(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        token = qr_token(appmod, seed['session_id'])

        first = kemi.post('/mark_attendance', json={'qr_data': token})
        assert first.status_code == 200
        assert first.get_json()['status'] == 'success'

        second = kemi.post('/mark_attendance', json={'qr_data': token})
        assert second.status_code == 409
        assert second.get_json()['status'] == 'error'

    def test_an_unenrolled_student_is_a_403(self, appmod, seed, login):
        tayo = login(seed['other_student_email'])
        response = tayo.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert response.status_code == 403

    def test_an_unknown_session_is_a_404(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, 999999)})
        assert response.status_code == 404

    def test_a_malformed_or_expired_token_is_a_400(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        assert kemi.post('/mark_attendance',
                         json={'qr_data': 'garbage'}).status_code == 400
        assert kemi.post('/mark_attendance', json={}).status_code == 400
        stale = qr_token(appmod, seed['session_id'],
                         age_seconds=appmod.QR_CODE_WINDOW + 5)
        assert kemi.post('/mark_attendance',
                         json={'qr_data': stale}).status_code == 400

    def test_a_queued_scan_cannot_be_replayed_under_another_account(
            self, appmod, seed, login):
        """
        An offline scan carries the id of the student who took it. Replaying
        it while somebody else is signed in on that phone must not mark the
        wrong person present.
        """
        from models import Attendance

        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={
            'qr_data': qr_token(appmod, seed['session_id']),
            'user_marker': str(seed['other_student_id']),
        })
        assert response.status_code == 409
        with appmod.app.app_context():
            assert Attendance.query.count() == 0


class TestFlashMessagesRenderOnce:

    def test_a_flash_is_not_duplicated_on_the_page(self, appmod, seed, client):
        """
        base.html called get_flashed_messages() twice. Flask caches the list
        on the request context, so the second call re-rendered every message
        — always styled as a yellow warning, whatever its real category.
        """
        response = client.post('/login',
                               data={'email': seed['student_email'],
                                     'password': 'definitely-wrong-9'},
                               follow_redirects=True)
        assert response.data.count(b'Invalid email or password.') == 1


class TestScanPageShowsRealData:

    def test_the_scan_page_lists_courses_the_student_has_attended(
            self, appmod, seed, login):
        """
        scan_page() rendered the template with no context, so the guard
        `{% if attendance_data %}` was always false and every student saw the
        empty state no matter how many classes they had attended.
        """
        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance',
                  json={'qr_data': qr_token(appmod, seed['session_id'])})

        page = kemi.get('/scan_page')
        assert page.status_code == 200
        assert b'CSC201' in page.data
        assert b"haven't marked attendance for any courses yet" not in page.data


class TestOfflineQueueHonesty:

    def test_the_service_worker_is_told_the_servers_qr_window(self, client, appmod):
        """
        The worker used to hold queued scans for 5 minutes against a
        45-second server window, then delete them silently. It now gets the
        real number from the server so the two cannot drift apart.
        """
        response = client.get('/service-worker.js')
        assert response.status_code == 200
        assert (f'self.SCANMARK_QR_WINDOW_SECONDS = {appmod.QR_CODE_WINDOW};'
                in response.get_data(as_text=True))


class TestGeofenceRequiredMode:

    def test_strict_mode_refuses_a_scan_when_no_classroom_is_pinned(
            self, appmod, seed, login, monkeypatch):
        """
        With no pinned location the distance check is skipped entirely, so
        the class is marked with no proximity requirement at all. Strict
        mode makes that refuse instead of silently accepting.
        """
        from models import Attendance

        monkeypatch.setattr(appmod, 'GEOFENCE_REQUIRED', True)
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={
            'qr_data': qr_token(appmod, seed['session_id']),
            'lat': 7.227, 'lon': 3.438,
        })
        assert response.status_code == 422
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_the_default_stays_permissive_so_a_class_is_never_locked_out(
            self, appmod, seed, login):
        assert appmod.GEOFENCE_REQUIRED is False
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert response.status_code == 200


class TestEarlyWarningCadence:
    """
    The threshold check used to run inline on every scan. That cost two COUNT
    queries per scan AND re-sent the warning every time — a student below the
    line got one email per class attended for the rest of the semester, with
    a copy to their parent each time.
    """

    def _struggling(self, appmod, seed, held=10, attended=2):
        from models import db, ClassSession, Attendance, NotificationPreference

        with appmod.app.app_context():
            db.session.add(NotificationPreference(
                user_id=seed['student_id'], email_alerts=True,
                warning_threshold=75, notify_parent=True,
                parent_email='guardian@example.test'))
            sessions = [ClassSession(course_id=seed['course_id'], title=f'W{n}')
                        for n in range(held)]
            db.session.add_all(sessions)
            db.session.commit()
            for row in sessions[:attended]:
                db.session.add(Attendance(student_id=seed['student_id'],
                                          course_id=seed['course_id'],
                                          session_id=row.id))
            db.session.commit()

    def test_the_sweep_warns_once_not_once_per_run(self, appmod, seed, monkeypatch):
        from models import EarlyWarning

        self._struggling(appmod, seed)
        sent = []
        monkeypatch.setattr(appmod, 'notify_early_warning',
                            lambda **kwargs: sent.append(kwargs['student'].id) or (1, 1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        assert appmod.run_early_warnings() == 1
        assert len(sent) == 1
        # Same day, same week: silence.
        assert appmod.run_early_warnings() == 0
        assert appmod.run_early_warnings() == 0
        assert len(sent) == 1

        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 1

    def test_a_student_who_slips_further_is_told_again_inside_the_cooldown(
            self, appmod, seed, monkeypatch):
        from models import db, ClassSession

        # The seed fixture already opened one session, so derive the expected
        # percentages from the database rather than assuming a round number.
        self._struggling(appmod, seed, held=10, attended=5)
        sent = []
        monkeypatch.setattr(appmod, 'notify_early_warning',
                            lambda **kwargs: sent.append(round(kwargs['percentage'])) or (1, 1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        with appmod.app.app_context():
            held = ClassSession.query.filter_by(course_id=seed['course_id']).count()
        first_expected = round(5 / held * 100)

        assert appmod.run_early_warnings() == 1
        assert sent == [first_expected]

        # Ten more classes held, none of them attended — a material slip, so
        # the student hears about it again despite the cooldown.
        with appmod.app.app_context():
            db.session.add_all([ClassSession(course_id=seed['course_id'], title=f'X{n}')
                                for n in range(10)])
            db.session.commit()
        second_expected = round(5 / (held + 10) * 100)
        assert first_expected - second_expected >= appmod.EARLY_WARNING_RETRIGGER_DROP

        assert appmod.run_early_warnings() == 1
        assert sent == [first_expected, second_expected]

    def test_a_student_above_the_threshold_is_never_warned(
            self, appmod, seed, monkeypatch):
        self._struggling(appmod, seed, held=10, attended=9)   # 90%
        sent = []
        monkeypatch.setattr(appmod, 'notify_early_warning',
                            lambda **kwargs: sent.append(1) or (1, 1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        assert appmod.run_early_warnings() == 0
        assert sent == []

    def test_off_mode_sends_nothing(self, appmod, seed, monkeypatch):
        self._struggling(appmod, seed)
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'off')
        assert appmod.run_early_warnings() == 0

    def test_the_scan_path_no_longer_runs_the_threshold_check(
            self, appmod, seed, login, monkeypatch):
        """The two COUNT queries are off the hot path in the default mode."""
        called = []
        monkeypatch.setattr(appmod, 'process_early_warning',
                            lambda **kwargs: called.append(1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        appmod._post_scan_notifications(appmod.app, seed['student_id'],
                                        seed['course_id'], 'now')
        assert called == []

        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'scan')
        appmod._post_scan_notifications(appmod.app, seed['student_id'],
                                        seed['course_id'], 'now')
        assert called == [1]


class TestPostScanNotificationSwitch:

    def test_turning_post_scan_work_off_queues_nothing_but_still_records(
            self, appmod, seed, login, monkeypatch):
        """
        SCAN_CONFIRMATION_EMAILS only skipped composing the mail; the lookups
        still ran, so it bought ~4% under load. This is the lever that
        actually sheds the work.
        """
        from models import Attendance

        queued = []
        monkeypatch.setattr(appmod.notification_work_executor, 'submit',
                            lambda *a, **k: queued.append(a[0]) or object())
        monkeypatch.setattr(appmod, 'POST_SCAN_NOTIFICATIONS', False)

        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert response.status_code == 200
        assert queued == []
        with appmod.app.app_context():
            assert Attendance.query.count() == 1   # the scan itself is untouched

    def test_the_default_still_queues_the_courtesy_notification(
            self, appmod, seed, login, monkeypatch):
        queued = []
        monkeypatch.setattr(appmod.notification_work_executor, 'submit',
                            lambda *a, **k: queued.append(a[0]) or object())
        monkeypatch.setattr(appmod, 'POST_SCAN_NOTIFICATIONS', True)

        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance',
                  json={'qr_data': qr_token(appmod, seed['session_id'])})
        assert len(queued) == 1


class TestEarlyWarningSweepEdges:
    """
    Four defects caught in review of the sweep. Each one only shows up in a
    situation the happy-path tests never reach.
    """

    def _course_with_sessions(self, appmod, seed, held=10):
        from models import db, ClassSession
        with appmod.app.app_context():
            db.session.add_all([ClassSession(course_id=seed['course_id'], title=f'W{n}')
                                for n in range(held)])
            db.session.commit()

    def test_a_student_who_never_opened_settings_is_still_warned(
            self, appmod, seed, monkeypatch):
        """
        Candidates were drawn from NotificationPreference, but that row only
        exists once someone has saved their settings. The model default and
        the inline check both treat a missing row as email-alerts-on, so
        selecting on the table silently excluded most of the cohort.
        """
        from models import NotificationPreference

        self._course_with_sessions(appmod, seed)
        with appmod.app.app_context():
            assert NotificationPreference.query.filter_by(
                user_id=seed['student_id']).first() is None, 'fixture must have no pref row'

        warned = []
        monkeypatch.setattr(appmod, 'notify_early_warning',
                            lambda **kw: warned.append(kw['student'].id) or (1, 1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        assert appmod.run_early_warnings() == 1
        assert warned == [seed['student_id']]

    def test_a_student_who_silenced_every_channel_is_not_warned(
            self, appmod, seed, monkeypatch):
        from models import db, NotificationPreference

        self._course_with_sessions(appmod, seed)
        with appmod.app.app_context():
            db.session.add(NotificationPreference(
                user_id=seed['student_id'], email_alerts=False,
                whatsapp_alerts=False, notify_parent=False))
            db.session.commit()

        warned = []
        monkeypatch.setattr(appmod, 'notify_early_warning',
                            lambda **kw: warned.append(1) or (1, 1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        assert appmod.run_early_warnings() == 0
        assert warned == []

    def test_a_student_on_zero_percent_is_not_warned_every_single_day(
            self, appmod, seed, monkeypatch):
        """
        `previous.last_percentage or 100` read a stored 0.0 as "no record",
        making the drop 100 points on every sweep — so the students on nought
        percent, the ones the guard exists for, were warned daily.
        """
        self._course_with_sessions(appmod, seed)   # zero attendance -> 0%

        warned = []
        monkeypatch.setattr(appmod, 'notify_early_warning',
                            lambda **kw: warned.append(kw['percentage']) or (1, 1))
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        assert appmod.run_early_warnings() == 1
        assert warned == [0.0]

        # Every later sweep inside the cooldown must stay silent.
        for _ in range(5):
            assert appmod.run_early_warnings() == 0
        assert warned == [0.0]

    def test_a_dropped_delivery_does_not_earn_a_cooldown(
            self, appmod, seed, monkeypatch):
        """
        The sweep submits more jobs than the bounded pool holds, so refusals
        are a real outcome. Recording "sent" for a refused job would suppress
        the retry for the whole cooldown.
        """
        from models import EarlyWarning

        self._course_with_sessions(appmod, seed)
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')

        # Every channel refuses.
        monkeypatch.setattr(appmod, 'notify_early_warning', lambda **kw: (1, 0))
        assert appmod.run_early_warnings() == 0
        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 0, 'no cooldown for an undelivered warning'

        # The queue drains; the next sweep gets through.
        monkeypatch.setattr(appmod, 'notify_early_warning', lambda **kw: (1, 1))
        assert appmod.run_early_warnings() == 1
        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 1

    def test_notify_early_warning_reports_what_the_queue_did(self, appmod, seed):
        """The return value is what the sweep trusts, so pin it down."""
        import notifications
        from models import User, Course

        class Full:
            def submit(self, *a, **k): return None          # queue refuses
        class Open:
            def submit(self, *a, **k): return object()      # queue accepts

        with appmod.app.app_context():
            student = User.query.get(seed['student_id'])
            course = Course.query.get(seed['course_id'])
            original = notifications.notification_executor
            try:
                notifications.notification_executor = Full()
                assert notifications.notify_early_warning(
                    student=student, course=course, percentage=10, threshold=75,
                    preference=None, app_instance=appmod.app,
                    mail_func=appmod.send_email) == (1, 0)

                notifications.notification_executor = Open()
                assert notifications.notify_early_warning(
                    student=student, course=course, percentage=10, threshold=75,
                    preference=None, app_instance=appmod.app,
                    mail_func=appmod.send_email) == (1, 1)
            finally:
                notifications.notification_executor = original

    def test_a_course_with_warnings_can_still_be_deleted(
            self, appmod, seed, login, monkeypatch):
        """
        EarlyWarning references course.id. Postgres enforces that key, so
        forgetting it in delete_course() breaks deletion in production and
        nowhere else.
        """
        from models import db, Course, EarlyWarning
        import datetime

        self._course_with_sessions(appmod, seed)
        with appmod.app.app_context():
            db.session.add(EarlyWarning(student_id=seed['student_id'],
                                        course_id=seed['course_id'],
                                        last_sent_on=datetime.date.today(),
                                        last_percentage=0.0))
            db.session.commit()

        coordinator = login(seed['coordinator_email'])
        response = coordinator.post(f"/delete_course/{seed['course_id']}",
                                    follow_redirects=True)
        assert response.status_code == 200
        with appmod.app.app_context():
            assert Course.query.get(seed['course_id']) is None
            assert EarlyWarning.query.filter_by(course_id=seed['course_id']).count() == 0


class TestEarlyWarningPartialDelivery:
    """
    One student can generate four jobs (own email + WhatsApp, guardian email
    + WhatsApp) and a full sweep submits far more than the bounded pool
    holds, so partial acceptance is a real outcome — not an edge case.
    """

    def _struggling(self, appmod, seed, held=10):
        from models import db, ClassSession
        with appmod.app.app_context():
            db.session.add_all([ClassSession(course_id=seed['course_id'], title=f'W{n}')
                                for n in range(held)])
            db.session.commit()

    def test_a_partly_queued_warning_earns_no_cooldown(
            self, appmod, seed, monkeypatch):
        """
        Settling on the first acceptance would drop the refused channels —
        a guardian never hearing about it — for the whole cooldown.
        """
        from models import EarlyWarning

        self._struggling(appmod, seed)
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')
        # Two channels configured, only one taken by the queue.
        monkeypatch.setattr(appmod, 'notify_early_warning', lambda **kw: (2, 1))

        assert appmod.run_early_warnings() == 0
        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 0

        # Once the pool drains, the whole warning goes out and settles.
        monkeypatch.setattr(appmod, 'notify_early_warning', lambda **kw: (2, 2))
        assert appmod.run_early_warnings() == 1
        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 1

    def test_a_student_with_no_channels_configured_still_settles(
            self, appmod, seed, monkeypatch):
        """`attempted == 0` is nothing to deliver, not a dropped delivery."""
        from models import EarlyWarning

        self._struggling(appmod, seed)
        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')
        monkeypatch.setattr(appmod, 'notify_early_warning', lambda **kw: (0, 0))

        assert appmod.run_early_warnings() == 1
        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 1

    def test_the_sweep_stops_at_the_first_refusal_instead_of_grinding_on(
            self, appmod, seed, monkeypatch):
        """
        Continuing past a full queue would refuse nearly everyone. Stopping
        leaves the remainder with no cooldown, so the next sweep resumes.
        """
        from models import db, User, Course, EarlyWarning

        self._struggling(appmod, seed)
        with appmod.app.app_context():
            course = Course.query.get(seed['course_id'])
            extra = [User(full_name=f'S{n}', email=f'extra{n}@student.funaab.edu.ng',
                          password='x', role='student', matric_no=f'E{n:04}', level='300')
                     for n in range(5)]
            db.session.add_all(extra)
            db.session.commit()
            for student in extra:
                student.enrolled_courses.append(course)
            db.session.commit()

        monkeypatch.setattr(appmod, 'EARLY_WARNING_MODE', 'daily')
        calls = []

        def flaky(**kw):
            calls.append(kw['student'].id)
            # The pool has room for two, then refuses.
            return (1, 1) if len(calls) <= 2 else (1, 0)

        monkeypatch.setattr(appmod, 'notify_early_warning', flaky)

        assert appmod.run_early_warnings() == 2
        # Two delivered, the third refused and ended the sweep — the
        # remaining students were never even attempted.
        assert len(calls) == 3
        with appmod.app.app_context():
            assert EarlyWarning.query.count() == 2
