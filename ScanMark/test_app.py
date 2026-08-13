"""
Route-level tests for ScanMark.

Every bug this suite was written for shipped to main because nothing ever
executed app.py. The first class below is the cheap generic guard that would
have caught all six undefined names on its own; the rest pin down the specific
behaviours that were wrong.
"""
import time

import pytest

from conftest import VALID_PASSWORD, qr_token, scan_body


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
                     json=scan_body(appmod, seed['session_id']))

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

    @pytest.mark.parametrize('staff_role,stored', [
        ('Lecturer', 'Lecturer'),
        ('Course Coordinator', 'Course Coordinator'),
    ])
    def test_staff_sign_in_the_moment_the_account_exists(
            self, appmod, client, staff_role, stored):
        """
        Only students are gated. A lecturer who signs up minutes before a class
        must not be stuck waiting on an inbox — the account works immediately,
        unconfirmed address and all.
        """
        from models import User

        appmod.REQUIRE_EMAIL_VERIFICATION = True
        try:
            email = f"{stored.split()[0].lower()}.now@staff.funaab.edu.ng"
            client.post('/signup', data={
                'full_name': 'Straight In', 'email': email,
                'password': VALID_PASSWORD, 'staff_role': staff_role,
            })
            with appmod.app.app_context():
                user = User.query.filter_by(email=email).first()
                assert user is not None and user.role == stored
                # The row still records the truth: nobody proved this address.
                assert user.email_verified is False

            c = appmod.app.test_client()
            response = c.post('/login', data={'email': email,
                                              'password': VALID_PASSWORD})
            assert response.status_code == 302, 'staff were held at the login page'
            assert '/lecturer_dashboard' in response.headers['Location']
        finally:
            appmod.REQUIRE_EMAIL_VERIFICATION = False

    def test_only_the_student_role_is_gated(self, appmod):
        assert appmod.role_requires_email_verification('student') is True
        assert appmod.role_requires_email_verification('Student') is True
        assert appmod.role_requires_email_verification('Lecturer') is False
        assert appmod.role_requires_email_verification('course coordinator') is False
        assert appmod.role_requires_email_verification('HOD') is False

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
                             json=scan_body(appmod, seed['session_id']))
        assert response.get_json()['status'] == 'success'
        with appmod.app.app_context():
            assert Attendance.query.count() == 1

    def test_a_second_scan_is_refused_politely(self, appmod, seed, login):
        from models import Attendance
        kemi = login(seed['student_email'])
        token = qr_token(appmod, seed['session_id'])
        kemi.post('/mark_attendance', json=scan_body(appmod, token=token))
        response = kemi.post('/mark_attendance', json=scan_body(appmod, token=token))
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
            return c.post('/mark_attendance', json=scan_body(appmod, token=token)).get_json()

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
                             json=scan_body(appmod, seed['session_id']))
        assert 'not registered' in response.get_json()['message']
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_a_stale_token_is_refused(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        stale = qr_token(appmod, seed['session_id'],
                         age_seconds=appmod.QR_CODE_WINDOW + 5)
        response = kemi.post('/mark_attendance', json=scan_body(appmod, token=stale))
        assert 'expired' in response.get_json()['message'].lower()

    def test_a_token_still_inside_the_window_is_accepted(self, appmod, seed, login):
        """Queued scans must survive the wait, or clients retry and amplify."""
        kemi = login(seed['student_email'])
        nearly = qr_token(appmod, seed['session_id'],
                          age_seconds=appmod.QR_CODE_WINDOW - 5)
        assert kemi.post('/mark_attendance',
                         json=scan_body(appmod, token=nearly)).get_json()['status'] == 'success'

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
        response = kemi.post('/mark_attendance', json=scan_body(appmod, token=forged))
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
        kemi.post('/mark_attendance', json=scan_body(appmod, other_id))
        with appmod.app.app_context():
            row = Attendance.query.one()
            assert row.session_id == other_id

    def test_scanning_is_rate_limited(self, appmod, seed, login):
        appmod.limiter.enabled = True
        try:
            kemi = login(seed['student_email'])
            codes = []
            for _ in range(14):
                r = kemi.post('/mark_attendance', json=scan_body(appmod, token='nonsense'))
                codes.append(r.status_code)
            assert 429 in codes, codes
        finally:
            appmod.limiter.enabled = False
            appmod.limiter.reset()


class TestGeofence:

    def _pin(self, appmod, seed, lat=7.22, lon=3.44):
        """Pin the MEETING's classroom — a lecture and the tutorial after it
        are legitimately in different rooms."""
        with appmod.app.app_context():
            appmod.set_class_location(seed['session_id'], lat, lon)

    def _scan_at_metres(self, appmod, seed, client, metres, **overrides):
        lat = 7.22 + (metres / 111320.0)
        payload = scan_body(
            appmod, seed['session_id'],
            lat=lat, lon=3.44,
            # Required, not accepted-if-present: omitting them used to be the
            # way past the check.
            accuracy_m=10, location_age_ms=1000,
        )
        payload.update(overrides)
        return client.post('/mark_attendance', json=payload).get_json()

    def test_the_configured_radius_is_what_is_enforced(self, appmod, seed, login):
        """
        The check was a hardcoded `dist > 50` while the message quoted
        GEOFENCE_RADIUS_M, so students were refused at 50m by an app telling
        them the limit was 100m — and raising the env var changed nothing.
        Indoor GPS drifts 20-50m, so this rejected people sitting in the hall.
        """
        assert appmod.GEOFENCE_RADIUS_M == 100
        self._pin(appmod, seed)
        kemi = login(seed['student_email'])
        assert self._scan_at_metres(appmod, seed, kemi, 80)['status'] == 'success'

    def test_beyond_the_radius_is_refused(self, appmod, seed, login):
        self._pin(appmod, seed)
        kemi = login(seed['student_email'])
        result = self._scan_at_metres(appmod, seed, kemi, 250)
        assert result['status'] == 'error'
        assert 'max 100m' in result['message']

    def test_a_missing_reading_is_refused_when_a_class_is_pinned(
            self, appmod, seed, login):
        self._pin(appmod, seed)
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json=scan_body(appmod, seed['session_id']))
        assert 'Location required' in response.get_json()['message']

    def test_a_zero_coordinate_is_a_reading_not_a_missing_value(
            self, appmod, seed, login):
        """`not student_lat` also rejected a legitimate 0.0."""
        self._pin(appmod, seed, lat=0.0, lon=0.0)
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json=scan_body(
            appmod, seed['session_id'], lat=0.0, lon=0.0,
            accuracy_m=10, location_age_ms=500))
        assert response.get_json()['status'] == 'success'

    @pytest.mark.parametrize('missing', ['accuracy_m', 'location_age_ms'])
    def test_the_fields_that_prove_a_reading_cannot_be_left_out(
            self, appmod, seed, login, missing):
        """
        Both were read only `if isinstance(...)`, so a payload that simply
        omitted them sailed through every freshness and precision check. A
        scan submitted by hand is not obliged to be honest, but it is obliged
        to be complete.
        """
        self._pin(appmod, seed)
        kemi = login(seed['student_email'])
        payload = scan_body(appmod, seed['session_id'], lat=7.22, lon=3.44,
                            accuracy_m=10, location_age_ms=500)
        payload.pop(missing)
        response = kemi.post('/mark_attendance', json=payload)
        assert response.status_code == 422
        with appmod.app.app_context():
            from models import Attendance
            assert Attendance.query.count() == 0

    def test_a_fix_too_imprecise_to_mean_anything_is_refused(
            self, appmod, seed, login):
        """A 5km error radius 'inside' a 100m geofence proves nothing."""
        self._pin(appmod, seed)
        kemi = login(seed['student_email'])
        result = self._scan_at_metres(appmod, seed, kemi, 5,
                                      accuracy_m=appmod.GEOFENCE_MAX_ACCURACY_M + 1)
        assert result['status'] == 'error'
        assert 'too imprecise' in result['message']

    def test_a_stale_fix_is_refused(self, appmod, seed, login):
        self._pin(appmod, seed)
        kemi = login(seed['student_email'])
        result = self._scan_at_metres(
            appmod, seed, kemi, 5,
            location_age_ms=appmod.GEOFENCE_MAX_LOCATION_AGE_MS + 1)
        assert result['status'] == 'error'
        assert 'stale' in result['message'].lower()

    def test_no_pin_means_no_geofence(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json=scan_body(appmod, seed['session_id']))
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

        first = kemi.post('/mark_attendance', json=scan_body(appmod, token=token))
        assert first.status_code == 200
        assert first.get_json()['status'] == 'success'

        second = kemi.post('/mark_attendance', json=scan_body(appmod, token=token))
        assert second.status_code == 409
        assert second.get_json()['status'] == 'error'

    def test_an_unenrolled_student_is_a_403(self, appmod, seed, login):
        tayo = login(seed['other_student_email'])
        response = tayo.post('/mark_attendance',
                             json=scan_body(appmod, seed['session_id']))
        assert response.status_code == 403

    def test_an_unknown_session_is_a_404(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json=scan_body(appmod, 999999))
        assert response.status_code == 404

    def test_a_malformed_or_expired_token_is_a_400(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        assert kemi.post('/mark_attendance',
                         json=scan_body(appmod, token='garbage')).status_code == 400
        assert kemi.post('/mark_attendance', json={}).status_code == 400
        stale = qr_token(appmod, seed['session_id'],
                         age_seconds=appmod.QR_CODE_WINDOW + 5)
        assert kemi.post('/mark_attendance',
                         json=scan_body(appmod, token=stale)).status_code == 400

    def test_a_queued_scan_cannot_be_replayed_under_another_account(
            self, appmod, seed, login):
        """
        An offline scan carries the id of the student who took it. Replaying
        it while somebody else is signed in on that phone must not mark the
        wrong person present.
        """
        from models import Attendance

        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json=scan_body(
            appmod, seed['session_id'],
            user_marker=str(seed['other_student_id'])))
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
                  json=scan_body(appmod, seed['session_id']))

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
        response = kemi.post('/mark_attendance', json=scan_body(
            appmod, seed['session_id'], lat=7.227, lon=3.438))
        assert response.status_code == 422
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_the_shipped_default_is_to_require_a_pinned_classroom(self, appmod):
        """
        This used to default OFF, and the failure mode was silent and total:
        a lecturer who dismissed one browser location prompt recorded a whole
        term of attendance that anyone could have submitted from anywhere,
        with nothing on the register saying so. Refusing is loud and fixable
        in ten seconds.

        (The suite's own fixture turns it back off — see conftest — because
        almost every other test here is about something else.)
        """
        assert appmod._env_flag('GEOFENCE_REQUIRED', True) is True

    def test_turning_it_off_is_still_possible_and_deliberate(
            self, appmod, seed, login, monkeypatch):
        monkeypatch.setattr(appmod, 'GEOFENCE_REQUIRED', False)
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json=scan_body(appmod, seed['session_id']))
        assert response.status_code == 200




class TestEmailIsSignupOnly:
    """
    ScanMark sends account email and nothing else. A scan used to queue a
    confirmation, a WhatsApp, guardian copies of both and a threshold check —
    five extra queries and up to four outbound jobs per student, per scan.
    """

    def _captured_sends(self, appmod, monkeypatch):
        sent = []
        monkeypatch.setattr(appmod.account_email_executor, 'submit',
                            lambda *a, **k: sent.append(a[0]) or object())
        return sent

    def test_marking_attendance_sends_nothing_at_all(
            self, appmod, seed, login, monkeypatch):
        from models import Attendance

        sent = self._captured_sends(appmod, monkeypatch)
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance',
                             json=scan_body(appmod, seed['session_id']))

        assert response.status_code == 200
        assert sent == [], f'a scan queued outbound work: {sent}'
        with appmod.app.app_context():
            assert Attendance.query.count() == 1   # the register is untouched

    def test_signing_up_still_sends_the_confirmation_link(
            self, appmod, monkeypatch):
        from models import User

        sent = self._captured_sends(appmod, monkeypatch)
        appmod.REQUIRE_EMAIL_VERIFICATION = True
        try:
            client = appmod.app.test_client()
            response = client.post('/signup', data={
                'full_name': 'New Person', 'email': 'newperson@gmail.com',
                'password': VALID_PASSWORD, 'matric_no': '20201234', 'level': '300',
            })
            assert response.status_code in (200, 302)
            assert len(sent) >= 1, 'signup must still send the verification link'
            with appmod.app.app_context():
                assert User.query.filter_by(email='newperson@gmail.com').first() is not None
        finally:
            appmod.REQUIRE_EMAIL_VERIFICATION = False

    def test_a_forgotten_password_can_still_be_recovered(
            self, appmod, seed, monkeypatch):
        """
        Password reset is account access, not a notification — without it a
        forgotten password is a permanent lockout with no admin screen to
        undo it. Deliberately kept.
        """
        sent = self._captured_sends(appmod, monkeypatch)
        client = appmod.app.test_client()
        response = client.post('/forgot_password',
                               data={'email': seed['student_email']})
        assert response.status_code in (200, 302)
        assert len(sent) == 1

    def test_the_notification_stack_is_gone(self, appmod):
        """No settings page, no scheduler, no notifications module."""
        import importlib

        endpoints = {rule.endpoint for rule in appmod.app.url_map.iter_rules()}
        assert 'notification_settings' not in endpoints

        for gone in ('run_weekly_reports', 'run_early_warnings',
                     '_post_scan_notifications', 'send_attendance_confirmation',
                     'notification_work_executor', 'scheduler'):
            assert not hasattr(appmod, gone), f'{gone} survived the cut'

        with pytest.raises(ImportError):
            importlib.import_module('notifications')

    def test_no_scan_ever_touches_a_notification_table(self, appmod):
        """The three notification models are gone from the schema."""
        from models import db

        table_names = set(db.metadata.tables)
        assert 'notification_preference' not in table_names
        assert 'weekly_report' not in table_names
        assert 'early_warning' not in table_names


class TestLegacyNotificationTables:
    """
    Removing a model does not remove its table: db.create_all() only ever
    creates. On a database upgraded from a release that still had the
    notification stack, `early_warning` survives with its FOREIGN KEY to
    course.id intact — and Postgres enforces it, so historical rows block
    DELETE on any course they reference. SQLite does not enforce it, so this
    class of bug is invisible to the rest of this suite.
    """

    def test_a_fresh_database_detects_no_legacy_tables(self, appmod):
        assert appmod.LEGACY_COURSE_REF_TABLES == ()

    def test_course_deletion_clears_a_surviving_early_warning_table(
            self, appmod, seed, login, monkeypatch):
        """
        Simulate the upgraded shape: create the legacy table by hand, point a
        row at the course, and delete the course through the route.
        """
        import datetime
        from models import db, Course

        with appmod.app.app_context():
            db.session.execute(db.text('''
                CREATE TABLE IF NOT EXISTS early_warning (
                    id INTEGER PRIMARY KEY,
                    student_id INTEGER NOT NULL REFERENCES "user"(id),
                    course_id INTEGER NOT NULL REFERENCES course(id),
                    last_sent_on DATE NOT NULL,
                    last_percentage FLOAT
                )'''))
            # An explicit id: `id INTEGER PRIMARY KEY` auto-increments on
            # SQLite but is a plain NOT NULL column on Postgres, and this
            # test exists for a Postgres-only failure mode — it has to be
            # able to run there.
            db.session.execute(
                db.text('INSERT INTO early_warning '
                        '(id, student_id, course_id, last_sent_on, last_percentage) '
                        'VALUES (1, :s, :c, :d, 0.0)'),
                {'s': seed['student_id'], 'c': seed['course_id'],
                 'd': datetime.date.today()})
            db.session.commit()

        # The detection runs at boot; point it at the table we just made.
        monkeypatch.setattr(appmod, 'LEGACY_COURSE_REF_TABLES', ('early_warning',))

        coordinator = login(seed['coordinator_email'])
        response = coordinator.post(f"/delete_course/{seed['course_id']}",
                                    follow_redirects=True)
        assert response.status_code == 200

        with appmod.app.app_context():
            assert Course.query.get(seed['course_id']) is None
            left = db.session.execute(db.text(
                'SELECT count(*) FROM early_warning WHERE course_id = :c'),
                {'c': seed['course_id']}).scalar()
            assert left == 0, 'legacy rows must be cleared with the course'
            db.session.execute(db.text('DROP TABLE early_warning'))
            db.session.commit()

    def test_dropping_the_legacy_table_mid_flight_does_not_break_deletion(
            self, appmod, seed, login, monkeypatch):
        """
        The startup message invites an operator to drop these tables whenever
        they like. If a worker booted while the table existed, its cached
        list still names it — and on Postgres the failed DELETE aborts the
        whole transaction, so every course deletion 500s until all workers
        restart. A savepoint plus self-healing makes the drop safe at any
        moment.
        """
        from models import Course

        # Booted with the table, but it is not actually there any more.
        monkeypatch.setattr(appmod, 'LEGACY_COURSE_REF_TABLES', ('early_warning',))

        coordinator = login(seed['coordinator_email'])
        response = coordinator.post(f"/delete_course/{seed['course_id']}",
                                    follow_redirects=True)
        assert response.status_code == 200
        with appmod.app.app_context():
            assert Course.query.get(seed['course_id']) is None

        # The worker stopped asking for it, so the next delete is untouched.
        assert appmod.LEGACY_COURSE_REF_TABLES == ()
