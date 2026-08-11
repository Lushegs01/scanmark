"""
Regression tests for the attendance/academic-record and release-blocking
security bugs.

One test per defect, named for the behaviour that was wrong. Each of these
fails on the code as it was.
"""
import time

import pytest

from conftest import qr_token


# ============================================================
# SESSION LIFECYCLE
# ============================================================

class TestEndingAClassEndsIt:

    def test_end_class_closes_the_session_on_the_server(self, appmod, seed, login):
        """The button was a GET form pointing at the lecturer dashboard: it
        navigated, and nothing about the class changed."""
        from models import db, ClassSession

        ada = login(seed['coordinator_email'])
        response = ada.post(f"/session/{seed['session_id']}/end")
        assert response.status_code == 302

        with appmod.app.app_context():
            row = db.session.get(ClassSession, seed['session_id'])
            assert row.active is False
            assert row.ended_at is not None
            assert row.is_open is False

    def test_a_token_minted_before_the_end_stops_working_immediately(
            self, appmod, seed, login):
        """
        A token stayed redeemable for the rest of its 45-second window after
        the class ended — long enough to photograph the projector on the way
        out and mark a friend present from the corridor.
        """
        from models import Attendance

        token = qr_token(appmod, seed['session_id'])
        ada = login(seed['coordinator_email'])
        ada.post(f"/session/{seed['session_id']}/end")

        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={'qr_data': token})
        assert response.status_code == 409
        assert 'ended' in response.get_json()['message'].lower()
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_the_projector_endpoints_refuse_an_ended_session(
            self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        ada.post(f"/session/{seed['session_id']}/end")
        assert ada.get(f"/api/qr_data/{seed['session_id']}").status_code == 409
        assert ada.get(f"/session/{seed['session_id']}/live").status_code == 409

    def test_only_a_course_lecturer_can_end_a_class(self, appmod, seed, login):
        from models import db, ClassSession

        eve = login(seed['outsider_email'])
        eve.post(f"/session/{seed['session_id']}/end")
        with appmod.app.app_context():
            assert db.session.get(ClassSession, seed['session_id']).is_open is True


class TestMoreThanOneClassADay:

    def test_starting_again_resumes_the_class_that_is_running(
            self, appmod, seed, login):
        from models import ClassSession

        ada = login(seed['coordinator_email'])
        first = ada.post(f"/course/{seed['course_id']}/start_session")
        second = ada.post(f"/course/{seed['course_id']}/start_session")
        assert first.headers['Location'] == second.headers['Location']

        with appmod.app.app_context():
            assert ClassSession.query.filter_by(course_id=seed['course_id']).count() == 1

    def test_a_second_meeting_on_the_same_day_is_its_own_record_set(
            self, appmod, seed, login):
        """
        A lecture and the tutorial after it were silently merged into one
        session, because a session was keyed on (course, UTC day). A makeup
        class could not be recorded at all.
        """
        from models import ClassSession

        ada = login(seed['coordinator_email'])
        ada.post(f"/course/{seed['course_id']}/start_session")
        ada.post(f"/course/{seed['course_id']}/start_session",
                 data={'new_session': '1', 'kind': 'Makeup Class'})

        with appmod.app.app_context():
            rows = (ClassSession.query
                    .filter_by(course_id=seed['course_id'])
                    .order_by(ClassSession.id.asc()).all())
            assert len(rows) == 2
            assert rows[-1].kind == 'Makeup Class'
            assert rows[-1].sequence == 2
            # Starting a new one closes the one still running, so two live
            # sessions never compete for the same scans.
            assert rows[0].is_open is False
            assert rows[-1].is_open is True

    def test_each_meeting_keeps_its_own_attendance(self, appmod, seed, login):
        from models import Attendance, ClassSession

        ada = login(seed['coordinator_email'])
        ada.post(f"/course/{seed['course_id']}/start_session",
                 data={'new_session': '1', 'kind': 'Tutorial'})

        with appmod.app.app_context():
            tutorial = (ClassSession.query
                        .filter_by(course_id=seed['course_id'], kind='Tutorial')
                        .one())
            tutorial_id = tutorial.id

        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance', json={'qr_data': qr_token(appmod, tutorial_id)})

        with appmod.app.app_context():
            rows = Attendance.query.all()
            assert len(rows) == 1
            assert rows[0].session_id == tutorial_id


class TestSessionCreationIsNotAGetRequest:

    def test_generate_qr_refuses_a_cross_site_navigation(self, appmod, seed, login):
        """
        `GET /generate_qr/<course>` created a class session, so any link,
        redirect or <img> on any site could open one in a lecturer's name —
        and every student enrolled at that moment was then absent from a class
        that never happened.
        """
        from models import ClassSession

        ada = login(seed['coordinator_email'])
        response = ada.get(f"/generate_qr/{seed['course_id']}")
        assert response.status_code == 405
        with appmod.app.app_context():
            assert ClassSession.query.filter_by(course_id=seed['course_id']).count() == 1


# ============================================================
# THE ACADEMIC CALENDAR
# ============================================================

class TestCoursesRecurNextTerm:

    def test_the_same_code_can_run_again_in_another_term(self, appmod, seed):
        """`code` was globally unique, so CSC201 could exist exactly once in
        the history of the institution."""
        from models import db, Course

        with appmod.app.app_context():
            existing = db.session.get(Course, seed['course_id'])
            repeat = Course(code='CSC201', title='Data Structures',
                            coordinator_id=existing.coordinator_id,
                            academic_year='2099/2100', semester='First')
            db.session.add(repeat)
            db.session.commit()
            assert Course.query.filter_by(code='CSC201').count() == 2

    def test_the_same_offering_twice_is_still_refused(self, appmod, seed):
        from sqlalchemy.exc import IntegrityError
        from models import db, Course

        with appmod.app.app_context():
            existing = db.session.get(Course, seed['course_id'])
            clash = Course(code='CSC201', title='Clash',
                           coordinator_id=existing.coordinator_id,
                           academic_year=existing.academic_year,
                           semester=existing.semester,
                           section=existing.section)
            db.session.add(clash)
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_last_years_sessions_do_not_count_towards_this_year(
            self, appmod, seed, login):
        """
        Reports accumulated across years: the same course row carried every
        session it had ever held, so an old term dragged the new one down
        forever. A term is a separate offering with its own sessions.
        """
        from models import db, Course, ClassSession

        with appmod.app.app_context():
            old = db.session.get(Course, seed['course_id'])
            fresh = Course(code='CSC201', title='Data Structures',
                           coordinator_id=old.coordinator_id,
                           department='Computer Science',
                           academic_year='2099/2100', semester='First')
            db.session.add(fresh)
            db.session.commit()
            fresh_id = fresh.id
            db.session.add(ClassSession(course_id=fresh_id, title='New term week 1'))
            db.session.commit()

            assert ClassSession.query.filter_by(course_id=seed['course_id']).count() == 1
            assert ClassSession.query.filter_by(course_id=fresh_id).count() == 1

    def test_an_archived_course_drops_off_the_working_dashboard(
            self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        assert b'CSC201' in ada.get('/lecturer_dashboard').data

        # follow_redirects so the confirmation flash (which names the course)
        # is consumed before the assertions below read the page.
        ada.post(f"/course/{seed['course_id']}/archive", follow_redirects=True)
        assert b'CSC201' not in ada.get('/lecturer_dashboard').data
        # ...but is still reachable when asked for.
        assert b'CSC201' in ada.get('/lecturer_dashboard?archived=1').data


class TestLocalTime:

    def test_timestamps_render_in_funaab_time_not_utc(self, appmod):
        from datetime import datetime

        from localtime import format_local, to_local

        # 23:30 UTC is 00:30 the NEXT day in Lagos.
        stored = datetime(2026, 3, 10, 23, 30)
        assert to_local(stored).hour == 0
        assert to_local(stored).day == 11
        assert format_local(stored, '%d %b %I:%M %p') == '11 Mar 12:30 AM'

    def test_today_is_a_local_day_not_a_utc_day(self, appmod):
        import datetime as dt

        from localtime import local_day_bounds_utc

        start, end = local_day_bounds_utc(dt.date(2026, 3, 11))
        # The local day begins an hour before midnight UTC.
        assert start == dt.datetime(2026, 3, 10, 23, 0)
        assert end == dt.datetime(2026, 3, 11, 23, 0)

    def test_the_attendance_page_states_the_timezone_it_is_showing(
            self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        page = ada.get(f"/course/{seed['course_id']}/attendance")
        assert b'Africa/Lagos' in page.data


# ============================================================
# ROSTER SNAPSHOTS
# ============================================================

class TestTheRosterIsFrozenPerClass:

    def _enrol(self, appmod, user_id, course_id):
        from models import db, Course, User
        with appmod.app.app_context():
            user = db.session.get(User, user_id)
            user.enrolled_courses.append(db.session.get(Course, course_id))
            db.session.commit()

    def test_a_late_joiner_is_not_absent_from_classes_held_before_they_enrolled(
            self, appmod, seed, login):
        """
        The denominator was every session the course had ever held, so a
        student who registered in week 6 opened their dashboard on 0% of five
        lectures they could not have attended.
        """
        # Tayo enrols AFTER the seeded session was opened and snapshotted.
        self._enrol(appmod, seed['other_student_id'], seed['course_id'])

        tayo = login(seed['other_student_email'])
        page = tayo.get('/student_dashboard')
        assert page.status_code == 200

        with appmod.app.app_context():
            from flask_login import login_user
            from models import db, User
            with appmod.app.test_request_context():
                login_user(db.session.get(User, seed['other_student_id']))
                _courses, rows = appmod._student_attendance_summary()
        row = next(r for r in rows if r['code'] == 'CSC201')
        assert row['total_sessions'] == 0, 'counted a class held before enrolment'
        assert row['pct'] is None

    def test_a_percentage_cannot_exceed_one_hundred_after_a_roster_change(
            self, appmod, seed, login):
        """
        Historical figures used today's enrolment as the denominator, so
        removing a student pushed everyone else's history above 100%.
        """
        from models import db, Course, User

        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance',
                  json={'qr_data': qr_token(appmod, seed['session_id'])})

        # The one enrolled student leaves the course after the class.
        with appmod.app.app_context():
            student = db.session.get(User, seed['student_id'])
            student.enrolled_courses.remove(db.session.get(Course, seed['course_id']))
            db.session.commit()

        ada = login(seed['coordinator_email'])
        page = ada.get(f"/course/{seed['course_id']}/attendance")
        assert page.status_code == 200
        # 1 present out of the 1 person who was on the roster that day.
        assert b'1 / 1 present' in page.data
        assert b'(100%)' in page.data

    def test_the_register_marks_pre_enrolment_classes_as_not_applicable(
            self, appmod, seed, login):
        self._enrol(appmod, seed['other_student_id'], seed['course_id'])
        ada = login(seed['coordinator_email'])
        register = ada.get(f"/course/{seed['course_id']}/download_csv")
        body = register.get_data(as_text=True)
        tayo_row = next(line for line in body.splitlines() if '20200002' in line)
        # Not "Absent": the class happened before they were on the roster.
        assert '"Absent"' not in tayo_row
        assert tayo_row.endswith('"0","0","0%"')


# ============================================================
# ACCESS CONTROL AND REPORTING CORRECTNESS
# ============================================================

class TestDestructiveActionsBelongToTheOwner:

    def test_an_invited_instructor_cannot_delete_a_session(
            self, appmod, seed, login):
        """
        Any invited instructor could destroy a whole meeting and every
        attendance record in it, including one they had no part in running.
        """
        from models import db, ClassSession

        ada = login(seed['coordinator_email'])
        ada.post('/add_instructor', data={'course_id': seed['course_id'],
                                          'lecturer_email': seed['lecturer_email']})

        grace = login(seed['lecturer_email'])
        grace.post(f"/session/{seed['session_id']}/delete")

        with appmod.app.app_context():
            assert db.session.get(ClassSession, seed['session_id']) is not None

    def test_the_coordinator_can_still_delete_a_session(self, appmod, seed, login):
        from models import db, ClassSession

        ada = login(seed['coordinator_email'])
        ada.post(f"/session/{seed['session_id']}/delete")
        with appmod.app.app_context():
            assert db.session.get(ClassSession, seed['session_id']) is None


class TestSupervisoryScopeAndMaths:

    def _promote(self, appmod, user_id, role, department=None, faculty=None):
        from models import db, User
        with appmod.app.app_context():
            user = db.session.get(User, user_id)
            user.role = role
            user.department = department
            user.faculty = faculty
            db.session.commit()

    def test_an_hod_with_no_department_sees_no_courses(self, appmod, seed, login):
        """
        `filter_by(department=None)` matched every course whose department was
        also NULL — the unclassified pile — which is the opposite of what an
        unplaced HOD is documented to see.
        """
        from models import db, Course

        with appmod.app.app_context():
            db.session.get(Course, seed['course_id']).department = None
            db.session.commit()

        self._promote(appmod, seed['outsider_id'], 'hod', department=None)
        hod = login(seed['outsider_email'])
        page = hod.get('/hod_dashboard')
        assert page.status_code == 200
        assert b'CSC201' not in page.data
        assert b'not linked to a department' in page.data

    def test_hod_analytics_reports_percentages_not_scan_counts(
            self, appmod, seed, login):
        """
        The chart is labelled "Average Attendance %" with its axis capped at
        100 and it was fed a raw count of scans, so every course above a
        hundred scans drew the same clipped, meaningless bar.
        """
        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance',
                  json={'qr_data': qr_token(appmod, seed['session_id'])})

        with appmod.app.app_context():
            data = appmod.get_department_analytics('Computer Science')

        assert data['labels'] == ['CSC201']
        # One scan, one place on the roster -> 100%, not "1".
        assert data['data'] == [100]
        assert data['meta'][0]['present'] == 1
        assert data['meta'][0]['expected'] == 1

    def test_an_hod_analytics_page_without_a_department_charts_nothing(
            self, appmod, seed, login):
        self._promote(appmod, seed['outsider_id'], 'hod', department=None)
        hod = login(seed['outsider_email'])
        assert hod.get('/hod_analytics').status_code == 200
        with appmod.app.app_context():
            assert appmod.get_department_analytics(None)['labels'] == []

    def test_a_dean_counts_lecturers_whatever_the_role_casing(
            self, appmod, seed, login):
        """
        `role='lecturer'` matched only the accounts CampOS created. Self-signup
        stores 'Lecturer', so a faculty of thirty could report four.
        """
        from models import db, User

        with appmod.app.app_context():
            # One of each spelling that reaches the database in practice.
            db.session.get(User, seed['lecturer_id']).role = 'Lecturer'
            db.session.get(User, seed['coordinator_id']).role = 'course coordinator'
            db.session.commit()

        self._promote(appmod, seed['outsider_id'], 'dean', faculty='Physical Sciences')
        dean = login(seed['outsider_email'])
        page = dean.get('/dean_dashboard')
        assert page.status_code == 200

        with appmod.app.app_context():
            count = (User.query
                     .filter(appmod.role_is('lecturer', 'course coordinator'),
                             User.faculty == 'Physical Sciences')
                     .count())
        assert count == 2

    def test_the_dap_counts_students_whatever_the_role_casing(
            self, appmod, seed, login):
        from models import db, User

        with appmod.app.app_context():
            db.session.get(User, seed['student_id']).role = 'Student'
            db.session.get(User, seed['other_student_id']).role = 'student'
            db.session.commit()
            assert User.query.filter(appmod.role_is('student')).count() == 2

    def test_supervisory_pages_link_onward_instead_of_dead_ending(
            self, appmod, seed, login):
        """HOD "Audit Attendance" pointed at href="#", and the analytics
        routes had no link from anywhere at all."""
        self._promote(appmod, seed['outsider_id'], 'hod',
                      department='Computer Science')
        hod = login(seed['outsider_email'])
        page = hod.get('/hod_dashboard').get_data(as_text=True)
        assert 'href="#"' not in page
        assert f"/course/{seed['course_id']}/attendance" in page
        assert '/hod_analytics' in page

        self._promote(appmod, seed['outsider_id'], 'dap')
        dap = login(seed['outsider_email'])
        assert '/dap_analytics' in dap.get('/dap_dashboard').get_data(as_text=True)


class TestPageSizeAndCounts:

    def _many_sessions(self, appmod, course_id, count):
        from models import db, ClassSession
        with appmod.app.app_context():
            for index in range(count):
                row = ClassSession(course_id=course_id, title=f'Week {index + 2}')
                db.session.add(row)
                db.session.flush()
                appmod._snapshot_roster(row)
            db.session.commit()

    def test_the_header_counts_every_class_held_not_just_this_page(
            self, appmod, seed, login):
        """It printed len(sessions_data) — the number on the current page,
        capped at ten however long the semester ran."""
        self._many_sessions(appmod, seed['course_id'], 14)

        ada = login(seed['coordinator_email'])
        page = ada.get(f"/course/{seed['course_id']}/attendance")
        assert b'<strong>15</strong> class' in page.data
        assert b'<strong>10</strong> class' not in page.data

    def test_only_a_bounded_number_of_rows_is_rendered_per_session(
            self, appmod, seed, login, monkeypatch):
        from models import db, Attendance, User
        from werkzeug.security import generate_password_hash

        monkeypatch.setattr(appmod, 'ATTENDANCE_PREVIEW_ROWS', 3)
        with appmod.app.app_context():
            for index in range(8):
                extra = User(full_name=f'Bulk Student {index}',
                             email=f'bulk{index}@student.funaab.edu.ng',
                             password=generate_password_hash('x', method='scrypt'),
                             role='student', matric_no=f'9900{index}',
                             level='300', email_verified=True)
                db.session.add(extra)
                db.session.flush()
                db.session.add(Attendance(student_id=extra.id,
                                          course_id=seed['course_id'],
                                          session_id=seed['session_id']))
            db.session.commit()

        ada = login(seed['coordinator_email'])
        body = ada.get(f"/course/{seed['course_id']}/attendance").get_data(as_text=True)
        assert body.count('Bulk Student') <= 3
        assert 'Showing the first 3 of 8 scans' in body
        # The full sheet is a page of its own.
        assert f"/session/{seed['session_id']}/attendance" in body

    def test_the_full_session_sheet_paginates(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        page = ada.get(f"/session/{seed['session_id']}/attendance")
        assert page.status_code == 200

    def test_the_roster_api_is_paginated(self, appmod, seed, login):
        """It returned the entire roster in one document — megabytes for a
        2000-student course, built from 2000 ORM objects."""
        from models import db, Course, User
        from werkzeug.security import generate_password_hash

        with appmod.app.app_context():
            course = db.session.get(Course, seed['course_id'])
            for index in range(6):
                extra = User(full_name=f'Roster {index}',
                             email=f'roster{index}@student.funaab.edu.ng',
                             password=generate_password_hash('x', method='scrypt'),
                             role='student', matric_no=f'8800{index}',
                             level='300', email_verified=True)
                extra.enrolled_courses.append(course)
                db.session.add(extra)
            db.session.commit()

        ada = login(seed['coordinator_email'])
        first = ada.get(
            f"/api/course/{seed['course_id']}/enrolled_students?limit=2").get_json()
        assert len(first['students']) == 2
        assert first['has_more'] is True
        assert first['total'] == 7

        second = ada.get(f"/api/course/{seed['course_id']}/enrolled_students"
                         f"?limit=2&after={first['last_id']}").get_json()
        assert len(second['students']) == 2
        assert second['students'][0]['id'] != first['students'][0]['id']

    def test_the_instructors_tile_shows_a_number(self, appmod, seed, login):
        """It was rendered as an em dash by a deliberate `if false`."""
        ada = login(seed['coordinator_email'])
        ada.post('/add_instructor', data={'course_id': seed['course_id'],
                                          'lecturer_email': seed['lecturer_email']})
        body = ada.get('/lecturer_dashboard').get_data(as_text=True)
        assert 'if false' not in body
        # The coordinator plus the invited lecturer.
        assert '<div class="stat-number">2</div>' in body


# ============================================================
# REFERENTIAL INTEGRITY
# ============================================================

class TestForeignKeysAreEnforced:

    def test_sqlite_enforces_foreign_keys(self, appmod):
        """
        With them off, development and CI happily write rows production's
        constraints forbid, so a referential bug is only ever found by
        students.
        """
        from models import db

        with appmod.app.app_context():
            if db.engine.dialect.name != 'sqlite':
                pytest.skip('SQLite-specific pragma')
            enabled = db.session.execute(db.text('PRAGMA foreign_keys')).scalar()
            assert enabled == 1

    def test_an_orphan_attendance_row_is_refused(self, appmod, seed):
        from sqlalchemy.exc import IntegrityError
        from models import db, Attendance

        with appmod.app.app_context():
            if db.engine.dialect.name != 'sqlite':
                pytest.skip('SQLite-specific pragma')
            db.session.add(Attendance(student_id=seed['student_id'],
                                      course_id=999999,
                                      session_id=seed['session_id']))
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_a_referencing_table_created_after_boot_is_still_cleared(
            self, appmod, seed, login):
        """
        Detection ran once at boot, so a table that appeared afterwards — an
        upgrade against a live deployment, a restored dump — blocked every
        course deletion with a foreign-key violation.
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
            db.session.execute(
                db.text('INSERT INTO early_warning '
                        '(student_id, course_id, last_sent_on, last_percentage) '
                        'VALUES (:s, :c, :d, 0.0)'),
                {'s': seed['student_id'], 'c': seed['course_id'],
                 'd': datetime.date.today()})
            db.session.commit()

        # Deliberately NOT monkeypatched: the boot-time list is empty, and the
        # route has to discover the table for itself.
        assert appmod.LEGACY_COURSE_REF_TABLES == ()

        ada = login(seed['coordinator_email'])
        response = ada.post(f"/delete_course/{seed['course_id']}",
                            follow_redirects=True)
        assert response.status_code == 200

        with appmod.app.app_context():
            assert db.session.get(Course, seed['course_id']) is None
            db.session.execute(db.text('DROP TABLE early_warning'))
            db.session.commit()


class TestMigrationFailuresAreFatal:

    def test_a_failed_migration_step_stops_the_process(self, appmod):
        """
        "will retry next boot" was never true for the unique attendance index:
        the worker carried on serving without it, so every scan hit ON
        CONFLICT with no matching constraint — a 500 per student, for the
        whole class.
        """
        source = open('app.py', encoding='utf-8').read()
        assert '_fatal_migration' in source
        # The three swallow-and-continue prints are gone.
        assert 'Index creation failed (will retry next boot)' not in source
        assert 'Duplicate-attendance cleanup failed' not in source

    def test_the_unique_scan_index_exists(self, appmod):
        from models import db

        with appmod.app.app_context():
            names = {index['name'] for index in
                     db.inspect(db.engine).get_indexes('attendance')}
        assert 'uq_attendance_student_session' in names


# ============================================================
# AUDIT TRAIL
# ============================================================

class TestAuditTrail:

    def test_deleting_a_session_is_recorded(self, appmod, seed, login):
        from models import AuditLog

        kemi = login(seed['student_email'])
        kemi.post('/mark_attendance',
                  json={'qr_data': qr_token(appmod, seed['session_id'])})

        ada = login(seed['coordinator_email'])
        ada.post(f"/session/{seed['session_id']}/delete")

        with appmod.app.app_context():
            entry = AuditLog.query.filter_by(action='session.delete').one()
            assert entry.actor_id == seed['coordinator_id']
            assert entry.target_id == seed['session_id']
            assert '"attendance_deleted": 1' in entry.details

    def test_deleting_a_course_is_recorded_and_survives_the_course(
            self, appmod, seed, login):
        from models import db, AuditLog, Course

        ada = login(seed['coordinator_email'])
        ada.post(f"/delete_course/{seed['course_id']}")

        with appmod.app.app_context():
            assert db.session.get(Course, seed['course_id']) is None
            entry = AuditLog.query.filter_by(action='course.delete').one()
            assert entry.target_label.startswith('CSC201')
            assert entry.actor_email == seed['coordinator_email']

    def test_the_trail_is_readable_for_a_course(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        ada.post(f"/course/{seed['course_id']}/start_session",
                 data={'new_session': '1'})
        page = ada.get(f"/course/{seed['course_id']}/audit")
        assert page.status_code == 200
        assert b'session.start' in page.data

    def test_a_student_cannot_read_the_trail(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        assert kemi.get(f"/course/{seed['course_id']}/audit").status_code == 302


# ============================================================
# SECURITY: ACCOUNTS AND SESSIONS
# ============================================================

class TestGoogleSignIn:

    def _callback(self, appmod, monkeypatch, userinfo):
        monkeypatch.setattr(appmod.google, 'authorize_access_token',
                            lambda: {'userinfo': userinfo})
        return appmod.app.test_client().get('/authorize/google',
                                            follow_redirects=False)

    def test_an_unverified_google_address_is_refused(self, appmod, monkeypatch):
        from models import User

        response = self._callback(appmod, monkeypatch, {
            'email': 'stranger@gmail.com', 'name': 'Stranger',
            'email_verified': False})
        assert response.status_code == 302
        with appmod.app.app_context():
            assert User.query.filter_by(email='stranger@gmail.com').first() is None

    def test_a_missing_email_verified_claim_is_refused(self, appmod, monkeypatch):
        """
        `is not False` also accepted a claim that was absent or null — which
        is exactly the case where Google is telling us it has not checked.
        """
        from models import User

        response = self._callback(appmod, monkeypatch, {
            'email': 'unchecked@gmail.com', 'name': 'Unchecked'})
        assert response.status_code == 302
        with appmod.app.app_context():
            assert User.query.filter_by(email='unchecked@gmail.com').first() is None

        self._callback(appmod, monkeypatch, {
            'email': 'null@gmail.com', 'name': 'Null', 'email_verified': None})
        with appmod.app.app_context():
            assert User.query.filter_by(email='null@gmail.com').first() is None

    def test_google_retires_a_squatters_password(self, appmod, monkeypatch):
        """
        An attacker registered someone else's Gmail with a password of their
        choosing. When the real owner signed in through Google the account
        became verified and the attacker's password kept working. CampOS
        retires that password; Google did not.
        """
        from werkzeug.security import check_password_hash
        from models import db, User

        with appmod.app.app_context():
            squatter = User(full_name='Squatter', email='victim@gmail.com',
                            password=__import__('werkzeug.security', fromlist=['x'])
                            .generate_password_hash('attacker-pass-1', method='scrypt'),
                            role='student', email_verified=False)
            db.session.add(squatter)
            db.session.commit()
            victim_id = squatter.id

        self._callback(appmod, monkeypatch, {
            'email': 'victim@gmail.com', 'name': 'Real Owner',
            'email_verified': True})

        with appmod.app.app_context():
            user = db.session.get(User, victim_id)
            assert user.email_verified is True
            assert not check_password_hash(user.password, 'attacker-pass-1'), \
                "the squatter's password still works on the verified account"
            # And anything that password already minted is revoked with it.
            assert user.security_stamp

    def test_a_verified_account_is_left_alone(self, appmod, monkeypatch):
        from werkzeug.security import check_password_hash, generate_password_hash
        from models import db, User

        with appmod.app.app_context():
            owner = User(full_name='Owner', email='owner@gmail.com',
                         password=generate_password_hash('my-own-pass-1',
                                                         method='scrypt'),
                         role='student', email_verified=True)
            db.session.add(owner)
            db.session.commit()
            owner_id = owner.id

        self._callback(appmod, monkeypatch, {
            'email': 'owner@gmail.com', 'name': 'Owner', 'email_verified': True})

        with appmod.app.app_context():
            assert check_password_hash(
                db.session.get(User, owner_id).password, 'my-own-pass-1')


class TestPasswordResetRevokesSessions:

    def test_an_existing_session_stops_working_after_a_reset(
            self, appmod, seed, login):
        """
        Somebody resets a password because they think somebody else has it.
        The intruder's session in Redis and their 30-day remember-me cookie
        both kept working, which made the reset theatre.
        """
        from models import db, User

        intruder = login(seed['student_email'])
        assert intruder.get('/student_dashboard').status_code == 200

        with appmod.app.app_context():
            user = db.session.get(User, seed['student_id'])
            token = appmod.serializer.dumps(
                {'email': user.email,
                 'pw': appmod._password_fingerprint(user.password)},
                salt='password-reset-salt')

        victim = appmod.app.test_client()
        assert victim.post(f'/reset_password/{token}',
                           data={'password': 'brand-new-pass-9'}).status_code == 302

        # The session that existed before the reset no longer resolves.
        assert intruder.get('/student_dashboard').status_code == 302

    def test_the_new_password_works(self, appmod, seed, login):
        from models import db, User

        with appmod.app.app_context():
            user = db.session.get(User, seed['student_id'])
            token = appmod.serializer.dumps(
                {'email': user.email,
                 'pw': appmod._password_fingerprint(user.password)},
                salt='password-reset-salt')

        appmod.app.test_client().post(f'/reset_password/{token}',
                                      data={'password': 'brand-new-pass-9'})
        fresh = login(seed['student_email'], 'brand-new-pass-9')
        assert fresh.get('/student_dashboard').status_code == 200


class TestPasswordPolicyMatchesWhatIsAdvertised:

    @pytest.mark.parametrize('password,reason', [
        ('aaaaaaaaa!', 'no number'),
        ('!!!!!!!!!!', 'no letter and no number'),
        ('----------', 'symbols only'),
    ])
    def test_a_password_with_no_number_is_refused(self, appmod, password, reason):
        """
        The rule refused a password only when it was ENTIRELY digits or
        ENTIRELY letters, so 'aaaaaaaaa!' passed with no number in it while
        the signup page promised letters and numbers.
        """
        problem = appmod.validate_password_strength(password)
        assert problem is not None, f'accepted a password with {reason}'

    @pytest.mark.parametrize('password', ['correct-horse-9', 'Passw0rdLong'])
    def test_a_conforming_password_is_accepted(self, appmod, password):
        assert appmod.validate_password_strength(password) is None

    def test_the_page_advertises_the_rule_the_server_enforces(self, appmod, client):
        body = client.get('/signup').get_data(as_text=True)
        assert 'one letter and one number' in body


class TestUnknownRolesDoNotLoop:

    def test_an_unrecognised_role_lands_on_a_page_that_stays_put(
            self, appmod, seed, login):
        """
        /dashboard → /student_dashboard → /login → /student_dashboard, forever,
        with no way out but closing the tab.
        """
        from models import db, User

        with appmod.app.app_context():
            db.session.get(User, seed['student_id']).role = 'visiting-fellow'
            db.session.commit()

        user = login(seed['student_email'])
        response = user.get('/dashboard', follow_redirects=True)
        assert response.status_code == 403
        assert b'no dashboard yet' in response.data

        # And the terminal page does not bounce anywhere.
        assert user.get('/account_pending').status_code == 403

    def test_a_known_role_never_reaches_the_pending_page(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        assert kemi.get('/account_pending').status_code == 302


class TestLogoutIsNotAGetRequest:

    def test_a_get_logout_is_refused(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        assert kemi.get('/logout').status_code == 405
        # Still signed in.
        assert kemi.get('/student_dashboard').status_code == 200

    def test_a_post_logout_works(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        assert kemi.post('/logout').status_code == 302
        assert kemi.get('/student_dashboard').status_code == 302


class TestCompleteProfile:

    def test_a_malformed_matric_number_is_refused(self, appmod, seed, login):
        from models import db, User

        with appmod.app.app_context():
            db.session.get(User, seed['student_id']).matric_no = None
            db.session.commit()

        kemi = login(seed['student_email'])
        response = kemi.post('/complete_profile',
                             data={'matric_no': '!!', 'level': '300'})
        assert response.status_code == 400

    def test_an_invented_level_is_refused(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        response = kemi.post('/complete_profile',
                             data={'matric_no': '20200099', 'level': 'professor'})
        assert response.status_code == 400

    def test_a_duplicate_matric_number_does_not_500(self, appmod, seed, login):
        """It had no handler for the unique constraint, on a page every new
        student sees."""
        kemi = login(seed['student_email'])
        response = kemi.post('/complete_profile',
                             data={'matric_no': '20200002',   # Tayo's
                                   'level': '300'})
        assert response.status_code == 409
        assert b'already registered' in response.data

    def test_staff_cannot_claim_a_matric_number(self, appmod, seed, login):
        from models import db, User

        grace = login(seed['lecturer_email'])
        response = grace.post('/complete_profile',
                              data={'matric_no': '20200003', 'level': '300'})
        assert response.status_code == 302
        with appmod.app.app_context():
            assert db.session.get(User, seed['lecturer_id']).matric_no is None


# ============================================================
# SECURITY: DEPLOYMENT AND OUTPUT HANDLING
# ============================================================

class TestProductionDetectionFailsClosed:

    def test_an_undeclared_environment_counts_as_production(self):
        """
        It recognised only FLASK_ENV=production and RENDER=true, so the same
        image on any other host ran with the public development secret,
        insecure cookies, no HSTS and email verification disabled.
        """
        from campos_integration import is_production_environment

        assert is_production_environment({}) is True
        assert is_production_environment({'FLY_APP_NAME': 'scanmark'}) is True
        assert is_production_environment({'DYNO': 'web.1'}) is True
        assert is_production_environment({'K_SERVICE': 'scanmark'}) is True

    def test_only_an_explicit_declaration_opts_out(self):
        from campos_integration import is_production_environment

        assert is_production_environment({'FLASK_ENV': 'development'}) is False
        assert is_production_environment({'SCANMARK_ENV': 'testing'}) is False
        assert is_production_environment({'FLASK_ENV': 'production'}) is True
        # An unrecognised value is not a licence to relax.
        assert is_production_environment({'FLASK_ENV': 'staging'}) is True

    def test_the_remember_cookie_follows_the_same_decision_as_the_session(
            self, appmod):
        """
        On Render (RENDER=true, FLASK_ENV unset) the session cookie was Secure
        and the 30-day remember-me cookie was then overwritten to False by a
        second, raw FLASK_ENV comparison.
        """
        assert (appmod.app.config['REMEMBER_COOKIE_SECURE']
                == appmod.app.config['SESSION_COOKIE_SECURE'])
        source = open('app.py', encoding='utf-8').read()
        assert "REMEMBER_COOKIE_SECURE'] = os.environ.get('FLASK_ENV')" not in source


class TestExternalLinksIgnoreTheHostHeader:

    def test_a_reset_link_is_built_from_the_configured_origin(
            self, appmod, monkeypatch):
        """
        `_external=True` builds from the incoming Host header, so a request
        carrying `Host: evil.example` produced an emailed link on
        evil.example — handing the signed reset token to whoever sent it.
        """
        monkeypatch.setattr(appmod, 'PUBLIC_ORIGIN_HOST', 'scanmark.funaab.edu.ng')
        monkeypatch.setattr(appmod, 'PUBLIC_ORIGIN_SCHEME', 'https')

        with appmod.app.test_request_context('/', base_url='http://evil.example'):
            link = appmod.external_url_for('reset_password', token='abc')
        assert link.startswith('https://scanmark.funaab.edu.ng/')
        assert 'evil.example' not in link

    def test_a_request_for_an_unrecognised_host_is_refused(
            self, appmod, monkeypatch):
        monkeypatch.setattr(appmod, 'TRUSTED_HOSTS', {'scanmark.funaab.edu.ng'})
        client = appmod.app.test_client()
        assert client.get('/login', base_url='http://evil.example').status_code == 421
        assert client.get('/login',
                          base_url='http://scanmark.funaab.edu.ng').status_code == 200


class TestCsvSafety:

    def test_a_formula_cell_is_neutralised(self, appmod):
        """
        Quoting does not stop this: spreadsheets parse the cell after
        unquoting it, so the register ran the formula in the lecturer's
        session the moment they opened it.
        """
        assert appmod._csv_cell('=HYPERLINK("http://evil","payroll")') \
            .startswith('"\'=')
        for leader in ('=', '+', '-', '@'):
            assert appmod._csv_cell(f'{leader}cmd').startswith('"\'')
        # Ordinary values are untouched.
        assert appmod._csv_cell('Doe, John') == '"Doe, John"'

    def test_a_formula_name_survives_the_register_as_text(
            self, appmod, seed, login):
        from models import db, User

        with appmod.app.app_context():
            db.session.get(User, seed['student_id']).full_name = '=1+1'
            db.session.commit()

        ada = login(seed['coordinator_email'])
        body = ada.get(f"/course/{seed['course_id']}/download_csv") \
                  .get_data(as_text=True)
        assert '"\'=1+1"' in body

    def test_a_course_code_with_a_newline_cannot_break_the_header(
            self, appmod, seed, login):
        """An internal CR/LF made werkzeug refuse the Content-Disposition
        value and turned the export into a 500."""
        from models import db, Course

        with appmod.app.app_context():
            db.session.get(Course, seed['course_id']).code = 'CSC\r\n201'
            db.session.commit()

        ada = login(seed['coordinator_email'])
        response = ada.get(f"/course/{seed['course_id']}/download_csv")
        assert response.status_code == 200
        disposition = response.headers['Content-Disposition']
        assert '\r' not in disposition and '\n' not in disposition

    def test_a_control_character_never_reaches_a_stored_course_code(
            self, appmod, seed, login):
        """Sanitised on the way in, so no later consumer has to remember."""
        from models import Course

        ada = login(seed['coordinator_email'])
        ada.post('/add_course', data={'code': 'CS\r\nC9', 'title': 'Injected'})
        with appmod.app.app_context():
            stored = Course.query.filter_by(title='Injected').first()
            assert stored is not None
            assert stored.code == 'CS C9'
            assert not any(ord(character) < 32 for character in stored.code)

    def test_a_course_code_of_pure_punctuation_is_rejected(
            self, appmod, seed, login):
        from models import Course

        ada = login(seed['coordinator_email'])
        ada.post('/add_course', data={'code': '///', 'title': 'Nonsense'})
        with appmod.app.app_context():
            assert Course.query.filter_by(title='Nonsense').first() is None


class TestEmailsAreEscaped:

    def test_a_name_containing_markup_is_escaped_in_the_html_body(
            self, appmod, monkeypatch):
        """
        A full name is whatever the person typed into the signup form, and it
        was interpolated straight into an HTML email.
        """
        captured = {}

        def capture(subject, recipients, text_body, html_body, sender=None):
            captured['html'] = html_body

        monkeypatch.setattr(appmod, 'send_email', capture)
        with appmod.app.test_request_context():
            appmod.send_welcome_email('victim@gmail.com',
                                      '<script>alert(1)</script>', 'student')

        assert '<script>alert(1)</script>' not in captured['html']
        assert '&lt;script&gt;' in captured['html']


class TestQrReplayWindow:

    def test_a_code_read_long_before_the_request_is_refused(
            self, appmod, seed, login):
        """
        The only freshness check was the token's age at the server. A capture
        time far outside the window is a photograph being replayed, not a
        camera reading the screen.
        """
        token = qr_token(appmod, seed['session_id'])
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={
            'qr_data': token,
            'captured_at': (time.time() - 3600) * 1000,
        })
        assert response.status_code == 400
        assert 'not read from the screen' in response.get_json()['message']

    def test_an_honest_capture_time_is_accepted(self, appmod, seed, login):
        from datetime import datetime, timezone

        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json={
            'qr_data': qr_token(appmod, seed['session_id']),
            'captured_at': datetime.now(timezone.utc).isoformat(),
        })
        assert response.status_code == 200


class TestReadiness:

    def test_healthz_reports_unhealthy_when_a_dependency_is_down(
            self, appmod, monkeypatch):
        """
        It answered 204 from the WSGI layer without checking anything, so a
        dead database left the deployment 'healthy' while every real request
        failed.
        """
        def broken():
            raise RuntimeError('database is gone')

        monkeypatch.setattr(appmod, '_check_database', broken)
        appmod._readiness_cache['report'] = None
        try:
            response = appmod.app.test_client().get('/healthz')
            assert response.status_code == 503
            assert response.get_json()['checks']['database'].startswith('error')
        finally:
            appmod._readiness_cache['report'] = None

    def test_healthz_is_204_when_everything_is_up(self, appmod):
        appmod._readiness_cache['report'] = None
        assert appmod.app.test_client().get('/healthz').status_code == 204


class TestCamposSsoIsBoundToTheBrowser:

    def test_a_callback_without_state_is_refused_by_default(
            self, appmod, monkeypatch):
        """
        Anyone who obtains a hand-off code — including one an attacker made
        for their own account — could feed it to somebody else's browser and
        silently sign that browser into the attacker's account, where the
        victim's scans were then recorded.
        """
        assert appmod.CAMPOS_SSO_REQUIRE_STATE is True

        called = []
        monkeypatch.setattr(appmod, 'exchange_campos_sso_code',
                            lambda code: called.append(code))

        response = appmod.app.test_client().get('/sso/callback?code=' + 'a' * 43)
        assert response.status_code == 302
        assert called == [], 'redeemed a code with no browser-bound state'

    def test_a_mismatched_state_is_refused(self, appmod, monkeypatch):
        called = []
        monkeypatch.setattr(appmod, 'exchange_campos_sso_code',
                            lambda code: called.append(code))

        client = appmod.app.test_client()
        with appmod.app.test_request_context():
            cookie = appmod.serializer.dumps('the-real-nonce',
                                             salt='campos-sso-state')
        client.set_cookie('campos_sso_state', cookie,
                          domain='localhost.localdomain')
        response = client.get(f"/sso/callback?code={'a' * 43}&state=not-the-nonce")
        assert response.status_code == 302
        assert called == []


class TestTheOfflineQueueTellsTheTruth:

    def test_a_scan_rejected_because_the_class_ended_is_distinguishable(
            self, appmod, seed, login):
        """
        The queue reported every 409 as "recorded", because 409 used to mean
        only "already marked". It now also means the class had ended and the
        scan landed nowhere — reporting that as recorded tells a student they
        are present when they are not.
        """
        token = qr_token(appmod, seed['session_id'])
        ada = login(seed['coordinator_email'])
        ada.post(f"/session/{seed['session_id']}/end")

        kemi = login(seed['student_email'])
        body = kemi.post('/mark_attendance', json={'qr_data': token}).get_json()
        assert body['outcome'] == 'session_ended'

    def test_a_genuine_duplicate_still_reports_as_a_duplicate(
            self, appmod, seed, login):
        kemi = login(seed['student_email'])
        token = qr_token(appmod, seed['session_id'])
        kemi.post('/mark_attendance', json={'qr_data': token})
        body = kemi.post('/mark_attendance', json={'qr_data': token}).get_json()
        assert body['outcome'] == 'duplicate'

    def test_the_queue_matches_on_the_outcome_not_the_status(self, appmod):
        page = open('templates/base.html', encoding='utf-8').read()
        assert "payload.outcome === 'duplicate'" in page
        assert 'response.status === 409' not in page


class TestUpgradingAnExistingDatabase:
    """
    The migration path from the schema that is in production today. Run in a
    subprocess against a throwaway file, because it is the *boot* that has to
    do the work.
    """

    LEGACY_SCHEMA = '''
        CREATE TABLE "user" (id INTEGER PRIMARY KEY, campos_user_id VARCHAR(100) UNIQUE,
          campos_institution_id VARCHAR(100), full_name VARCHAR(100) NOT NULL,
          email VARCHAR(120) NOT NULL UNIQUE, password VARCHAR(200) NOT NULL,
          email_verified BOOLEAN, role VARCHAR(20) NOT NULL, department VARCHAR(50),
          matric_no VARCHAR(20) UNIQUE, level VARCHAR(10), faculty VARCHAR(50));
        CREATE TABLE course (id INTEGER PRIMARY KEY, code VARCHAR(10) NOT NULL UNIQUE,
          title VARCHAR(100) NOT NULL, department VARCHAR(50),
          coordinator_id INTEGER NOT NULL REFERENCES "user"(id), faculty VARCHAR(50));
        CREATE TABLE class_session (id INTEGER PRIMARY KEY,
          course_id INTEGER NOT NULL REFERENCES course(id),
          title VARCHAR(100) NOT NULL, date_created DATETIME);
        CREATE TABLE attendance (id INTEGER PRIMARY KEY,
          student_id INTEGER NOT NULL REFERENCES "user"(id),
          course_id INTEGER NOT NULL REFERENCES course(id),
          session_id INTEGER REFERENCES class_session(id), timestamp DATETIME,
          device_id VARCHAR(200));
        CREATE TABLE enrollments (user_id INTEGER NOT NULL REFERENCES "user"(id),
          course_id INTEGER NOT NULL REFERENCES course(id),
          PRIMARY KEY (user_id, course_id));
        CREATE TABLE course_instructors (user_id INTEGER NOT NULL REFERENCES "user"(id),
          course_id INTEGER NOT NULL REFERENCES course(id),
          PRIMARY KEY (user_id, course_id));
        INSERT INTO "user" VALUES (1,NULL,NULL,'Ada','ada@staff.funaab.edu.ng','h',1,
          'Course Coordinator','CS',NULL,NULL,'PS');
        INSERT INTO "user" VALUES (2,NULL,NULL,'Kemi','k@student.funaab.edu.ng','h',1,
          'student',NULL,'20200001','300',NULL);
        INSERT INTO course VALUES (1,'CSC201','Data Structures','CS',1,'PS');
        INSERT INTO class_session VALUES (1,1,'Week 1','2026-03-01 09:00:00');
        INSERT INTO enrollments VALUES (2,1);
        INSERT INTO attendance VALUES (1,2,1,1,'2026-03-01 09:05:00','browser');
    '''

    def _boot_against(self, tmp_path):
        import os
        import sqlite3
        import subprocess
        import sys

        database = tmp_path / 'legacy.db'
        connection = sqlite3.connect(database)
        connection.executescript(self.LEGACY_SCHEMA)
        connection.commit()
        connection.close()

        environment = dict(os.environ,
                           SECRET_KEY='upgrade-test',
                           FLASK_ENV='testing',
                           DATABASE_URL=f'sqlite:///{database}')
        environment.pop('REDIS_URL', None)
        result = subprocess.run(
            [sys.executable, '-c', 'import app'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=environment, capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        return database, result.stdout

    def test_an_existing_database_upgrades_without_losing_anything(self, tmp_path):
        import sqlite3

        database, output = self._boot_against(tmp_path)
        assert 'Database initialized successfully' in output

        connection = sqlite3.connect(database)
        try:
            counts = {
                table: connection.execute(
                    f'SELECT count(*) FROM {table}').fetchone()[0]
                for table in ('user', 'course', 'class_session',
                              'attendance', 'enrollments')
            }
            assert counts == {'user': 2, 'course': 1, 'class_session': 1,
                              'attendance': 1, 'enrollments': 1}
            # Adopted into the current term rather than left without one.
            year, semester = connection.execute(
                'SELECT academic_year, semester FROM course').fetchone()
            assert year and semester
            # Sessions that predate the lifecycle are closed, not left open
            # with their tokens still redeemable.
            assert connection.execute(
                'SELECT active FROM class_session').fetchone()[0] in (0, None)
            # And they got a roster snapshot, so their percentages stop moving.
            assert connection.execute(
                'SELECT count(*) FROM session_roster').fetchone()[0] == 1
            assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        finally:
            connection.close()

    def test_the_legacy_global_unique_on_course_code_is_actually_removed(
            self, tmp_path):
        """
        SQLite bakes a column-level UNIQUE into the table definition, and
        SQLAlchemy's inspector does not report it — so a migration that only
        looks at the inspector reports success while the database still
        refuses to let CSC201 run a second time.
        """
        import sqlite3

        database, output = self._boot_against(tmp_path)
        assert 'Rebuilding `course`' in output

        connection = sqlite3.connect(database)
        try:
            offering = ("INSERT INTO course (code,title,department,coordinator_id,"
                        "faculty,academic_year,semester,section,archived) VALUES "
                        "('CSC201',?,'CS',1,'PS',?,'First','',0)")
            connection.execute(offering, ('Next Year', '2099/2100'))
            connection.commit()

            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(offering, ('Same Offering', '2099/2100'))
                connection.commit()
        finally:
            connection.close()

    def test_booting_twice_over_the_same_database_changes_nothing(self, tmp_path):
        import os
        import subprocess
        import sys

        database, _first = self._boot_against(tmp_path)
        environment = dict(os.environ, SECRET_KEY='upgrade-test',
                           FLASK_ENV='testing',
                           DATABASE_URL=f'sqlite:///{database}')
        environment.pop('REDIS_URL', None)
        second = subprocess.run([sys.executable, '-c', 'import app'],
                                cwd=os.path.dirname(os.path.abspath(__file__)),
                                env=environment, capture_output=True, text=True,
                                timeout=180)
        assert second.returncode == 0, second.stdout + second.stderr
        assert 'Rebuilding `course`' not in second.stdout
        assert '[MIGRATION] Added' not in second.stdout


class TestTheTrailIsFindableAfterTheFact:

    def test_every_action_on_a_course_appears_in_its_trail(
            self, appmod, seed, login):
        """
        Entries were matched with a LIKE over the JSON details, which only hit
        when `course_id` happened not to be the last key — and course creation
        recorded no id at all, because the row had none until it was flushed.
        """
        from models import AuditLog

        ada = login(seed['coordinator_email'])
        ada.post('/add_course', data={'code': 'CSC777', 'title': 'Findable'})
        ada.post(f"/course/{seed['course_id']}/start_session",
                 data={'new_session': '1'})
        ada.post(f"/course/{seed['course_id']}/archive")

        with appmod.app.app_context():
            from models import Course
            created = Course.query.filter_by(code='CSC777').one()
            assert AuditLog.query.filter_by(course_id=created.id,
                                            action='course.create').count() == 1

            actions = {row.action for row in
                       AuditLog.query.filter_by(course_id=seed['course_id']).all()}
        assert {'session.start', 'session.end', 'course.archive'} <= actions

    def test_the_trail_page_lists_them(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        ada.post(f"/course/{seed['course_id']}/start_session",
                 data={'new_session': '1'})
        body = ada.get(f"/course/{seed['course_id']}/audit").get_data(as_text=True)
        assert 'session.start' in body
        assert 'session.end' in body


class TestTheAuditLogIsNotCollateral:

    def test_clearing_a_courses_references_never_touches_the_audit_log(
            self, appmod, seed):
        """
        Course deletion clears every table that references the course. The
        audit log carries a course_id and must not be one of them — deleting
        the record of a deletion along with it defeats the whole point.
        """
        with appmod.app.app_context():
            assert 'audit_log' not in appmod.discover_course_ref_tables()

    def test_the_trail_outlives_every_row_it_names(self, appmod, seed, login):
        from models import db, AuditLog, ClassSession, Course

        ada = login(seed['coordinator_email'])
        ada.post(f"/course/{seed['course_id']}/start_session",
                 data={'new_session': '1'})
        ada.post(f"/delete_course/{seed['course_id']}")

        with appmod.app.app_context():
            assert db.session.get(Course, seed['course_id']) is None
            assert ClassSession.query.filter_by(
                course_id=seed['course_id']).count() == 0
            surviving = AuditLog.query.filter_by(
                course_id=seed['course_id']).all()
            assert {entry.action for entry in surviving} >= {
                'session.start', 'course.delete'}
