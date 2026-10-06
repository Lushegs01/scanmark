"""
Event Check-In Mode: the public walk-up check-in, its projector feed and the
host pages. None of it touches courses, enrolment or /mark_attendance, and
the last tests here hold that line.
"""
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from conftest import scan_body

DEVICE_COOKIE = 'scanmark_event_device'
DEPARTMENTS = ['Computer Science', 'Cyber Security']


def _event_form(**overrides):
    form = {
        'title': 'CCS Freshers Orientation 2026',
        'subtitle': 'College of Computing Sciences',
        'venue': 'FUNAAB',
        'starts_at_local': '2026-10-07T09:00',
        'ends_at_local': '',
        'department_options': '\n'.join(DEPARTMENTS),
        'schedule_url': 'https://example.org/schedule',
        'info_url': '',
        'links_url': '',
        'community_url': 'https://example.org/community',
        'extra_links': 'Campus map | https://example.org/map',
    }
    form.update(overrides)
    return form


@pytest.fixture()
def host(seed, login):
    return login(seed['coordinator_email'])


@pytest.fixture()
def event_token(appmod, host):
    response = host.post('/events/new', data=_event_form())
    assert response.status_code == 302, response.data
    match = re.search(r'/event/([A-Za-z0-9_-]+)/manage', response.headers['Location'])
    assert match, response.headers['Location']
    return match.group(1)


def _checkins(appmod):
    from models import EventCheckin
    with appmod.app.app_context():
        return EventCheckin.query.order_by(EventCheckin.id).all()


def _count(client, token):
    response = client.get(f'/api/event/{token}/count')
    assert response.status_code == 200
    return response.get_json()['count']


def _set_event(appmod, token, **values):
    from models import EventSession, db
    with appmod.app.app_context():
        row = EventSession.query.filter_by(public_token=token).one()
        for key, value in values.items():
            setattr(row, key, value)
        db.session.commit()


class TestEventCreation:
    def test_a_host_creates_an_event_with_an_unguessable_token(self, appmod, host, event_token):
        from models import EventSession
        assert len(event_token) >= 32
        with appmod.app.app_context():
            row = EventSession.query.filter_by(public_token=event_token).one()
            assert row.title == 'CCS Freshers Orientation 2026'
            assert row.departments == DEPARTMENTS
            assert row.active and row.accepting_checkins()
            # 09:00 in Lagos (UTC+1) is stored as 08:00 UTC.
            assert row.starts_at.hour == 8
        page = host.get(f'/event/{event_token}/manage?created=1')
        assert page.status_code == 200
        assert b'Event created' in page.data
        assert f'/event/{event_token}'.encode() in page.data

    def test_the_create_form_is_prefilled_for_the_orientation(self, host):
        page = host.get('/events/new')
        assert page.status_code == 200
        assert b'CCS Freshers Orientation 2026' in page.data
        assert b'2026-10-07T09:00' in page.data

    def test_invalid_event_details_are_refused(self, appmod, host):
        from models import EventSession
        response = host.post('/events/new', data=_event_form(
            title='', schedule_url='javascript:alert(1)',
            starts_at_local='2026-10-07T12:00', ends_at_local='2026-10-07T09:00'))
        assert response.status_code == 400
        assert b'Give the event a title' in response.data
        assert b'https://' in response.data
        assert b'end time must be after' in response.data
        with appmod.app.app_context():
            assert EventSession.query.count() == 0

    def test_a_student_cannot_create_an_event(self, appmod, seed, login):
        from models import EventSession
        student = login(seed['student_email'])
        response = student.post('/events/new', data=_event_form())
        assert response.status_code == 302
        assert '/events/new' not in response.headers['Location']
        with appmod.app.app_context():
            assert EventSession.query.count() == 0

    def test_admin_emails_restrict_hosting_to_the_list(self, appmod, seed, login, monkeypatch):
        monkeypatch.setattr(appmod, 'EVENT_ADMIN_EMAILS', frozenset({seed['lecturer_email']}))
        coordinator = login(seed['coordinator_email'])
        assert coordinator.post('/events/new', data=_event_form()).status_code == 302
        assert coordinator.get('/events/new').status_code == 302
        lecturer = login(seed['lecturer_email'])
        assert lecturer.get('/events/new').status_code == 200

    def test_an_event_can_be_edited(self, appmod, host, event_token):
        from models import EventSession
        response = host.post(f'/event/{event_token}/edit', data=_event_form(
            venue='Main Auditorium', department_options='Computer Science\nData Science'))
        assert response.status_code == 302
        with appmod.app.app_context():
            row = EventSession.query.filter_by(public_token=event_token).one()
            assert row.venue == 'Main Auditorium'
            assert row.departments == ['Computer Science', 'Data Science']


class TestPublicCheckin:
    def test_the_page_needs_no_account(self, appmod, event_token):
        guest = appmod.app.test_client()
        page = guest.get(f'/event/{event_token}')
        assert page.status_code == 200
        assert b'CCS Freshers Orientation 2026' in page.data
        assert b'College of Computing Sciences' in page.data
        assert b'Computer Science' in page.data and b'Cyber Security' in page.data
        assert page.headers['Cache-Control'] == 'no-store'
        cookie = page.headers['Set-Cookie']
        assert DEVICE_COOKIE in cookie and 'HttpOnly' in cookie and 'SameSite=Lax' in cookie

    def test_a_successful_check_in(self, appmod, event_token):
        guest = appmod.app.test_client()
        guest.get(f'/event/{event_token}')
        response = guest.post(f'/event/{event_token}', data={
            'name': '  Test   Student ', 'department': 'Computer Science'})
        assert response.status_code == 200
        assert b"You're checked in" in response.data
        assert b'Test Student' in response.data
        # The hub links the host configured.
        assert b'https://example.org/schedule' in response.data
        assert b'Campus map' in response.data
        rows = _checkins(appmod)
        assert [(r.name, r.department) for r in rows] == [('Test Student', 'Computer Science')]
        assert _count(guest, event_token) == 1

    def test_a_missing_name_is_refused(self, appmod, event_token):
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={
            'name': '   ', 'department': 'Computer Science'})
        assert response.status_code == 400
        assert b'Please enter your full name' in response.data
        assert _checkins(appmod) == []

    def test_a_missing_department_is_refused(self, appmod, event_token):
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={'name': 'Test Student'})
        assert response.status_code == 400
        assert b'Please choose your department' in response.data
        # The name typed so far is kept.
        assert b'value="Test Student"' in response.data
        assert _checkins(appmod) == []

    def test_a_department_not_on_the_list_is_refused(self, appmod, event_token):
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Basket Weaving'})
        assert response.status_code == 400
        assert _checkins(appmod) == []

    def test_malformed_and_overlong_names_are_refused(self, appmod, event_token):
        guest = appmod.app.test_client()
        for name in ('12345', '!', 'x' * 101):
            response = guest.post(f'/event/{event_token}', data={
                'name': name, 'department': 'Computer Science'})
            assert response.status_code == 400, name
        assert _checkins(appmod) == []

    def test_names_are_escaped_not_rendered_as_html(self, appmod, event_token):
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={
            'name': '<script>alert(1)</script> Ade', 'department': 'Computer Science'})
        assert response.status_code == 200
        assert b'<script>alert(1)</script>' not in response.data
        assert b'&lt;script&gt;' in response.data

    def test_without_a_department_list_the_department_is_typed(self, appmod, host):
        response = host.post('/events/new', data=_event_form(department_options=''))
        token = re.search(r'/event/([A-Za-z0-9_-]+)/manage', response.headers['Location']).group(1)
        guest = appmod.app.test_client()
        page = guest.get(f'/event/{token}')
        assert b'<select' not in page.data
        response = guest.post(f'/event/{token}', data={
            'name': 'Test Student', 'department': 'Information Systems'})
        assert response.status_code == 200
        assert _checkins(appmod)[0].department == 'Information Systems'

    def test_an_invalid_token_is_a_friendly_404(self, appmod, event_token):
        guest = appmod.app.test_client()
        for token in ('nope', 'A' * 32, '../../etc'):
            page = guest.get(f'/event/{token}')
            assert page.status_code == 404
        page = guest.get('/event/' + 'A' * 32)
        assert b"isn't valid" in page.data
        response = guest.post('/event/' + 'A' * 32, data={
            'name': 'Test Student', 'department': 'Computer Science'})
        assert response.status_code == 404
        assert guest.get('/api/event/' + 'A' * 32 + '/count').status_code == 404
        assert _checkins(appmod) == []


class TestDuplicates:
    def test_the_same_phone_checks_in_once(self, appmod, event_token):
        guest = appmod.app.test_client()
        guest.get(f'/event/{event_token}')
        first = guest.post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Computer Science'})
        assert b"You're checked in" in first.data
        again = guest.post(f'/event/{event_token}', data={
            'name': 'Someone Else', 'department': 'Cyber Security'})
        assert again.status_code == 200
        assert b"You've already checked in" in again.data
        # They see their original check-in, not what they typed the second time.
        assert b'Test Student' in again.data and b'Someone Else' not in again.data
        revisit = guest.get(f'/event/{event_token}')
        assert b"You've already checked in" in revisit.data
        assert len(_checkins(appmod)) == 1

    def test_another_phone_is_another_check_in(self, appmod, event_token):
        for name in ('First Student', 'Second Student'):
            guest = appmod.app.test_client()
            guest.get(f'/event/{event_token}')
            guest.post(f'/event/{event_token}', data={
                'name': name, 'department': 'Computer Science'})
        assert len(_checkins(appmod)) == 2
        assert _count(appmod.app.test_client(), event_token) == 2

    def test_a_browser_that_refuses_cookies_still_checks_in(self, appmod, event_token):
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Computer Science'})
        assert response.status_code == 200
        assert DEVICE_COOKIE in response.headers['Set-Cookie']
        assert len(_checkins(appmod)) == 1

    def test_concurrent_duplicates_leave_exactly_one_row(self, appmod, event_token):
        device = 'D' * 43

        def submit(index):
            client = appmod.app.test_client()
            client.set_cookie(DEVICE_COOKIE, device, domain='localhost.localdomain',
                              path='/event/')
            return client.post(f'/event/{event_token}', data={
                'name': f'Racer {chr(65 + index)}', 'department': 'Computer Science'})

        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(submit, range(6)))

        assert all(r.status_code == 200 for r in responses), [r.status_code for r in responses]
        assert sum(b"You're checked in" in r.data for r in responses) == 1
        assert len(_checkins(appmod)) == 1

    def test_the_database_refuses_a_duplicate_device(self, appmod, event_token):
        from sqlalchemy.exc import IntegrityError
        from models import EventCheckin, EventSession, db
        with appmod.app.app_context():
            event_id = EventSession.query.filter_by(public_token=event_token).one().id
            db.session.add(EventCheckin(event_id=event_id, device_token='x' * 40,
                                        name='A', department='B'))
            db.session.commit()
            db.session.add(EventCheckin(event_id=event_id, device_token='x' * 40,
                                        name='A', department='B'))
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()


class TestLifecycle:
    def test_a_closed_event_refuses_check_ins(self, appmod, host, event_token):
        response = host.post(f'/event/{event_token}/close')
        assert response.status_code == 302
        guest = appmod.app.test_client()
        page = guest.get(f'/event/{event_token}')
        assert b'Check-in has closed' in page.data
        response = guest.post(f'/event/{event_token}', data={
            'name': 'Late Student', 'department': 'Computer Science'})
        assert response.status_code == 409
        assert b'Check-in has closed' in response.data
        assert _checkins(appmod) == []
        assert guest.get(f'/api/event/{event_token}/count').get_json()['open'] is False

    def test_reopening_accepts_check_ins_again(self, appmod, host, event_token):
        host.post(f'/event/{event_token}/close')
        host.post(f'/event/{event_token}/open')
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Computer Science'})
        assert response.status_code == 200
        assert len(_checkins(appmod)) == 1

    def test_an_event_past_its_end_time_refuses_check_ins(self, appmod, event_token):
        from localtime import utcnow_naive
        _set_event(appmod, event_token, ends_at=utcnow_naive() - timedelta(minutes=1))
        guest = appmod.app.test_client()
        assert b'Check-in has closed' in guest.get(f'/event/{event_token}').data
        response = guest.post(f'/event/{event_token}', data={
            'name': 'Late Student', 'department': 'Computer Science'})
        assert response.status_code == 409
        assert _checkins(appmod) == []

    def test_reopening_an_expired_event_clears_the_end_time(self, appmod, host, event_token):
        from localtime import utcnow_naive
        _set_event(appmod, event_token, ends_at=utcnow_naive() - timedelta(minutes=1))
        host.post(f'/event/{event_token}/open')
        guest = appmod.app.test_client()
        response = guest.post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Computer Science'})
        assert response.status_code == 200

    def test_only_a_host_can_close_an_event(self, appmod, seed, login, event_token):
        outsider = login(seed['outsider_email'])
        assert outsider.post(f'/event/{event_token}/close').status_code == 403
        guest = appmod.app.test_client()
        assert guest.post(f'/event/{event_token}/close').status_code == 302   # to /login
        assert guest.get(f'/api/event/{event_token}/count').get_json()['open'] is True


class TestDeletion:
    def test_a_host_deletes_an_event_and_its_check_ins(self, appmod, host, event_token):
        from models import AuditLog, EventCheckin, EventSession
        for name in ('First Student', 'Second Student'):
            appmod.app.test_client().post(f'/event/{event_token}', data={
                'name': name, 'department': 'Computer Science'})
        assert b'Delete event' in host.get(f'/event/{event_token}/manage').data

        response = host.post(f'/event/{event_token}/delete')
        assert response.status_code == 302
        assert response.headers['Location'].endswith('/events')
        with appmod.app.app_context():
            assert EventSession.query.count() == 0
            assert EventCheckin.query.count() == 0
            entry = AuditLog.query.filter_by(action='event_deleted').one()
            assert entry.target_label == 'CCS Freshers Orientation 2026'
            assert '"checkins": 2' in entry.details
        # The QR link now goes nowhere.
        guest = appmod.app.test_client()
        assert guest.get(f'/event/{event_token}').status_code == 404
        assert guest.get(f'/api/event/{event_token}/count').status_code == 404

    def test_only_a_host_can_delete(self, appmod, seed, login, event_token):
        from models import EventSession
        assert login(seed['outsider_email']).post(
            f'/event/{event_token}/delete').status_code == 403
        assert login(seed['student_email']).post(
            f'/event/{event_token}/delete').status_code == 403
        response = appmod.app.test_client().post(f'/event/{event_token}/delete')
        assert response.status_code == 302 and '/login' in response.headers['Location']
        with appmod.app.app_context():
            assert EventSession.query.count() == 1

    def test_delete_is_a_post_not_a_link(self, host, event_token):
        assert host.get(f'/event/{event_token}/delete').status_code == 405

    def test_deleting_one_event_leaves_the_others(self, appmod, host, event_token):
        from models import EventCheckin, EventSession
        response = host.post('/events/new', data=_event_form(title='Second Event'))
        other = re.search(r'/event/([A-Za-z0-9_-]+)/manage', response.headers['Location']).group(1)
        appmod.app.test_client().post(f'/event/{other}', data={
            'name': 'Stays Here', 'department': 'Computer Science'})
        host.post(f'/event/{event_token}/delete')
        with appmod.app.app_context():
            assert [e.title for e in EventSession.query.all()] == ['Second Event']
            assert [c.name for c in EventCheckin.query.all()] == ['Stays Here']


class TestLiveFeeds:
    def test_the_public_count_has_no_names(self, appmod, event_token):
        guest = appmod.app.test_client()
        guest.post(f'/event/{event_token}', data={
            'name': 'Private Person', 'department': 'Computer Science'})
        response = appmod.app.test_client().get(f'/api/event/{event_token}/count')
        assert response.status_code == 200
        body = response.get_json()
        assert body == {'status': 'success', 'count': 1, 'open': True}
        assert b'Private Person' not in response.data

    def test_the_projector_feed_shows_recent_names_to_the_host(self, appmod, host, event_token):
        for name in ('First Student', 'Second Student'):
            appmod.app.test_client().post(f'/event/{event_token}', data={
                'name': name, 'department': 'Cyber Security'})
        body = host.get(f'/api/event/{event_token}/live').get_json()
        assert body['count'] == 2
        assert [r['name'] for r in body['recent']] == ['Second Student', 'First Student']
        assert body['recent'][0]['department'] == 'Cyber Security'
        assert body['recent'][0]['time']

    def test_the_projector_page_renders_with_its_qr(self, appmod, host, event_token):
        page = host.get(f'/event/{event_token}/admin')
        assert page.status_code == 200
        assert f'/event/{event_token}/qr.png'.encode() in page.data
        assert b'CHECKED IN' in page.data
        qr = host.get(f'/event/{event_token}/qr.png')
        assert qr.status_code == 200
        assert qr.mimetype == 'image/png'
        assert qr.data[:8] == b'\x89PNG\r\n\x1a\n'

    def test_the_qr_encodes_the_public_check_in_url(self, appmod, event_token):
        from models import EventSession
        with appmod.app.test_request_context():
            row = EventSession.query.filter_by(public_token=event_token).one()
            url = appmod._event_public_url(row)
        assert url.endswith(f'/event/{event_token}')
        assert url.startswith('http')


class TestHostPagesAreProtected:
    PAGES = ('/event/{t}/admin', '/event/{t}/manage', '/event/{t}/attendees',
             '/event/{t}/attendees.csv', '/event/{t}/qr.png', '/event/{t}/edit',
             '/api/event/{t}/live')

    def test_anonymous_visitors_are_sent_to_sign_in(self, appmod, event_token):
        guest = appmod.app.test_client()
        for page in self.PAGES:
            response = guest.get(page.format(t=event_token))
            assert response.status_code in (302, 401), page
            if response.status_code == 302:
                assert '/login' in response.headers['Location'], page

    def test_another_staff_member_is_refused(self, appmod, seed, login, event_token):
        outsider = login(seed['outsider_email'])
        for page in self.PAGES:
            assert outsider.get(page.format(t=event_token)).status_code == 403, page

    def test_a_listed_admin_can_run_any_event(self, appmod, seed, login, event_token, monkeypatch):
        monkeypatch.setattr(appmod, 'EVENT_ADMIN_EMAILS', frozenset({seed['outsider_email']}))
        outsider = login(seed['outsider_email'])
        assert outsider.get(f'/event/{event_token}/admin').status_code == 200

    def test_the_attendee_list_paginates(self, appmod, host, event_token, monkeypatch):
        monkeypatch.setattr(appmod, 'EVENT_ATTENDEES_PER_PAGE', 2)
        for index in range(5):
            appmod.app.test_client().post(f'/event/{event_token}', data={
                'name': f'Student {chr(65 + index)}', 'department': 'Computer Science'})
        first = host.get(f'/event/{event_token}/attendees')
        assert first.status_code == 200
        assert b'Student E' in first.data and b'Student D' in first.data
        assert b'Student A' not in first.data
        assert b'Page 1 of 3' in first.data
        last = host.get(f'/event/{event_token}/attendees?page=3')
        assert b'Student A' in last.data and b'Student E' not in last.data

    def test_the_csv_neutralises_formulas(self, appmod, host, event_token):
        appmod.app.test_client().post(f'/event/{event_token}', data={
            'name': '=HYPERLINK("http://evil") Bob', 'department': 'Computer Science'})
        response = host.get(f'/event/{event_token}/attendees.csv')
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert body.splitlines()[0].startswith('"Name","Department"')
        assert '"\'=HYPERLINK' in body


class TestAbuseProtection:
    def test_check_in_requires_a_csrf_token(self, appmod, event_token):
        appmod.app.config['WTF_CSRF_ENABLED'] = True
        try:
            guest = appmod.app.test_client()
            response = guest.post(f'/event/{event_token}', data={
                'name': 'Test Student', 'department': 'Computer Science'})
            assert response.status_code == 400
            assert b'timed out' in response.data
            assert _checkins(appmod) == []

            page = guest.get(f'/event/{event_token}')
            token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1)
            response = guest.post(f'/event/{event_token}', data={
                'csrf_token': token.decode(), 'name': 'Test Student',
                'department': 'Computer Science'})
            assert response.status_code == 200
            assert len(_checkins(appmod)) == 1
        finally:
            appmod.app.config['WTF_CSRF_ENABLED'] = False

    def test_one_phone_is_rate_limited(self, appmod, event_token, monkeypatch):
        monkeypatch.setattr(appmod, 'EVENT_DEVICE_RATE_LIMIT', '3 per minute')
        appmod.limiter.enabled = True
        try:
            guest = appmod.app.test_client()
            guest.get(f'/event/{event_token}')
            codes = [guest.post(f'/event/{event_token}', data={'name': ''}).status_code
                     for _ in range(5)]
            assert codes[:3] == [400, 400, 400]
            assert codes[3:] == [429, 429]
            limited = guest.post(f'/event/{event_token}', data={'name': ''})
            assert b'One moment' in limited.data
            assert limited.headers.get('Retry-After')
            # A different phone on the same network is unaffected.
            other = appmod.app.test_client()
            assert other.post(f'/event/{event_token}', data={
                'name': 'Test Student', 'department': 'Computer Science'}).status_code == 200
        finally:
            appmod.limiter.enabled = False
            appmod.limiter.reset()


class TestAcademicAttendanceIsUntouched:
    def test_a_class_scan_still_works_alongside_an_event(self, appmod, seed, login, event_token):
        from models import Attendance
        appmod.app.test_client().post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Computer Science'})
        kemi = login(seed['student_email'])
        response = kemi.post('/mark_attendance', json=scan_body(appmod, seed['session_id']))
        assert response.status_code == 200, response.get_json()
        with appmod.app.app_context():
            assert Attendance.query.count() == 1
        assert len(_checkins(appmod)) == 1

    def test_event_check_ins_create_no_users_or_attendance(self, appmod, seed, event_token):
        from models import Attendance, User
        with appmod.app.app_context():
            users_before = User.query.count()
        appmod.app.test_client().post(f'/event/{event_token}', data={
            'name': 'Test Student', 'department': 'Computer Science'})
        with appmod.app.app_context():
            assert User.query.count() == users_before
            assert Attendance.query.count() == 0

