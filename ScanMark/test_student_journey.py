"""
The student journey on a bad network: open the app, scan, be recorded.

One test per change in the 2026-11 performance round. The end-to-end timings
those changes produced come from loadtest/journey/ (a real browser on an
emulated 2G/3G link); these tests hold the behaviour in place.
"""
import json
import pathlib
import re
import sys

import pytest

from conftest import scan_body

ROOT = pathlib.Path(__file__).resolve().parent
METRES_PER_DEGREE = 111_194.9266          # the haversine scale at R = 6371 km


def _read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


def _scan_at(appmod, seed, client, metres, accuracy_m, **overrides):
    payload = scan_body(appmod, seed['session_id'],
                        lat=7.22 + metres / METRES_PER_DEGREE, lon=3.44,
                        accuracy_m=accuracy_m, location_age_ms=500)
    payload.update(overrides)
    return client.post('/mark_attendance', json=payload)


def _pin(appmod, seed, lat=7.22, lon=3.44):
    with appmod.app.app_context():
        appmod.set_class_location(seed['session_id'], lat, lon)


# ---------------------------------------------------------------------------
# Location: a student inside the hall is not refused for GPS drift
# ---------------------------------------------------------------------------

class TestGeofenceAllowance:

    @pytest.mark.parametrize('accuracy,radius,expected', [
        (5, 100, 5),        # never more than the fix's own stated error
        (40, 100, 25),      # never more than the cap, however vague the fix
        (40, 30, 15),       # never more than half a tight room's fence
        (0, 100, 0),
    ])
    def test_the_allowance_is_bounded_three_ways(self, appmod, accuracy, radius, expected):
        assert appmod.geofence_allowance_m(accuracy, radius) == expected

    def test_a_reading_that_drifted_just_past_the_fence_is_admitted(
            self, appmod, seed, login):
        """
        The complaint: a student in their seat, a ±30m indoor reading that
        wandered to 115m, refused as "115m away (max 100m)".
        """
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        response = _scan_at(appmod, seed, kemi, 115, 30)
        assert response.status_code == 200, response.get_json()

    def test_a_vague_reading_buys_no_more_than_the_cap(self, appmod, seed, login):
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        response = _scan_at(appmod, seed, kemi, 130, 90)
        body = response.get_json()
        assert response.status_code == 422
        assert body['outcome'] == 'outside_geofence'
        # What the scanner uses to tell drift from being somewhere else.
        assert body['distance_m'] == 130
        assert body['radius_m'] == 100
        assert body['accuracy_m'] == 90

    def test_somewhere_else_is_still_refused(self, appmod, seed, login):
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 600, 20).status_code == 422
        from models import Attendance
        with appmod.app.app_context():
            assert Attendance.query.count() == 0

    def test_zero_restores_the_strict_boundary(self, appmod, seed, login, monkeypatch):
        monkeypatch.setattr(appmod, 'GEOFENCE_ACCURACY_ALLOWANCE_M', 0.0)
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 104, 30).status_code == 422

    def test_an_imprecise_refusal_says_how_imprecise(self, appmod, seed, login):
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        body = _scan_at(appmod, seed, kemi, 5,
                        appmod.GEOFENCE_MAX_ACCURACY_M + 50).get_json()
        assert body['outcome'] == 'imprecise_location'
        assert body['accuracy_m'] == appmod.GEOFENCE_MAX_ACCURACY_M + 50
        assert body['max_accuracy_m'] == appmod.GEOFENCE_MAX_ACCURACY_M


class TestThePinsOwnErrorCounts:
    """
    Distance is measured between two uncertain points. The fence used to
    forgive only the student's error, so a sharp ±5m phone in a room pinned
    at ±60m was refused for the pin's drift, not its own.
    """

    def _room(self, appmod, seed, accuracy_m):
        from models import ClassSession, Classroom, db
        with appmod.app.app_context():
            room = Classroom(name='LT2', latitude=7.22, longitude=3.44,
                             accuracy_m=accuracy_m, institution='funaab.edu.ng')
            db.session.add(room)
            db.session.commit()
            appmod.pin_session_to_classroom(
                db.session.get(ClassSession, seed['session_id']), room)

    @pytest.mark.parametrize('pin,expected', [
        (None, 5), (0, 5), (12, 13), (60, 25), (float('nan'), 5),
    ])
    def test_the_combined_error_is_still_bounded_by_the_same_caps(
            self, appmod, pin, expected):
        assert appmod.geofence_allowance_m(5, 100, pin) == pytest.approx(expected)

    def test_a_precise_student_is_not_refused_for_a_vague_room_pin(
            self, appmod, seed, login):
        self._room(appmod, seed, accuracy_m=60)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 112, 5).status_code == 200

    def test_a_vague_pin_still_buys_no_more_than_the_cap(self, appmod, seed, login):
        self._room(appmod, seed, accuracy_m=90)
        kemi = login(seed['student_email'])
        response = _scan_at(appmod, seed, kemi, 127, 5)
        assert response.status_code == 422
        assert response.get_json()['outcome'] == 'outside_geofence'

    def test_a_room_typed_off_a_map_is_exact(self, appmod, seed, login):
        self._room(appmod, seed, accuracy_m=None)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 112, 5).status_code == 422

    def test_an_ad_hoc_browser_pin_counts_its_error_too(self, appmod, seed, login):
        with appmod.app.app_context():
            appmod.set_class_location(seed['session_id'], 7.22, 3.44, accuracy_m=40)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 112, 5).status_code == 200

    def test_a_scan_that_passes_does_not_look_the_pin_error_up(
            self, appmod, seed, login, monkeypatch):
        """Nearly every scan passes; they should not pay for the rare refusal."""
        _pin(appmod, seed)

        def not_on_the_hot_path(*_args, **_kwargs):
            raise AssertionError('a passing scan read the pin accuracy')

        monkeypatch.setattr(appmod, '_pin_accuracy', not_on_the_hot_path)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 40, 10).status_code == 200


class TestRefusalsSayWhatIsTrue:

    def test_a_distance_just_past_the_fence_is_not_reported_as_on_it(
            self, appmod, seed, login):
        """It truncated: 100.6m refused as "100m away (max 100m)"."""
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        body = _scan_at(appmod, seed, kemi, 100.3, 0).get_json()
        assert body['outcome'] == 'outside_geofence'
        assert 'You are 101m away (max 100m)' in body['message']

    def test_a_far_distance_is_reported_as_measured(self, appmod, seed, login):
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        body = _scan_at(appmod, seed, kemi, 600, 10).get_json()
        assert 'You are 600m away (max 100m)' in body['message']

    def test_an_approximate_location_is_told_to_turn_on_precise_location(
            self, appmod, seed, login):
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        body = _scan_at(appmod, seed, kemi, 5, 2400).get_json()
        assert body['outcome'] == 'imprecise_location'
        assert 'approximate location (±2.4km)' in body['message']
        assert 'Precise Location' in body['message']
        assert 'window' not in body['message']

    def test_a_merely_weak_fix_is_told_how_to_improve_it(self, appmod, seed, login):
        _pin(appmod, seed)
        kemi = login(seed['student_email'])
        body = _scan_at(appmod, seed, kemi, 5, 140).get_json()
        assert 'accurate to 140m' in body['message']
        assert 'Wi-Fi' in body['message']

    @pytest.mark.parametrize('lat,lon', [(True, 3.44), (7.22, False)])
    def test_a_boolean_is_not_a_coordinate(self, appmod, seed, login, lat, lon):
        _pin(appmod, seed, lat=1.0, lon=3.44)
        kemi = login(seed['student_email'])
        response = _scan_at(appmod, seed, kemi, 0, 5, lat=lat, lon=lon)
        assert response.status_code == 422
        assert response.get_json()['outcome'] == 'missing_location'


class TestTheSavedRoomIsThePin:

    def _room(self, appmod, seed, lat=7.22, lon=3.44):
        from models import ClassSession, Classroom, db
        with appmod.app.app_context():
            room = Classroom(name='LT1', latitude=lat, longitude=lon,
                             institution='funaab.edu.ng')
            db.session.add(room)
            db.session.commit()
            appmod.pin_session_to_classroom(
                db.session.get(ClassSession, seed['session_id']), room)

    def test_a_scan_in_a_saved_room_does_not_ask_the_cache(
            self, appmod, seed, login, monkeypatch):
        """
        The join already returns the room; every path that pins a meeting
        held in a saved room pins exactly that room. Reading Redis for it was
        one round trip per scan to learn the same two numbers.
        """
        self._room(appmod, seed)

        def no_cache_read(*_args, **_kwargs):
            raise AssertionError('the scan path read the cached pin')

        monkeypatch.setattr(appmod, 'get_class_location', no_cache_read)
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 20, 10).status_code == 200

    def test_the_room_wins_over_a_stray_cached_pin(self, appmod, seed, login):
        self._room(appmod, seed)
        _pin(appmod, seed, lat=8.5, lon=4.5)          # 140 km away
        kemi = login(seed['student_email'])
        assert _scan_at(appmod, seed, kemi, 20, 10).status_code == 200


class TestABrowserPinOnlyImproves:
    """
    The projector re-pinned the class with whatever reading it got every 30
    seconds, so the centre of every student's fence wandered with the
    laptop's GPS through the lecture.
    """

    def _post(self, client, seed, metres, accuracy):
        return client.post(f"/session/{seed['session_id']}/set_location", json={
            'lat': 7.22 + metres / METRES_PER_DEGREE, 'lon': 3.44,
            'accuracy_m': accuracy}).get_json()

    def _pin_lat(self, appmod, seed):
        with appmod.app.app_context():
            return appmod.get_class_location(seed['session_id'])['lat']

    def test_a_vaguer_reading_does_not_replace_a_precise_one(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        assert self._post(ada, seed, 0, 15)['status'] == 'ok'
        kept = self._post(ada, seed, 60, 80)
        assert kept['kept'] is True
        assert self._pin_lat(appmod, seed) == pytest.approx(7.22)

    def test_a_better_reading_does_replace_it(self, appmod, seed, login):
        ada = login(seed['coordinator_email'])
        self._post(ada, seed, 0, 40)
        self._post(ada, seed, 30, 10)
        assert self._pin_lat(appmod, seed) == pytest.approx(7.22 + 30 / METRES_PER_DEGREE)

    def test_a_class_that_moved_rooms_is_followed(self, appmod, seed, login):
        """Far beyond both readings' error and the fence: not drift, a move."""
        ada = login(seed['coordinator_email'])
        self._post(ada, seed, 0, 10)
        self._post(ada, seed, 900, 60)
        assert self._pin_lat(appmod, seed) == pytest.approx(7.22 + 900 / METRES_PER_DEGREE)


# ---------------------------------------------------------------------------
# Instant confirmation, and no reload to recover a stale form token
# ---------------------------------------------------------------------------

class TestTheConfirmation:

    def test_success_names_the_course(self, appmod, seed, login):
        kemi = login(seed['student_email'])
        body = kemi.post('/mark_attendance',
                         json=scan_body(appmod, seed['session_id'])).get_json()
        assert body['status'] == 'success'
        assert body['course_code'] == 'CSC201'
        assert 'CSC201' in body['message']

    def test_a_stale_form_token_is_answered_with_a_fresh_one(self, appmod, seed, login):
        """
        The stock CSRF refusal is HTML, and the scanner's only recovery was
        to reload the page — seconds on 2G, and the scan in hand lost. The
        refusal now carries a new token, and resending with it works.
        """
        kemi = login(seed['student_email'])
        appmod.app.config['WTF_CSRF_ENABLED'] = True
        try:
            refused = kemi.post('/mark_attendance',
                                json=scan_body(appmod, seed['session_id']),
                                headers={'X-CSRFToken': 'left-over-from-yesterday'})
            assert refused.status_code == 400
            body = refused.get_json()
            assert body['outcome'] == 'csrf_expired'
            accepted = kemi.post('/mark_attendance',
                                 json=scan_body(appmod, seed['session_id']),
                                 headers={'X-CSRFToken': body['csrf_token']})
            assert accepted.status_code == 200, accepted.get_json()
        finally:
            appmod.app.config['WTF_CSRF_ENABLED'] = False


# ---------------------------------------------------------------------------
# Page weight and round trips
# ---------------------------------------------------------------------------

class TestStaticDelivery:

    def _call(self, appmod, query):
        captured = {}

        def inner(environ, start_response):
            start_response('200 OK', [('Cache-Control', 'max-age=86400, public')])
            return [b'']

        def start_response(status, headers, exc_info=None):
            captured['headers'] = dict(headers)

        middleware = appmod.VersionedStaticCache(inner, appmod.ASSET_VERSION)
        middleware({'PATH_INFO': '/static/style.css', 'QUERY_STRING': query},
                   start_response)
        return captured['headers']['Cache-Control']

    def test_this_deploys_versioned_urls_are_immutable(self, appmod):
        assert 'immutable' in self._call(appmod, f'v={appmod.ASSET_VERSION}')

    def test_other_urls_keep_a_short_lifetime(self, appmod):
        assert 'immutable' not in self._call(appmod, '')
        # A previous deploy's hash is answered with today's bytes: never pin
        # those under yesterday's name for a year.
        assert 'immutable' not in self._call(appmod, 'v=000000000000')

    def test_files_in_subdirectories_are_precompressed(self, appmod, tmp_path):
        """jsQR lives in static/vendor/ and went out uncompressed: 131 KB."""
        nested = tmp_path / 'vendor'
        nested.mkdir()
        (nested / 'library.js').write_text('function f(){return 1;}\n' * 2000)
        appmod._precompress_static(str(tmp_path))
        assert (nested / 'library.js.br').exists()
        assert (nested / 'library.js.gz').exists()

    @pytest.mark.parametrize('template', ['templates/base.html',
                                          'templates/complete_profile.html'])
    def test_pages_need_no_third_party_origin(self, template):
        """Each new origin is DNS + TCP + TLS before its first byte."""
        page = _read(template)
        for origin in ('cdn.jsdelivr.net', 'fonts.googleapis.com',
                       'fonts.gstatic.com', 'cdnjs.cloudflare.com'):
            assert origin not in page, origin

    def test_bootstrap_does_not_block_the_page(self):
        assert re.search(r'bootstrap\.bundle\.min\.js[^>]*\bdefer\b', _read('templates/base.html'))

    def test_every_icon_in_use_is_in_the_subset_font(self):
        """Re-run tools/subset_icons.py after adding an icon."""
        sys.path.insert(0, str(ROOT / 'tools'))
        try:
            import subset_icons
        finally:
            sys.path.pop(0)
        mapping = subset_icons.codepoints()
        used = {name for name in subset_icons.icons_used() if name in mapping}
        manifest = set(json.loads(_read('static/vendor/fontawesome/icons.json'))['icons'])
        assert used <= manifest, sorted(used - manifest)

    def test_the_worker_precaches_only_files_that_exist(self):
        worker = _read('static/service-worker.js')
        listed = re.findall(r"'(/static/[^'?]+\.[a-z0-9]+)'", worker)
        assert listed
        for path in listed:
            assert (ROOT / path.lstrip('/')).is_file(), path


class TestOneTapScanner:

    def test_the_dashboard_opens_the_camera_in_place(self, appmod, seed, login):
        """No second page load, and no second tap."""
        page = login(seed['student_email']).get('/student_dashboard').get_data(as_text=True)
        assert 'id="scanner-container"' in page
        assert re.search(r'<a href="/scan_page"[^>]*data-open-scanner', page)
        assert 'autoStart: false' in page
        assert 'data-attended-for="CSC201"' in page

    def test_the_scan_page_starts_the_camera_on_arrival(self, appmod, seed, login):
        page = login(seed['student_email']).get('/scan_page').get_data(as_text=True)
        assert 'autoStart: true' in page
        assert f'qrWindowSeconds: {appmod.QR_CODE_WINDOW}' in page
        # Loaded on demand, not as a parser-blocking script.
        assert '<script src="/static/vendor/jsQR.min.js' not in page


class TestScannerContract:
    """What the scanner promises about the network and the GPS."""

    scanner = staticmethod(lambda: _read('static/scanner.js'))
    # Fix selection and GPS error wording are shared with the manual
    # attendance code; the scanner delegates to this module.
    location = staticmethod(lambda: _read('static/attendance-common.js'))

    def test_it_sends_the_most_precise_recent_fix_not_the_latest(self):
        source = self.location()
        assert 'function bestFix(' in source
        assert 'bestFix(newerThan)' in source
        assert 'locator.acquire(newerThan' in self.scanner()

    def test_a_refused_fix_is_retried_with_a_newer_one(self):
        source = self.scanner()
        # By the locator's own id for the reading, not its timestamp: a
        # phone with a broken stamp (or a cached repeat of the same reading)
        # would otherwise hand the refused fix straight back as "newer".
        assert 'refusedFixAt = locator.fixId(position)' in source
        assert 'acquirePosition(refusedFixAt)' in source

    def test_a_timeout_is_not_reported_as_a_permission_problem(self):
        source = self.location()
        assert 'Allow GPS access and scan again' not in source + self.scanner()
        assert 'code === 1' in source and 'code === 2' in source
        # The scanner's messages still end "…then scan again".
        assert "retryHint: 'scan again'" in self.scanner()

    def test_a_retry_carries_the_newest_code_the_camera_has_read(self):
        source = self.scanner()
        assert 'token.issuedAt > pending.token.issuedAt' in source
        assert 'pending.qrData = qrData' in source

    def test_a_foreign_qr_code_is_never_posted(self):
        source = self.scanner()
        assert 'TOKEN_PATTERN' in source
        detected = source[source.index('function qrDetected('):]
        assert detected.index('if (!token)') < detected.index('attempt()')

    def test_capture_time_is_reported_on_the_servers_clock(self):
        assert 'scan.capturedAt + (serverOffsetMs || 0)' in self.scanner()

    def test_a_stale_form_token_is_replaced_without_a_reload(self):
        source = self.scanner()
        assert "payload.outcome === 'csrf_expired'" in source
        assert 'config.csrfToken = payload.csrf_token' in source


class TestServiceWorkerQueue:

    def test_server_answers_reach_the_scanner_untouched(self):
        """
        Any 5xx used to become "saved offline" — hiding Retry-After from the
        scanner and stopping it, so a database busy for two seconds cost a
        student their scan.
        """
        worker = _read('static/service-worker.js')
        assert 'transient HTTP' not in worker
        handler = worker[worker.index('async function handleAttendanceRequest'):]
        handler = handler[:handler.index('\n}\n')]
        start = handler.index('await fetch(request)')
        network = handler[start:handler.index('} catch', start)]
        assert 'return response;' in network
        assert 'throw' not in network

    def test_stored_scans_are_sent_without_waiting_for_an_online_event(self):
        """A dead-but-connected 2G cell never fires `online`."""
        worker = _read('static/service-worker.js')
        page = _read('templates/base.html')
        assert "addEventListener('sync'" in worker
        assert 'drainUntilDeadline' in worker
        assert "'visibilitychange'" in page
        assert "type: 'flush'" in page

    def test_signing_out_drops_the_saved_pages(self):
        worker = _read('static/service-worker.js')
        assert "url.pathname === '/logout'" in worker
        assert 'caches.delete(PAGE_CACHE)' in worker
