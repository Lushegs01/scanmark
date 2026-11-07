// Unit tests for the manual attendance code's browser logic, run with
// `node --test test_manual_code_browser.cjs` (no browser, no network).
// The full in-browser journey is e2e/manual_code.e2e.cjs.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const manual = require('./static/manual-code.js');
const common = require('./static/attendance-common.js');

test('digits are extracted, capped at eight, and leading zeros kept', () => {
    assert.equal(manual.codeDigits('0123 4567'), '01234567');
    assert.equal(manual.codeDigits('0000-0001'), '00000001');
    assert.equal(manual.codeDigits('48269137999'), '48269137');
    assert.equal(manual.codeDigits('Code: 4826 9137'), '48269137');
    assert.equal(manual.codeDigits(null), '');
});

test('the code is grouped XXXX XXXX as it is typed', () => {
    assert.equal(manual.formatCode(''), '');
    assert.equal(manual.formatCode('4'), '4');
    assert.equal(manual.formatCode('4826'), '4826');
    assert.equal(manual.formatCode('48269'), '4826 9');
    assert.equal(manual.formatCode('48269137'), '4826 9137');
    assert.equal(manual.formatCode(' 4826-9137 '), '4826 9137');
    assert.equal(manual.formatCode('01234567'), '0123 4567');
});

test('letters and symbols are noticed, separators are not', () => {
    assert.equal(manual.hasStrayCharacters('4826 9137'), false);
    assert.equal(manual.hasStrayCharacters('4826-9137'), false);
    assert.equal(manual.hasStrayCharacters('4826 9137'), false);
    assert.equal(manual.hasStrayCharacters('48a6'), true);
    assert.equal(manual.hasStrayCharacters('4826+9137'), true);
});

test('the caret stays after the same digit when the box reformats', () => {
    // Typing the fifth digit at the end: caret after the 5th digit (index 6).
    assert.equal(manual.caretForDigits('4826 9', 5), 6);
    // Correcting the 2nd digit in the middle.
    assert.equal(manual.caretForDigits('4826 9137', 2), 2);
    assert.equal(manual.caretForDigits('4826 9137', 4), 4);
    assert.equal(manual.caretForDigits('4826 9137', 0), 0);
    assert.equal(manual.digitsBeforeCaret('4826 9137', 6), 5);
    assert.equal(manual.digitsBeforeCaret('4826 9137', 5), 4);
});

test('responses are classified into what the page should do', () => {
    const c = manual.classifyResponse;
    assert.equal(c(200, { status: 'success', outcome: 'success' }, 1).kind, 'success');
    // Our own earlier attempt landed: that is success, not "already".
    assert.equal(c(409, { outcome: 'duplicate' }, 2).kind, 'success');
    assert.equal(c(409, { outcome: 'duplicate' }, 1).kind, 'already');
    assert.equal(c(400, { outcome: 'code_expired' }, 1).kind, 'expired');
    const wrong = c(400, { outcome: 'invalid_code', attempts_remaining: 3 }, 1);
    assert.equal(wrong.kind, 'wrong_code');
    assert.equal(wrong.attemptsRemaining, 3);
    assert.equal(c(400, { outcome: 'invalid_code', retry_after_seconds: 120 }, 1).retryAfterSeconds, 120);
    assert.equal(c(429, { outcome: 'rate_limited', retry_after_seconds: 90 }, 1).retryAfterSeconds, 90);
    // The request limiter's 429 carries `retry_after` instead.
    assert.equal(c(429, { outcome: 'rate_limited', retry_after: 30 }, 1).retryAfterSeconds, 30);
    assert.equal(c(429, { outcome: 'admission_throttled' }, 1).kind, 'busy');
    assert.equal(c(503, { outcome: 'database_saturated' }, 1).kind, 'busy');
    assert.equal(c(503, { outcome: 'verification_unavailable', retry_after_seconds: 15 }, 1).kind,
                 'unavailable');
    assert.equal(c(422, { outcome: 'outside_geofence' }, 1).kind, 'location');
    assert.equal(c(400, { outcome: 'session_required', sessions: [{}, {}] }, 1).sessions.length, 2);
    assert.equal(c(404, { outcome: 'no_active_session' }, 1).kind, 'no_session');
    for (const outcome of ['not_enrolled', 'session_ended', 'course_archived', 'not_student']) {
        assert.equal(c(409, { outcome }, 1).kind, 'terminal', outcome);
    }
    assert.equal(c(400, { outcome: 'csrf_expired', csrf_token: 't' }, 1).kind, 'csrf');
    assert.equal(c(500, { outcome: 'server_error' }, 1).kind, 'error');
    // Nothing but a confirmed 200 is ever a success.
    for (const status of [201, 202, 204, 400, 500]) {
        assert.notEqual(c(status, { outcome: 'success' }, 1).kind, 'success', String(status));
    }
});

test('lockout waits read like a clock', () => {
    assert.equal(manual.formatWait(9.2), '10s');
    assert.equal(manual.formatWait(120), '2:00');
    assert.equal(manual.formatWait(61), '1:01');
});

test('Retry-After is honoured, clamped and jittered', () => {
    const response = value => ({ headers: { get: () => value } });
    assert.equal(common.serverRetryDelay(response(null)), null);
    assert.equal(common.serverRetryDelay(response('nonsense')), null);
    assert.equal(common.serverRetryDelay(response('2'), undefined, () => 0.5), 2000);
    assert.equal(common.serverRetryDelay(response('3600'), undefined, () => 0.5), 30000);
    assert.equal(common.serverRetryDelay(response('0'), undefined, () => 0.5), 250);
});

function fakeGeolocation(script) {
    const watchers = [];
    return {
        watchers,
        watchPosition(success, failure) { watchers.push({ success, failure }); script(watchers.length - 1, success, failure); return watchers.length; },
        clearWatch() {},
        getCurrentPosition(success, failure) { script('once', success, failure); },
    };
}

const fix = (accuracy, ageMs = 500) => ({
    coords: { latitude: 7.22, longitude: 3.44, accuracy },
    timestamp: Date.now() - ageMs,
});

test('the locator returns the most precise fresh fix and its payload', async () => {
    const geolocation = fakeGeolocation((id, success) => {
        if (id === 0) { success(fix(60)); success(fix(12)); success(fix(40)); }
    });
    const locator = common.createLocator({ geolocation, maxLocationAccuracyM: 100 });
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 12);
    const body = locator.payload(position);
    assert.deepEqual(Object.keys(body).sort(), ['accuracy_m', 'lat', 'location_age_ms', 'lon']);
    assert.ok(body.location_age_ms >= 0);
    locator.stopWatching();
});

test('a location denial is reported now, with what to do', async () => {
    const geolocation = fakeGeolocation((id, _success, failure) => {
        if (id === 0) setTimeout(() => failure({ code: 1 }), 5);
    });
    const locator = common.createLocator({ geolocation, retryHint: 'try again' });
    await assert.rejects(locator.acquire(0), error => {
        assert.equal(error.locationProblem, true);
        assert.match(error.message, /permission is off.*then try again/);
        return true;
    });
    locator.stopWatching();
});

test('no geolocation at all is a clear refusal, not a hang', async () => {
    const locator = common.createLocator({ geolocation: null });
    await assert.rejects(locator.acquire(0), /not supported/);
});

test('the manual-code script never asks for the camera', () => {
    const fs = require('fs');
    const source = fs.readFileSync(require.resolve('./static/manual-code.js'), 'utf8') +
        fs.readFileSync(require.resolve('./static/attendance-common.js'), 'utf8');
    assert.ok(!/getUserMedia|mediaDevices|BarcodeDetector/.test(source.replace(/^\s*\/\/.*$|\/\*[\s\S]*?\*\//gm, '')));
});
