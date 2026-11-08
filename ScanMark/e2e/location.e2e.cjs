/*
 * Location verification in a real browser, against a real server, through
 * the browser's OWN Geolocation API (Playwright's geolocation emulation and
 * permission grants — no JavaScript fake), on Android and iPhone profiles.
 *
 *   python e2e/seed_e2e.py > /tmp/e2e-seed.json        # same env as the server
 *   E2E_BASE=http://127.0.0.1:8100 E2E_SEED=/tmp/e2e-seed.json \
 *       node --test e2e/location.e2e.cjs
 *
 * Uses the typed attendance code, which goes through exactly the same
 * locator (static/attendance-common.js) and the same server geofence as a
 * QR scan, without needing a camera. Creates attendance: use a disposable
 * database, and re-seed before each run (it opens fresh classes).
 *
 * The engine is Chromium throughout: an "iPhone" here is Chromium with an
 * iPhone's user agent and screen. That checks the iPhone-specific wording and
 * paths, not WebKit's own geolocation — which needs a real device.
 */
'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { chromium, devices } = require('playwright');

const BASE = (process.env.E2E_BASE || 'http://127.0.0.1:8100').replace(/\/$/, '');
const SEED = JSON.parse(fs.readFileSync(process.env.E2E_SEED || '/tmp/e2e-seed.json', 'utf8'));
const SID = SEED.session_id;
const ROOM = SEED.room;
const METRES_PER_DEGREE = 111194.9266;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const ANDROID = devices['Pixel 7'];
const IPHONE = devices['iPhone 15'];

let browser;
let lecturer;

before(async () => {
    browser = await chromium.launch();
    lecturer = await browser.newContext();
    await signIn(lecturer, SEED.lecturer);
});

after(async () => {
    if (browser) await browser.close();
});

async function signIn(context, email) {
    const page = await context.request.get(`${BASE}/login`);
    const token = /name="csrf_token" value="([^"]+)"/.exec(await page.text())[1];
    const response = await context.request.post(`${BASE}/login`, {
        form: { csrf_token: token, email, password: SEED.password },
        maxRedirects: 0,
    });
    assert.equal(response.status(), 302, `sign-in failed for ${email}`);
}

/** Where a phone `metres` north of the pinned room says it is. */
function northOfRoom(metres, accuracy) {
    return { latitude: ROOM.lat + metres / METRES_PER_DEGREE, longitude: ROOM.lon, accuracy };
}

/**
 * A signed-in student on a phone. `location` null means the site has NOT
 * been granted location — Chromium then refuses it, as a phone does once
 * the student has tapped "Block".
 */
async function phone(index, device, location) {
    const options = { ...device };
    if (location) {
        options.geolocation = location;
        options.permissions = ['geolocation'];
    }
    const context = await browser.newContext(options);
    // Playwright's emulated position is delivered only when it CHANGES, so a
    // page would see one fix and then silence for ever. A real receiver
    // reports every second or so, a few centimetres apart: do the same.
    // (setGeolocation also moves the fix for the tests that relocate it.)
    let held = location;
    const setLocation = context.setGeolocation.bind(context);
    context.setGeolocation = next => { held = next; return setLocation(next); };
    const ticker = setInterval(() => {
        if (!held) return;
        const jitter = (Math.random() - 0.5) * 1e-6;
        setLocation({ ...held, latitude: held.latitude + jitter }).catch(() => {});
    }, 1000);
    context.on('close', () => clearInterval(ticker));
    await signIn(context, SEED.students[index]);
    const page = await context.newPage();
    const posts = [];
    page.on('request', request => {
        if (request.method() === 'POST' && request.url().includes('/api/attendance/manual')) {
            posts.push(JSON.parse(request.postData() || '{}'));
        }
    });
    await page.goto(`${BASE}/student_dashboard`);
    return { context, page, posts };
}

async function projectedCode() {
    for (;;) {
        const response = await lecturer.request.get(`${BASE}/api/session/${SID}/manual_code`);
        assert.equal(response.status(), 200);
        const data = await response.json();
        if (data.expires_in_ms > 15000) return data.code;
        await sleep(data.expires_in_ms + 800);
    }
}

async function submitCode(page, code) {
    await page.fill('#manualCodeInput', code || await projectedCode());
    await page.locator('#manualSession').getByText('CSC301').waitFor();
    await page.click('#manualCodeSubmit');
}

async function feedback(page, kind, timeout = 20000) {
    const box = page.locator(`#manualCodeFeedback.is-${kind}`);
    await box.waitFor({ timeout });
    return box.textContent();
}

async function attendedMatrics() {
    const response = await lecturer.request.get(
        `${BASE}/api/session/${SID}/attendees?limit=500`);
    return (await response.json()).new_attendees.map(entry => entry.matric_no);
}

// ---------------------------------------------------------------------------

test('Android, inside the room: marked at once with a fresh, honest fix', async () => {
    const { context, page, posts } = await phone(0, ANDROID, northOfRoom(20, 15));
    await page.focus('#manualCodeInput');          // starts the watch
    const code = await projectedCode();            // may wait for a fresh code: not timed
    const started = Date.now();
    await submitCode(page, code);
    assert.match(await feedback(page, 'success'), /Attendance successfully marked for CSC301/);
    assert.ok(Date.now() - started < 8000, `took ${Date.now() - started}ms`);
    assert.equal(posts.length, 1);
    assert.equal(posts[0].accuracy_m, 15);
    assert.ok(posts[0].location_age_ms >= 0 && posts[0].location_age_ms < 10000,
              `location_age_ms ${posts[0].location_age_ms}`);
    assert.ok((await attendedMatrics()).includes('E2E00000'));
    await context.close();
});

test('iPhone, inside the room near the edge of the fence: still marked', async () => {
    // 108m north of a 100m fence, ±10m fix, room pinned at ±8m: inside the
    // fix's own error. The kind of reading a student at the back of a long
    // hall gets.
    const { context, page } = await phone(1, IPHONE, northOfRoom(108, 10));
    await page.focus('#manualCodeInput');
    await submitCode(page);
    assert.match(await feedback(page, 'success'), /Attendance successfully marked/);
    await context.close();
});

test('outside the fence: refused by the server, nothing recorded', async () => {
    const { context, page, posts } = await phone(2, ANDROID, northOfRoom(600, 10));
    await page.focus('#manualCodeInput');
    await submitCode(page);
    const text = await feedback(page, 'danger', 30000);
    assert.match(text, /Too far from the classroom\. You are 600m away \(max 100m\)/);
    assert.match(text, /not recorded/);
    // Kilometres-scale "elsewhere" is not retried as drift.
    assert.equal(posts.length, 1);
    assert.ok(!(await attendedMatrics()).includes('E2E00002'));
    await context.close();
});

test('approximate location only: explained in seconds, nothing posted', async () => {
    const { context, page, posts } = await phone(3, IPHONE, northOfRoom(5, 2400));
    await page.focus('#manualCodeInput');
    const code = await projectedCode();
    const started = Date.now();
    await submitCode(page, code);
    const text = await feedback(page, 'danger', 15000);
    assert.match(text, /only sharing an approximate location \(±2\.4km\)/);
    assert.match(text, /Precise Location/);
    assert.ok(Date.now() - started < 9000, `took ${Date.now() - started}ms`);
    assert.equal(posts.length, 0, 'a fix the server must refuse was posted');
    await context.close();
});

test('Android, location blocked: told on focus, with where the switch is', async () => {
    const { context, page, posts } = await phone(4, ANDROID, null);
    await page.focus('#manualCodeInput');
    const text = await feedback(page, 'danger', 5000);
    assert.match(text, /Location is blocked for this site/);
    assert.match(text, /Permissions › Location › Allow/);
    assert.equal(posts.length, 0);
    await context.close();
});

test('iPhone, location blocked: names Location Services, not Android settings', async () => {
    const { context, page } = await phone(5, IPHONE, null);
    await page.focus('#manualCodeInput');
    const text = await feedback(page, 'danger', 5000);
    assert.match(text, /Privacy & Security › Location Services/);
    assert.doesNotMatch(text, /quick settings/);
    await context.close();
});

test('allowing location after blocking it works without reloading', async () => {
    const { context, page } = await phone(6, ANDROID, null);
    await page.focus('#manualCodeInput');
    await feedback(page, 'danger', 5000);
    // The student changes the site setting and comes back to the same page.
    await context.setGeolocation(northOfRoom(10, 12));
    await context.grantPermissions(['geolocation'], { origin: BASE });
    await submitCode(page);
    assert.match(await feedback(page, 'success'), /Attendance successfully marked/);
    await context.close();
});

test('the scanner and the code box share one GPS watch on the dashboard', async () => {
    const { context, page } = await phone(7, ANDROID, northOfRoom(10, 12));
    await page.evaluate(() => {
        const geolocation = navigator.geolocation;
        const original = geolocation.watchPosition.bind(geolocation);
        window.__watches = 0;
        geolocation.watchPosition = (...args) => { window.__watches += 1; return original(...args); };
        // No camera in this browser: the scanner still starts its watch
        // before it finds that out.
    });
    await page.focus('#manualCodeInput');
    await page.click('#scanBtn');
    await sleep(500);
    assert.equal(await page.evaluate(() => window.__watches), 1);
    await context.close();
});

test('scanner, location blocked: told while aiming, camera closed, nothing posted', async () => {
    // A camera that opens, as a phone's does (Chromium's fake device).
    const cameraBrowser = await chromium.launch({
        args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'],
    });
    try {
        const context = await cameraBrowser.newContext({ ...IPHONE });
        await context.grantPermissions(['camera'], { origin: BASE });
        await signIn(context, SEED.students[7]);
        const page = await context.newPage();
        let posts = 0;
        page.on('request', request => {
            if (request.method() === 'POST' && request.url().includes('/mark_attendance')) posts += 1;
        });
        await page.goto(`${BASE}/scan_page`);
        const banner = page.locator('#result-banner');
        await banner.waitFor({ state: 'visible', timeout: 10000 });
        const text = await banner.textContent();
        assert.match(text, /Location Services/);
        assert.match(text, /scan again\.$/);
        // The camera is not left running behind a scan that cannot succeed.
        assert.equal(await page.evaluate(() => {
            const video = document.querySelector('video');
            return Boolean(video && video.srcObject);
        }), false);
        assert.equal(posts, 0);
        await context.close();
    } finally {
        await cameraBrowser.close();
    }
});
