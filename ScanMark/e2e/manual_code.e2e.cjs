/*
 * The manual attendance code in a real browser, against a real server.
 *
 *   python e2e/seed_e2e.py > /tmp/e2e-seed.json        # same env as the server
 *   E2E_BASE=http://127.0.0.1:8100 E2E_SEED=/tmp/e2e-seed.json \
 *       node --test e2e/manual_code.e2e.cjs
 *
 * Needs Playwright with Chromium (`require('playwright')`). Creates
 * attendance, so point it at a disposable database. Covers what only a
 * browser can show: no camera at all, the input's formatting and caret, one
 * request per tap, the projector's countdown and full-screen layout, the
 * stale/offline display, keyboard-only use — and that QR scanning still
 * works after the scanner's location code moved into attendance-common.js.
 */
'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { chromium } = require('playwright');

const BASE = (process.env.E2E_BASE || 'http://127.0.0.1:8100').replace(/\/$/, '');
const SEED = JSON.parse(fs.readFileSync(process.env.E2E_SEED || '/tmp/e2e-seed.json', 'utf8'));
const SID = SEED.session_id;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

let browser;
let lecturer;            // { context, page }

before(async () => {
    browser = await chromium.launch();
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    await signIn(context, SEED.lecturer);
    lecturer = { context, page: await context.newPage() };
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

/** A phone's GPS as a page sees it: a fresh fix every second, inside the room. */
function fakeGeolocation(room) {
    const location = { lat: room.lat + 0.00008, lon: room.lon, accuracy: 12 };
    window.__e2eLocation = location;
    const fix = () => ({
        coords: { latitude: location.lat, longitude: location.lon, accuracy: location.accuracy,
                  altitude: null, altitudeAccuracy: null, heading: null, speed: null },
        timestamp: Date.now(),
    });
    const watches = new Map();
    let next = 1;
    const geolocation = {
        getCurrentPosition(success) { setTimeout(() => success(fix()), 50); },
        watchPosition(success) {
            const id = next++;
            setTimeout(() => success(fix()), 50);
            watches.set(id, setInterval(() => success(fix()), 1000));
            return id;
        },
        clearWatch(id) { clearInterval(watches.get(id)); watches.delete(id); },
    };
    Object.defineProperty(navigator, 'geolocation', { value: geolocation, configurable: true });
}

/** A phone with no usable camera at all, and no native QR decoder. */
function noCamera() {
    Object.defineProperty(navigator, 'mediaDevices', { value: undefined, configurable: true });
    try { delete window.BarcodeDetector; } catch (_) { /* not present */ }
    window.BarcodeDetector = undefined;
}

/** Counts camera requests, so a test can prove the code path never makes one. */
function countCameraRequests() {
    window.__cameraRequests = 0;
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        const original = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
        navigator.mediaDevices.getUserMedia = (...args) => {
            window.__cameraRequests += 1;
            return original(...args);
        };
    }
}

async function student(index, { camera = 'none' } = {}) {
    const context = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true });
    await signIn(context, SEED.students[index]);
    await context.addInitScript(fakeGeolocation, SEED.room);
    if (camera === 'none') await context.addInitScript(noCamera);
    if (camera === 'counted') await context.addInitScript(countCameraRequests);
    const page = await context.newPage();
    await page.goto(`${BASE}/student_dashboard`);
    return { context, page };
}

/** The code on the projector right now, with enough of its minute left to type it. */
async function projectedCode(sessionId = SID) {
    for (;;) {
        const response = await lecturer.context.request.get(`${BASE}/api/session/${sessionId}/manual_code`);
        assert.equal(response.status(), 200);
        const data = await response.json();
        if (data.expires_in_ms > 12000) return data;
        await sleep(data.expires_in_ms + 800);
    }
}

async function attendees() {
    const response = await lecturer.context.request.get(`${BASE}/api/session/${SID}/attendees?limit=500`);
    return (await response.json()).new_attendees;
}

// ---------------------------------------------------------------------------

test('a phone with no camera marks attendance with the code alone', async () => {
    const { context, page } = await student(0, { camera: 'none' });
    // The scanner cannot open a camera, and says where to go instead.
    await page.click('#scanBtn');
    const banner = page.locator('#result-banner');
    await banner.waitFor({ state: 'visible' });
    assert.match(await banner.textContent(), /Camera error.*enter the attendance code instead/);
    assert.ok(await page.locator('#attendance-code.is-suggested').count());

    const counted = page.locator('[data-attended-for="CSC301"]');
    const attendedBefore = Number(await counted.getAttribute('data-attended'));
    const { code } = await projectedCode();
    const input = page.locator('#manualCodeInput');
    await input.click();
    await page.keyboard.type(code, { delay: 30 });
    assert.equal(await input.inputValue(), `${code.slice(0, 4)} ${code.slice(4)}`);
    // Exactly one class open for this student: no choice to make.
    await page.locator('#manualSession').getByText('CSC301').waitFor();
    await page.keyboard.press('Enter');
    const feedback = page.locator('#manualCodeFeedback.is-success');
    await feedback.waitFor({ timeout: 20000 });
    assert.match(await feedback.textContent(), /Attendance successfully marked for CSC301\./);
    assert.match(await feedback.textContent(), /Operating Systems/);
    assert.match(await feedback.textContent(), /Recorded at \d{1,2}:\d{2} [AP]M/);
    // The count on the page moved without a reload.
    assert.equal(Number(await counted.getAttribute('data-attended')), attendedBefore + 1);

    const mine = (await attendees()).filter(a => a.matric_no === 'E2E00000');  // this session only
    assert.equal(mine.length, 1);
    assert.equal(mine[0].method, 'manual_code');
    await context.close();
});

test('entering the code never asks for the camera', async () => {
    const { context, page } = await student(1, { camera: 'counted' });
    const { code } = await projectedCode();
    await page.fill('#manualCodeInput', code);
    await page.click('#manualCodeSubmit');
    await page.locator('#manualCodeFeedback.is-success').waitFor({ timeout: 20000 });
    assert.equal(await page.evaluate(() => window.__cameraRequests), 0);
    await context.close();
});

test('the code box formats, keeps leading zeros, ignores letters and corrects cleanly', async () => {
    const { context, page } = await student(2);
    const input = page.locator('#manualCodeInput');
    await input.fill('Code: 0123-4567');
    assert.equal(await input.inputValue(), '0123 4567');
    assert.match(await page.locator('#manualCodeFeedback').textContent(), /numbers only/);
    await input.fill('01234567999');
    assert.equal(await input.inputValue(), '0123 4567');
    // A pasted code with spaces lands formatted.
    await input.fill('');
    await input.focus();
    await page.keyboard.insertText(' 4826 9137 ');     // what a paste inserts
    assert.equal(await input.inputValue(), '4826 9137');
    // Backspace just after the space removes the digit before it, rather
    // than a separator that would only reappear.
    await input.fill('48269');
    assert.equal(await input.inputValue(), '4826 9');
    await page.evaluate(() => document.getElementById('manualCodeInput').setSelectionRange(5, 5));
    await page.keyboard.press('Backspace');
    assert.equal(await input.inputValue(), '4829');
    // Correcting a digit in the middle keeps the caret where it was.
    await input.fill('48269137');
    await page.evaluate(() => document.getElementById('manualCodeInput').setSelectionRange(2, 2));
    await page.keyboard.press('Backspace');
    await page.keyboard.type('5');
    assert.equal(await input.inputValue(), '4526 9137');
    // Too short is refused on the page, without a request.
    let posts = 0;
    page.on('request', request => { if (request.url().endsWith('/api/attendance/manual')) posts += 1; });
    await input.fill('4826 91');
    await page.click('#manualCodeSubmit');
    assert.match(await page.locator('#manualCodeFeedback').textContent(), /Enter all 8 digits/);
    assert.equal(await input.getAttribute('aria-invalid'), 'true');
    assert.equal(posts, 0);
    await context.close();
});

test('a double tap sends one request and shows one answer', async () => {
    const { context, page } = await student(3);
    let posts = 0;
    await page.route('**/api/attendance/manual', async route => {
        posts += 1;
        await sleep(1500);            // a slow network: the button is tapped again meanwhile
        await route.continue();
    });
    const { code } = await projectedCode();
    await page.fill('#manualCodeInput', code);
    await page.click('#manualCodeSubmit');
    await page.click('#manualCodeSubmit', { force: true, noWaitAfter: true }).catch(() => {});
    await page.dblclick('#manualCodeSubmit', { force: true, noWaitAfter: true }).catch(() => {});
    assert.equal(await page.locator('#manualCodeSubmit').isDisabled(), true);
    assert.equal(await page.locator('#manualCodeSubmit').getAttribute('aria-busy'), 'true');
    await page.locator('#manualCodeFeedback.is-success').waitFor({ timeout: 20000 });
    assert.equal(posts, 1);
    assert.equal((await attendees()).filter(a => a.matric_no === 'E2E00003').length, 1);
    await context.close();
});

test('an expired code asks for the new one; a lockout counts down; nothing claims success', async () => {
    const { context, page } = await student(4);
    const input = page.locator('#manualCodeInput');
    let reply = { status: 400, body: { status: 'error', outcome: 'code_expired',
        message: 'That code has just changed. Enter the new code shown on the screen.' } };
    await page.route('**/api/attendance/manual', route => route.fulfill({
        status: reply.status, contentType: 'application/json', body: JSON.stringify(reply.body),
    }));
    await input.fill('11112222');
    await page.click('#manualCodeSubmit');
    const feedback = page.locator('#manualCodeFeedback');
    await page.locator('#manualCodeFeedback.is-warning').waitFor();
    assert.match(await feedback.textContent(), /just changed/);
    assert.equal(await input.inputValue(), '');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'manualCodeInput');
    assert.equal(await page.locator('#manualCodeSubmit').isDisabled(), false);

    reply = { status: 400, body: { status: 'error', outcome: 'invalid_code', attempts_remaining: 0,
        retry_after_seconds: 120, message: 'That code is not correct, and that was too many incorrect codes.' } };
    await input.fill('11112222');
    await page.click('#manualCodeSubmit');
    await page.locator('#manualCodeSubmit:has-text("Try again in")').waitFor();
    assert.match(await page.locator('#manualCodeSubmit').textContent(), /Try again in [12]:\d\d/);
    assert.equal(await page.locator('#manualCodeSubmit').isDisabled(), true);
    assert.equal(await page.locator('#manualCodeFeedback.is-success').count(), 0);
    await context.close();
});

test('a dropped connection says NOT recorded, after one quiet retry', async () => {
    const { context, page } = await student(4);
    let posts = 0;
    await page.route('**/api/attendance/manual', route => { posts += 1; return route.abort('internetdisconnected'); });
    await page.fill('#manualCodeInput', '12345678');
    await page.click('#manualCodeSubmit');
    await page.locator('#manualCodeFeedback.is-danger').waitFor({ timeout: 20000 });
    assert.match(await page.locator('#manualCodeFeedback').textContent(), /NOT recorded/);
    assert.equal(posts, 2);
    assert.equal(await page.locator('#manualCodeSubmit').isDisabled(), false);
    await context.close();
});

test('two classes open: the student chooses, the page never guesses', async () => {
    const { context, page } = await student(5);
    await page.focus('#manualCodeInput');
    const select = page.locator('#manualSessionSelect');
    await select.waitFor();
    assert.equal(await select.locator('option').count(), 3);   // placeholder + 2 classes
    const { code } = await projectedCode();
    await page.fill('#manualCodeInput', code);
    await page.click('#manualCodeSubmit');
    assert.match(await page.locator('#manualCodeFeedback').textContent(), /Choose your class first/);
    await select.selectOption(String(SID));
    await page.click('#manualCodeSubmit');
    await page.locator('#manualCodeFeedback.is-success').waitFor({ timeout: 20000 });
    assert.match(await page.locator('#manualCodeFeedback').textContent(), /CSC301/);
    await context.close();
});

test('keyboard only: reach the box, type, submit, and see where focus is', async () => {
    const { context, page } = await student(6);
    let reached = false;
    for (let presses = 0; presses < 60 && !reached; presses++) {
        await page.keyboard.press('Tab');
        reached = await page.evaluate(() => document.activeElement && document.activeElement.id === 'manualCodeInput');
    }
    assert.ok(reached, 'the code box is reachable with Tab');
    const ring = await page.evaluate(() => getComputedStyle(document.activeElement).outlineStyle);
    assert.notEqual(ring, 'none');
    // Labelled, described, and announced.
    assert.equal(await page.locator('label[for="manualCodeInput"]').count(), 1);
    assert.match(await page.locator('#manualCodeInput').getAttribute('aria-describedby'), /manualCodeFeedback/);
    assert.equal(await page.locator('#manualCodeFeedback').getAttribute('role'), 'status');
    assert.equal(await page.locator('#manualCodeInput').getAttribute('inputmode'), 'numeric');
    const { code } = await projectedCode();
    await page.keyboard.type(code);
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'manualCodeSubmit');
    assert.notEqual(await page.evaluate(() => getComputedStyle(document.activeElement).outlineStyle), 'none');
    await page.keyboard.press('Enter');
    await page.locator('#manualCodeFeedback.is-success').waitFor({ timeout: 20000 });
    // The confirmation takes focus, so a screen reader reads it out.
    assert.equal(await page.evaluate(() => document.activeElement.id), 'manualCodeFeedback');
    // Big enough to hit with a thumb.
    const box = await page.locator('#manualCodeSubmit').boundingBox();
    assert.ok(box.height >= 44, `submit button is ${box.height}px tall`);
    await context.close();
});

test('the projector shows the code beside the QR, in full screen too, on the server clock', async () => {
    const page = lecturer.page;
    await page.goto(`${BASE}/session/${SID}/qr`);
    const digits = page.locator('#manualCodeDigits');
    await digits.waitFor();
    const api = await (await lecturer.context.request.get(`${BASE}/api/session/${SID}/manual_code`)).json();
    await page.waitForFunction(() => /New code in \d+s/.test(document.getElementById('manualCodeStatus').textContent));
    const shown = (await digits.textContent()).replace(/\D/g, '');
    const seconds = Number(/(\d+)s/.exec(await page.locator('#manualCodeStatus').textContent())[1]);
    if (api.expires_in_ms > 3000) {
        assert.equal(shown, api.code);
        assert.ok(Math.abs(seconds - Math.ceil(api.expires_in_ms / 1000)) <= 1,
                  `countdown ${seconds}s vs server ${api.expires_in_ms}ms`);
    }
    assert.match(await page.locator('.manual-code-instruction').textContent(),
                 /Can't scan the QR\? Enter this code in ScanMark\./);

    await page.click('#qrFullscreenBtn');
    await page.locator('#qrStage.is-full').waitFor();
    const viewport = page.viewportSize();
    const codeBox = await page.locator('#manualCode').boundingBox();
    const qrBox = await page.locator('#qrImage').boundingBox();
    for (const [name, box] of [['code', codeBox], ['qr', qrBox]]) {
        assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width + 1
                  && box.y + box.height <= viewport.height + 1, `${name} is on screen`);
    }
    const overlap = !(codeBox.x >= qrBox.x + qrBox.width || qrBox.x >= codeBox.x + codeBox.width
                      || codeBox.y >= qrBox.y + qrBox.height || qrBox.y >= codeBox.y + codeBox.height);
    assert.ok(!overlap, 'the code does not sit on top of the QR');
    const fontPx = await page.evaluate(() => parseFloat(getComputedStyle(
        document.querySelector('.manual-code-digits')).fontSize));
    assert.ok(fontPx >= 70, `projected digits are ${fontPx}px`);
    assert.ok(qrBox.height >= 0.8 * viewport.height, 'the QR still fills the height');
    await page.keyboard.press('Escape');
    await page.locator('#qrStage:not(.is-full)').waitFor();
});

test('a projector that loses the server blanks the expired code, then recovers', async () => {
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    await signIn(context, SEED.lecturer);
    const page = await context.newPage();
    await page.clock.install();
    await page.goto(`${BASE}/session/${SID}/qr`);
    await page.locator('#manualCodeDigits').waitFor();
    let calls = 0;
    let offline = true;
    await page.route('**/manual_code', route => {
        calls += 1;
        return offline ? route.abort('internetdisconnected') : route.continue();
    });
    // The tab comes back from the background: it re-syncs at once.
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await page.clock.runFor(500);
    assert.ok(calls >= 1, 'visibility change triggered a refresh');
    // Past the code's lifetime with no server: never shown as current.
    await page.clock.runFor(65000);
    await page.waitForFunction(() => document.getElementById('manualCode').classList.contains('is-offline'));
    assert.equal(await page.evaluate(() => getComputedStyle(
        document.getElementById('manualCodeDigits')).visibility), 'hidden');
    assert.match(await page.locator('#manualCodeStatus').textContent(), /Cannot reach ScanMark/);
    // Back online: the next retry restores a live code.
    offline = false;
    await page.clock.runFor(16000);
    await page.waitForFunction(() => !document.getElementById('manualCode').classList.contains('is-offline'),
                               null, { timeout: 15000 });
    assert.equal(await page.evaluate(() => getComputedStyle(
        document.getElementById('manualCodeDigits')).visibility), 'visible');
    await context.close();
});

test('the projector rotates the code by itself, once a minute, in step with the server', async () => {
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    await signIn(context, SEED.lecturer);
    const page = await context.newPage();
    let calls = 0;
    page.on('request', request => { if (request.url().includes('/manual_code')) calls += 1; });
    await page.goto(`${BASE}/session/${SID}/qr`);
    const first = await (await context.request.get(`${BASE}/api/session/${SID}/manual_code`)).json();
    const shownFirst = (await page.locator('#manualCodeDigits').textContent()).replace(/\D/g, '');
    // Real time, no fake clock: wait out the rest of this minute.
    await sleep(first.expires_in_ms + 2500);
    const second = await (await context.request.get(`${BASE}/api/session/${SID}/manual_code`)).json();
    const shownSecond = (await page.locator('#manualCodeDigits').textContent()).replace(/\D/g, '');
    assert.notEqual(second.code, first.code);
    assert.equal(shownSecond, second.code, 'the page shows the server\'s new code without a reload');
    assert.ok(shownFirst === first.code || first.expires_in_ms < 1500);
    assert.ok(calls >= 1 && calls <= 2, `${calls} refreshes across one rotation`);
    await context.close();
});

test('QR scanning still works after the shared-location refactor', async () => {
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await signIn(context, SEED.students[7]);
    await context.exposeFunction('__harnessFrame', async () => {
        const image = await lecturer.context.request.get(`${BASE}/session/${SID}/live?t=${Date.now()}`);
        return { png: `data:image/png;base64,${(await image.body()).toString('base64')}` };
    });
    await context.addInitScript(fakeGeolocation, SEED.room);
    await context.addInitScript(() => {
        try { delete window.BarcodeDetector; } catch (_) { /* jsQR path */ }
        window.BarcodeDetector = undefined;
        navigator.mediaDevices.getUserMedia = async () => {
            const canvas = document.createElement('canvas');
            canvas.width = 640;
            canvas.height = 480;
            const ctx = canvas.getContext('2d');
            let image = null;
            const refresh = async () => {
                const frame = await window.__harnessFrame();
                const next = new Image();
                next.onload = () => { image = next; };
                next.src = frame.png;
            };
            refresh();
            setInterval(refresh, 3000);
            setInterval(() => {
                ctx.fillStyle = '#fff';
                ctx.fillRect(0, 0, 640, 480);
                if (image) ctx.drawImage(image, 140, 60, 360, 360);
                ctx.fillStyle = (Math.floor(performance.now() / 33) % 2) ? '#fefefe' : '#fff';
                ctx.fillRect(0, 0, 1, 1);
            }, 33);
            return canvas.captureStream(30);
        };
    });
    const page = await context.newPage();
    await page.goto(`${BASE}/student_dashboard`);
    await page.click('#scanBtn');
    const banner = page.locator('#result-banner');
    await banner.waitFor({ state: 'visible', timeout: 45000 });
    assert.match(await banner.textContent(), /Marked present for CSC301/);
    const mine = (await attendees()).filter(a => a.matric_no === 'E2E00007');
    assert.equal(mine.length, 1);
    assert.equal(mine[0].method, 'qr');
    await context.close();
});
