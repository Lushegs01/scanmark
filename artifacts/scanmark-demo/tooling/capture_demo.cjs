/**
 * Drive the REAL ScanMark application with Playwright and capture the demo
 * asset package: screenshots 01-07 and recordings 08-09.
 *
 * Nothing on screen is mocked. The lecturer opens a class through the real
 * dashboard; the projector shows the real rotating QR; the student's phone
 * runs the real scanner (static/scanner.js + jsQR) against Chromium's fake
 * camera device, which is fed a capture of that projector screen; the scan is
 * judged by the real /mark_attendance endpoint, geofence included. Classmates
 * check in through the same endpoint with the token the projector is showing.
 *
 * Every screenshot logs the on-screen figures it shows to capture-log.json so
 * verify_demo.py can check them against the database afterwards.
 *
 * Run through run_demo.sh, which boots the isolated app and sets:
 *   DEMO_BASE_URL, DEMO_OUT_DIR, DEMO_RUN_DIR, DEMO_PASSWORD_FILE, DEMO_SEED_FILE
 */
'use strict';

// Behind an HTTPS-only egress proxy the CDN assets (Bootstrap, fonts,
// Chart.js) go through it while the local app must not. Playwright otherwise
// forces loopback through the proxy too.
process.env.PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK = '1';
// ScanMark's service worker answers POST /mark_attendance itself (it is the
// offline queue), so the scan only becomes visible to Playwright's routing
// when the worker's own network requests are reported.
process.env.PW_EXPERIMENTAL_SERVICE_WORKER_NETWORK_EVENTS = '1';

const { chromium, request } = require('playwright');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const BASE = process.env.DEMO_BASE_URL || 'http://127.0.0.1:8100';
const OUT = path.resolve(process.env.DEMO_OUT_DIR || path.join(__dirname, '..'));
const RUN = path.resolve(process.env.DEMO_RUN_DIR);
const PASSWORD = fs.readFileSync(process.env.DEMO_PASSWORD_FILE, 'utf8').trim();
const SEED = JSON.parse(fs.readFileSync(process.env.DEMO_SEED_FILE, 'utf8'));
const PROXY = process.env.HTTPS_PROXY
    ? { server: process.env.HTTPS_PROXY, bypass: '127.0.0.1,localhost' } : undefined;

// The recorded desktop renders at 1x. This container has no GPU, and
// software-rendering the app's glass and backdrop-blur styling at 2x cut every
// scroll to ~8 frames/s. The 4K stills come from a separate 2x tab instead
// (desktopStill), signed in to the same session and opened at the same moment.
const DESKTOP_RECORD = { viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 };
const DESKTOP_STILL = { viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 2 };
// The phone is a 390x844 window whose device scale is REALLY 3, set on the
// browser's command line, rather than Playwright's emulated deviceScaleFactor.
// Screencast frames are CSS-pixel sized under emulation (headless, new
// headless and headed alike), which would make the phone video 390x844; with
// a real scale factor they are 1170x2532 at full frame rate. Layout is the
// same either way: 390 CSS px wide, devicePixelRatio 3.
const PHONE_ARGS = ['--force-device-scale-factor=3', '--window-size=390,844'];
const PHONE = {
    viewport: null, hasTouch: true,
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 '
        + '(KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36',
};
// Pacing: how long a key screen stays still for the editor.
const BEAT = 1200, HOLD = 2500, LONG_HOLD = 4000;

const room = SEED.classroom;
const featured = SEED.featured_student;
const mainCourse = SEED.courses[SEED.main_course];
// Twenty of twenty-four turn up today. The four who do not are the ones the
// seeded history already shows struggling, plus one more.
const ABSENT_TODAY = new Set(['Kelechi Obi', 'Musa Garba', 'Blessing Effiong', 'Samuel Ojo']);
const classmates = SEED.students.filter(s => s.name !== featured.name && !ABSENT_TODAY.has(s.name));
const EARLY_CLASSMATES = 14;

const log = { started_at: new Date().toISOString(), base_url: BASE, assets: {}, events: [] };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function note(event, details = {}) {
    const entry = { t: new Date().toISOString(), event, ...details };
    log.events.push(entry);
    console.log(`[capture] ${event}`, Object.keys(details).length ? JSON.stringify(details) : '');
}

/* ---------------------------------------------------------------------------
 * Screen recorder: CDP screencast -> JPEG frames with real timestamps ->
 * ffmpeg. No cursor and no browser chrome exist in a screencast, and frame
 * timing is the page's own, so holds and transitions keep their real pace.
 * ------------------------------------------------------------------------- */
class Recorder {
    constructor(page, name, { maxWidth, maxHeight }) {
        this.page = page;
        this.name = name;
        this.dir = path.join(RUN, `frames-${name}`);
        this.size = { maxWidth, maxHeight };
        this.frames = [];
    }

    addFrame(base64, t) {
        const file = path.join(this.dir, `f${String(this.frames.length).padStart(6, '0')}.jpg`);
        fs.writeFileSync(file, Buffer.from(base64, 'base64'));
        this.frames.push({ file, t });
    }

    async start() {
        fs.rmSync(this.dir, { recursive: true, force: true });
        fs.mkdirSync(this.dir, { recursive: true });
        this.cdp = await this.page.context().newCDPSession(this.page);
        this.cdp.on('Page.screencastFrame', ({ data, metadata, sessionId }) => {
            this.addFrame(data, metadata.timestamp);
            this.cdp.send('Page.screencastFrameAck', { sessionId }).catch(() => {});
        });
        await this.cdp.send('Page.startScreencast',
            { format: 'jpeg', quality: 95, everyNthFrame: 1, ...this.size });
        note('recording.start', { name: this.name });
    }

    async stop() {
        const stoppedAt = Date.now() / 1000;
        await this.cdp.send('Page.stopScreencast');
        await this.cdp.detach();
        note('recording.stop', { name: this.name, frames: this.frames.length });
        return stoppedAt;
    }

    encode(stoppedAt) {
        if (this.frames.length < 2) throw new Error(`${this.name}: no frames recorded`);
        const lines = ['ffconcat version 1.0'];
        this.frames.forEach((frame, i) => {
            const next = i + 1 < this.frames.length ? this.frames[i + 1].t : stoppedAt;
            lines.push(`file '${frame.file}'`, `duration ${Math.max(1 / 60, next - frame.t).toFixed(4)}`);
        });
        // The concat demuxer ignores the last entry's duration unless the
        // file is listed once more.
        lines.push(`file '${this.frames[this.frames.length - 1].file}'`);
        const list = path.join(this.dir, 'frames.ffconcat');
        fs.writeFileSync(list, lines.join('\n'));
        // yuv420p needs even dimensions. Pad (never crop or resample) every
        // frame to the largest even size seen; a 3x capture can be 1 px odd.
        let width = 0, height = 0;
        for (const { file } of this.frames) {
            const size = jpegSize(fs.readFileSync(file));
            width = Math.max(width, size.width);
            height = Math.max(height, size.height);
        }
        width += width % 2;
        height += height % 2;
        const webm = path.join(OUT, `${this.name}.webm`);
        const common = ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', list,
            '-fps_mode', 'cfr', '-r', '30',
            '-vf', `pad=${width}:${height}:0:0:color=0x1f2328,format=yuv420p`, '-an'];
        execFileSync('ffmpeg', [...common, '-c:v', 'libvpx-vp9', '-crf', '20', '-b:v', '0',
            '-row-mt', '1', '-deadline', 'good', '-cpu-used', '2', webm]);
        // An H.264 twin: most editing tools import it without a plugin.
        const mp4 = path.join(OUT, 'editing-mezzanine', `${this.name}.mp4`);
        fs.mkdirSync(path.dirname(mp4), { recursive: true });
        execFileSync('ffmpeg', [...common, '-c:v', 'libx264', '-crf', '16', '-preset', 'slow',
            '-tune', 'stillimage', '-movflags', '+faststart', mp4]);
        fs.rmSync(this.dir, { recursive: true, force: true });
        log.assets[`${this.name}.webm`] = { kind: 'video', seconds: +(stoppedAt - this.frames[0].t).toFixed(1),
            source_frames: this.frames.length, mezzanine: `editing-mezzanine/${this.name}.mp4` };
    }
}

/** Pixel size of a baseline/progressive JPEG, from its SOF marker. */
function jpegSize(buffer) {
    for (let i = 2; i < buffer.length;) {
        const marker = buffer[i + 1];
        const length = buffer.readUInt16BE(i + 2);
        if (marker >= 0xC0 && marker <= 0xC2) {
            return { height: buffer.readUInt16BE(i + 5), width: buffer.readUInt16BE(i + 7) };
        }
        i += 2 + length;
    }
    throw new Error('not a JPEG');
}

/* ------------------------------------------------------------------------- */

async function settle(page) {
    await page.waitForLoadState('load');
    await page.evaluate(() => document.fonts.ready);
    // Icon font and web font swap-in, Bootstrap transitions.
    await sleep(400);
}

async function shot(page, name, facts) {
    const file = path.join(OUT, name);
    await page.screenshot({ path: file, animations: 'allow' });
    log.assets[name] = { kind: 'screenshot', url: page.url().replace(BASE, ''), facts };
    note('screenshot', { name, facts });
}

let stillContext;   // the 2x "still camera"; see DESKTOP_STILL

/**
 * A 4K still of a desktop page from a tab that is never recorded: the same
 * signed-in session, URL and moment as the recording, rendered at 2x.
 *
 * With `fullPage` the window is made as tall as the page. The app paints its
 * gradient with `background-attachment: fixed` on a 100vh body, so a stitched
 * full-page screenshot shows the gradient for the first screen and plain white
 * after it, which no user ever sees.
 */
async function desktopStill(name, url, readFacts, { prepare, afterLoad = 0, fullPage = false } = {}) {
    const page = await stillContext.newPage();
    await page.goto(url);
    await settle(page);
    if (prepare) await prepare(page);
    await sleep(afterLoad);
    if (fullPage) {
        const height = await page.evaluate(() => Math.ceil(document.documentElement.scrollHeight));
        await page.setViewportSize({ width: DESKTOP_STILL.viewport.width, height });
        await sleep(600);
    }
    await parkPointer(page);
    await shot(page, name, await readFacts(page));
    log.assets[name].full_page = fullPage;
    await page.close();
}

// What each still shows, read from the page it was taken from.
const readDashboard = page => page.evaluate(() => ({
    stat_tiles: [...document.querySelectorAll('.stat-card')].map(c => c.innerText.replace(/\s+/g, ' ').trim()),
    courses: [...document.querySelectorAll('.course-card .course-code')].map(e => e.textContent.trim()),
}));
const readProjector = page => page.evaluate(() => ({
    heading: document.querySelector('h4.text-success').textContent.trim(),
    session: document.querySelector('.badge.bg-success').textContent.trim(),
    roster_line: document.querySelector('p.small.text-muted').textContent.replace(/\s+/g, ' ').trim(),
    classroom: document.getElementById('locationStatus').textContent.trim(),
    present: document.getElementById('student-count').textContent,
    enrolled: document.getElementById('enrolled-count').textContent,
}));
const readLiveList = page => page.evaluate(() => ({
    present: document.getElementById('student-count').textContent,
    enrolled: document.getElementById('enrolled-count').textContent,
    newest: document.querySelector('#live-student-list li').innerText.replace(/\s+/g, ' ').trim(),
}));
const readRecords = page => page.evaluate(() => ({
    summary: document.querySelector('h2 + p').textContent.replace(/\s+/g, ' ').trim(),
    first_session_header: document.querySelector('.accordion-button').textContent.replace(/\s+/g, ' ').trim(),
    first_session_rows: [...document.querySelectorAll('.accordion-collapse.show tbody tr')].length,
    names_in_first_session: [...document.querySelectorAll('.accordion-collapse.show tbody tr')]
        .map(tr => tr.innerText.replace(/\s+/g, ' ').trim()),
}));
const readAnalytics = page => page.evaluate(() => ({
    peak: document.getElementById('stat-peak').textContent,
    average: document.getElementById('stat-avg').textContent,
    series: JSON.parse(document.getElementById('chart-counts').textContent),
    rates: JSON.parse(document.getElementById('chart-rates').textContent),
    labels: JSON.parse(document.getElementById('chart-dates').textContent),
    chart_drawn: (() => {
        const c = document.getElementById('attendanceChart');
        const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
        let ink = 0;
        for (let i = 3; i < d.length; i += 4) if (d[i]) ink++;
        return ink > 1000;
    })(),
}));
const projectorReady = page => page.waitForFunction(() => {
    const img = document.getElementById('qrImage');
    return img.complete && img.naturalWidth > 0
        && document.getElementById('enrolled-count').textContent !== '0';
});

async function login(page, email) {
    await page.goto(`${BASE}/login`);
    await page.fill('input[name=email]', email);
    await page.fill('input[name=password]', PASSWORD);
    await Promise.all([page.waitForURL(url => !url.pathname.startsWith('/login')),
        page.click('button[type=submit]')]);
}

async function smoothScrollTo(page, top) {
    await page.evaluate(y => window.scrollTo({ top: y, behavior: 'smooth' }), top);
    await sleep(1100);
}

async function parkPointer(page) {
    // A hovered card lifts on this design; keep the pointer off the UI.
    await page.mouse.move(1915, 1075);
}

/** A classmate's own signed-in HTTP session, ready to post a scan. */
async function classmateSession(student) {
    const api = await request.newContext({ baseURL: BASE });
    const loginPage = await (await api.get('/login')).text();
    const csrf = loginPage.match(/name="csrf_token" value="([^"]+)"/)[1];
    const res = await api.post('/login', { form: { csrf_token: csrf, email: student.email, password: PASSWORD } });
    if (!res.ok()) throw new Error(`login failed for ${student.name}: ${res.status()}`);
    const scanPage = await (await api.get('/scan_page')).text();
    const scanCsrf = scanPage.match(/csrfToken: "([^"]+)"/)[1];
    return { student, api, scanCsrf };
}

/** Scan with the token the projector is displaying right now. */
async function classmateScan(lecturerPage, sessionId, mate, index) {
    const token = (await (await lecturerPage.request.get(`${BASE}/api/qr_data/${sessionId}`)).json()).qr_text;
    // Seats spread across the room, all well inside its geofence.
    const angle = index * 2.399, metres = 8 + (index * 7) % 30;
    const res = await mate.api.post('/mark_attendance', {
        headers: { 'X-CSRFToken': mate.scanCsrf },
        data: {
            qr_data: token,
            lat: room.lat + (metres * Math.cos(angle)) / 111320,
            lon: room.lon + (metres * Math.sin(angle)) / (111320 * Math.cos(room.lat * Math.PI / 180)),
            accuracy_m: 6 + (index % 5) * 3,
            location_age_ms: 400 + (index % 4) * 700,
            captured_at: new Date().toISOString(),
            device_id: `demo-capture-classmate-${index}`,
        },
    });
    const body = await res.json();
    if (body.outcome !== 'success') throw new Error(`${mate.student.name}: ${res.status()} ${JSON.stringify(body)}`);
    note('classmate.checked_in', { name: mate.student.name, outcome: body.outcome });
}

/** Build the phone camera's feed from the projector as it looks right now. */
async function writeCameraFeed(lecturerContext, sessionId, y4m) {
    // A second projector window, never recorded: the one on camera keeps its
    // own scroll position and pace. Both show the same token (it is cached
    // per session on the server).
    const projector = await lecturerContext.newPage();
    await projector.goto(`${BASE}/session/${sessionId}/qr`);
    await projector.waitForFunction(() => {
        const img = document.getElementById('qrImage');
        return img.complete && img.naturalWidth > 0;
    });
    await settle(projector);
    const card = projector.locator('.card.shadow-lg').first();
    const cardBox = await card.boundingBox();
    const qrBox = await projector.locator('#qrImage').boundingBox();
    const png = path.join(RUN, 'camera-source.png');
    await card.screenshot({ path: png, scale: 'css' });
    const token = (await (await projector.request.get(`${BASE}/api/qr_data/${sessionId}`)).json()).qr_text;
    await projector.close();

    // 1280x720: exactly what the scanner asks getUserMedia for, so Chromium
    // passes it through uncropped. On the phone the feed covers the screen
    // (844 CSS px tall, so x1.17) and is centred under the viewfinder; a
    // 180 px code there reads as ~210 px, inside the 280 px frame.
    const scale = 180 / qrBox.width;
    const qrCentreX = (qrBox.x - cardBox.x + qrBox.width / 2) * scale;
    const qrCentreY = (qrBox.y - cardBox.y + qrBox.height / 2) * scale;
    const x = Math.round(640 - qrCentreX), y = Math.round(360 - qrCentreY);
    execFileSync('ffmpeg', ['-y', '-loglevel', 'error',
        '-f', 'lavfi', '-i', 'color=c=0x1f2328:s=1280x720:r=15', '-i', png,
        '-filter_complex', `[1:v]scale=${Math.round(cardBox.width * scale)}:-1[c];[0:v][c]overlay=${x}:${y}`,
        '-t', '2', '-pix_fmt', 'yuv420p', y4m]);
    note('camera.feed_written', { token_session: token.split('|')[0], token_issued: token.split('|')[1] });
    return token;
}

(async () => {
    fs.mkdirSync(OUT, { recursive: true });
    fs.mkdirSync(RUN, { recursive: true });
    const y4m = path.join(RUN, 'phone-camera.y4m');
    // Chromium opens the fake camera file when getUserMedia runs, not at
    // launch, so a placeholder now and the real frame just before the scan.
    execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'lavfi',
        '-i', 'color=c=0x1f2328:s=1280x720:r=15', '-t', '1', '-pix_fmt', 'yuv420p', y4m]);

    const lecturerBrowser = await chromium.launch({ proxy: PROXY });
    const studentBrowser = await chromium.launch({
        proxy: PROXY,
        args: [...PHONE_ARGS, '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream',
            `--use-file-for-fake-video-capture=${y4m}`],
    });
    const failures = [];
    const watch = (page, who, { closesMidRequest = false } = {}) => {
        page.on('requestfailed', r => {
            // A still tab is closed while its page is still polling; the
            // aborted poll is the close, not a fault.
            if (closesMidRequest && r.failure().errorText === 'net::ERR_ABORTED') return;
            failures.push(`${who}: ${r.url()} ${r.failure().errorText}`);
        });
        page.on('response', r => { if (r.status() >= 500) failures.push(`${who}: HTTP ${r.status()} ${r.url()}`); });
        page.on('pageerror', e => failures.push(`${who}: pageerror ${e.message}`));
    };

    try {
        // ---- Sign-ins happen off camera --------------------------------------
        const lecturerContext = await lecturerBrowser.newContext(DESKTOP_RECORD);
        const lecturer = await lecturerContext.newPage();
        lecturer.on('dialog', dialog => dialog.accept());   // "End class?" confirm
        watch(lecturer, 'lecturer');
        await login(lecturer, SEED.lecturer.email);
        stillContext = await lecturerBrowser.newContext({
            ...DESKTOP_STILL, storageState: await lecturerContext.storageState(),
        });
        stillContext.on('page', page => watch(page, 'lecturer-still', { closesMidRequest: true }));

        // 18 m from the room's pinned centre, a good indoor fix.
        const phoneFix = { latitude: room.lat + 18 / 111320, longitude: room.lon, accuracy: 9 };
        const phoneContext = await studentBrowser.newContext({
            ...PHONE, permissions: ['camera', 'geolocation'], geolocation: phoneFix,
        });
        const phone = await phoneContext.newPage();
        watch(phone, 'student');
        await login(phone, featured.email);

        const mates = [];
        for (const student of classmates) mates.push(await classmateSession(student));
        note('signed_in', { lecturer: SEED.lecturer.name, student: featured.name, classmates: mates.length });

        // ---- 09: lecturer flow, recorded from the dashboard onwards -----------
        await lecturer.goto(`${BASE}/lecturer_dashboard`);
        await settle(lecturer);
        await parkPointer(lecturer);
        const lecturerRec = new Recorder(lecturer, '09-lecturer-dashboard-flow', { maxWidth: 1920, maxHeight: 1080 });
        await lecturerRec.start();
        await Promise.all([sleep(HOLD),
            desktopStill('01-product-dashboard.png', lecturer.url(), readDashboard)]);

        const card = lecturer.locator('.course-card', { hasText: SEED.main_course });
        await card.locator('select[name=classroom_id]').selectOption({ label: room.name });
        await sleep(BEAT);
        await Promise.all([lecturer.waitForURL(/\/session\/\d+\/qr$/),
            card.getByRole('button', { name: 'Start Attendance' }).click()]);
        await parkPointer(lecturer);
        await projectorReady(lecturer);
        await settle(lecturer);
        const sessionId = Number(lecturer.url().match(/session\/(\d+)\/qr/)[1]);
        log.live_session_id = sessionId;
        await Promise.all([sleep(HOLD),
            desktopStill('02-lecturer-session-qr.png', lecturer.url(), readProjector,
                { prepare: projectorReady })]);
        await sleep(BEAT);

        // The framing that shows the code AND the newest arrivals: new names
        // are prepended, so the top rows of the roll call are where it happens.
        const liveFraming = await lecturer.evaluate(() => {
            const list = document.getElementById('live-student-list').closest('.card');
            return Math.max(0, Math.round(list.getBoundingClientRect().top + window.scrollY - 720));
        });
        // Classmates arrive while the projector watches.
        for (let i = 0; i < EARLY_CLASSMATES; i++) {
            await classmateScan(lecturer, sessionId, mates[i], i);
            if (i === 2) await smoothScrollTo(lecturer, liveFraming);
            await sleep(650 + (i * 137) % 500);
        }
        await sleep(BEAT);

        // ---- 08: the featured student's phone ---------------------------------
        await phone.goto(`${BASE}/student_dashboard`);
        await settle(phone);
        const phoneRec = new Recorder(phone, '08-student-checkin-flow', { maxWidth: 1170, maxHeight: 2532 });
        await phoneRec.start();
        await sleep(HOLD);
        note('student.dashboard_before', { stat_tiles: (await readDashboard(phone)).stat_tiles });

        await Promise.all([phone.waitForURL(/\/scan_page$/), phone.locator('#scanBtn').tap()]);
        await settle(phone);
        await sleep(HOLD);

        // Hold the scan request a moment once it is sent, purely so the
        // in-flight screen can be photographed. It is sent unmodified.
        let releaseScan, scanSeen;
        const scanSent = new Promise(resolve => { scanSeen = resolve; });
        const holdScan = new Promise(resolve => { releaseScan = resolve; });
        const scanBodies = [];
        await phoneContext.route('**/mark_attendance', async route => {
            const body = route.request().postData();
            scanBodies.push(body ? JSON.parse(body) : null);
            scanSeen();
            await holdScan;
            await route.continue();
        });
        const scanResponse = phone.waitForResponse(r => r.url().endsWith('/mark_attendance'));

        const projectedToken = await writeCameraFeed(lecturerContext, sessionId, y4m);
        // Chromium stamps an emulated fix with the moment it was set, so the
        // one from sign-in is a minute old by now and ScanMark rightly calls it
        // stale (GEOFENCE_MAX_LOCATION_AGE_MS). A phone's GPS keeps producing
        // fixes while the camera is open; so does this.
        await phoneContext.setGeolocation(phoneFix);
        const gpsTicker = setInterval(() => phoneContext.setGeolocation(phoneFix).catch(() => {}), 2000);
        await phone.getByRole('button', { name: /Start Advanced Scanner/ }).tap();
        // Never hang the run on the hold: if routing misses the request the
        // scan simply completes and 03 shows whatever state is on screen.
        await Promise.race([scanSent, sleep(8000)]);
        await sleep(350);
        await shot(phone, '03-student-checkin.png', await phone.evaluate(() => ({
            scanner_status: document.getElementById('status-badge').textContent.trim(),
            camera_frame: `${document.getElementById('camera-feed').videoWidth}x${document.getElementById('camera-feed').videoHeight}`,
        })));
        await sleep(1200);
        releaseScan();
        const response = await scanResponse;
        clearInterval(gpsTicker);
        const result = await response.json();
        const sent = scanBodies.find(Boolean);
        log.featured_scan = {
            http_status: response.status(), outcome: result.outcome, message: result.message,
            projected_session: projectedToken.split('|')[0],
            decoded_session: sent ? sent.qr_data.split('|')[0] : null,
            sent_location: sent ? { lat: sent.lat, lon: sent.lon, accuracy_m: sent.accuracy_m } : null,
            request_held_for_screenshot: scanBodies.length > 0,
        };
        note('student.scan_response', log.featured_scan);
        if (result.outcome !== 'success') throw new Error(`featured scan failed: ${JSON.stringify(result)}`);
        await phone.waitForSelector('#result-banner.alert-success:not(.d-none)');
        await sleep(700);
        await shot(phone, '04-attendance-confirmation.png', await phone.evaluate(() => ({
            banner: document.getElementById('result-banner').textContent.trim(),
            signed_in_as: document.querySelector('p.text-muted').textContent.trim(),
        })));
        await sleep(HOLD);

        // Back to the portal by the logo, as a student would.
        await Promise.all([phone.waitForURL(/\/student_dashboard$/), phone.locator('a.navbar-brand').tap()]);
        await settle(phone);
        await sleep(LONG_HOLD);
        phoneRec.stoppedAt = await phoneRec.stop();
        // Off camera: software-rendered at 3x, a scroll here would play at a
        // few frames a second, so the recording ends on the portal and the
        // still frames the record row directly.
        await phone.evaluate(() => {
            const label = [...document.querySelectorAll('.section-label')].pop();
            window.scrollTo({ top: label.getBoundingClientRect().top + window.scrollY - 24, behavior: 'instant' });
        });
        await sleep(500);
        await shot(phone, '07-mobile-experience.png', await phone.evaluate(() => ({
            stat_tiles: [...document.querySelectorAll('.stat-card')].map(c => c.innerText.replace(/\s+/g, ' ').trim()),
            records_row: document.querySelector('tbody tr').innerText.replace(/\s+/g, ' ').trim(),
        })));

        // ---- 09 continues: the projector shows the new arrival ----------------
        await lecturer.waitForFunction(name => document.querySelector('#live-student-list li h6')
            ?.textContent === name, featured.name);
        await sleep(BEAT);
        await smoothScrollTo(lecturer, 10000);
        await Promise.all([sleep(LONG_HOLD),
            desktopStill('02b-lecturer-live-checkins.png', lecturer.url(), readLiveList, {
                prepare: async page => {
                    await projectorReady(page);
                    await page.waitForFunction(name => document.querySelector('#live-student-list li h6')
                        ?.textContent === name, featured.name);
                    await page.evaluate(() => window.scrollTo({ top: 10000, behavior: 'instant' }));
                    await sleep(300);
                },
            })]);

        // Late arrivals.
        for (let i = EARLY_CLASSMATES; i < mates.length; i++) {
            await classmateScan(lecturer, sessionId, mates[i], i);
            await sleep(900 + (i * 211) % 600);
        }
        await sleep(HOLD);
        await smoothScrollTo(lecturer, 0);
        await sleep(BEAT);

        // End the class. The recording keeps the app's one-off "has ended"
        // notice; the stills, loaded after it was shown, are the clean register.
        await Promise.all([lecturer.waitForURL(/\/course\/\d+\/attendance/),
            lecturer.getByRole('button', { name: /End Class/ }).click()]);
        await settle(lecturer);
        await parkPointer(lecturer);
        await Promise.all([sleep(LONG_HOLD), (async () => {
            await desktopStill('05-attendance-records.png', lecturer.url(), readRecords);
            await desktopStill('05b-attendance-records-full.png', lecturer.url(), readRecords, { fullPage: true });
        })()]);
        await smoothScrollTo(lecturer, 520);
        await sleep(HOLD);
        await smoothScrollTo(lecturer, 0);

        await Promise.all([lecturer.waitForURL(/dashboard/), lecturer.getByRole('link', { name: 'Back' }).click()]);
        await settle(lecturer);
        await parkPointer(lecturer);
        await sleep(BEAT);
        await Promise.all([lecturer.waitForURL(/\/analytics$/),
            lecturer.locator('.course-card', { hasText: SEED.main_course }).getByRole('link', { name: 'Analytics' }).click()]);
        await settle(lecturer);
        await parkPointer(lecturer);
        // Chart.js draws its line over 1.5 s; the stills wait it out too.
        await Promise.all([sleep(2200 + HOLD),
            desktopStill('06-dashboard-analytics.png', lecturer.url(), readAnalytics, { afterLoad: 2200 })]);
        // The chart's date axis sits just below the first screen.
        await smoothScrollTo(lecturer, 10000);
        await Promise.all([sleep(LONG_HOLD),
            desktopStill('06b-dashboard-analytics-full.png', lecturer.url(), readAnalytics,
                { afterLoad: 2200, fullPage: true })]);
        lecturerRec.stoppedAt = await lecturerRec.stop();

        // ---- Encode once the browsers are idle --------------------------------
        phoneRec.encode(phoneRec.stoppedAt);
        lecturerRec.encode(lecturerRec.stoppedAt);

        for (const mate of mates) await mate.api.dispose();
        log.failures = failures;
        log.finished_at = new Date().toISOString();
        fs.writeFileSync(path.join(RUN, 'capture-log.json'), JSON.stringify(log, null, 2));
        if (failures.length) {
            console.error('[capture] request failures during capture:\n' + failures.join('\n'));
            process.exitCode = 2;
        }
    } finally {
        await studentBrowser.close();
        await lecturerBrowser.close();
    }
})().catch(error => {
    fs.writeFileSync(path.join(RUN, 'capture-log.json'), JSON.stringify({ ...log, error: String(error.stack || error) }, null, 2));
    console.error(error);
    process.exit(1);
});
