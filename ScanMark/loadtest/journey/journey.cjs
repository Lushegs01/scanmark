/*
 * The student journey, end to end, on a bad mobile network.
 *
 *   node journey.cjs --base http://127.0.0.1:8200 --control http://127.0.0.1:8299 \
 *       --cdn-proxy http://127.0.0.1:8201 --projector http://127.0.0.1:8300 \
 *       --seed seed.json --profile 2g --runs 3 --scenario journey --label after
 *
 * Scenarios
 *   journey   cold dashboard load (empty cache) -> warm load (service worker
 *             installed, connections reaped as if the student waited) ->
 *             tap "scan" -> confirmation on screen.
 *   outage    scanner open, then the network goes away (--outage drop|stall
 *             for --outage-seconds) exactly as the code is read. Did the
 *             attendance reach the database, and when did the student see it?
 *
 * The camera is a canvas stream showing the code the projector would show
 * right now (it rotates every 12s and expires on the server's real window),
 * blank for the first 1.5s as the student lifts the phone and aims. GPS is
 * Playwright's geolocation, inside the classroom with a 15m fix.
 *
 * Prints one JSON object per run.
 */
'use strict';

const { chromium } = require('playwright');
const fs = require('fs');

function arg(name, fallback) {
    const index = process.argv.indexOf(`--${name}`);
    return index > -1 ? process.argv[index + 1] : fallback;
}

const BASE = arg('base');
const CONTROL = arg('control');
const CDN_PROXY = arg('cdn-proxy');
const PROJECTOR = arg('projector');
const SEED = JSON.parse(fs.readFileSync(arg('seed'), 'utf8'));
const PROFILE = arg('profile', '3g');
const RUNS = Number(arg('runs', 3));
const SCENARIO = arg('scenario', 'journey');
const LABEL = arg('label', '');
const FIRST_STUDENT = Number(arg('first-student', 0));
const OUTAGE = arg('outage', 'drop');
const OUTAGE_SECONDS = Number(arg('outage-seconds', 15));
const AIM_DELAY_MS = Number(arg('aim-ms', 1500));
const GPS_ACCURACY = Number(arg('gps-accuracy', 15));
const GPS_OFFSET_M = Number(arg('gps-offset-m', 20));
const GPS_FIRST_FIX_MS = Number(arg('gps-first-fix-ms', 1000));

const PROFILES = {
    // Rough shapes, not carrier measurements: a decent 3G cell, and a loaded
    // EDGE/2G cell in a full lecture hall.
    fast: { rtt: 0, down: 200000, up: 200000 },
    '4g': { rtt: 120, down: 6000, up: 2000 },
    '3g': { rtt: 300, down: 1600, up: 750 },
    '2g': { rtt: 800, down: 250, up: 100 },
};

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function control(path) {
    const response = await fetch(CONTROL + path);
    return response.json();
}

async function setProfile(name) {
    const p = PROFILES[name];
    return control(`/set?rtt=${p.rtt}&down=${p.down}&up=${p.up}&stall=0&drop=0`);
}

async function quietNetwork(maxMs) {
    // Wait until nothing has moved on the link for 2s: the service worker's
    // install-time precache has finished, as it would have long before a
    // returning student's next lecture.
    const started = Date.now();
    let last = -1;
    let stableSince = Date.now();
    while (Date.now() - started < maxMs) {
        const stats = await control('/stats');
        const moved = stats.down_bytes + stats.up_bytes;
        if (moved !== last) {
            last = moved;
            stableSince = Date.now();
        } else if (Date.now() - stableSince > 2000) {
            return;
        }
        await sleep(250);
    }
}

function fakeCamera(aimDelayMs) {
    // Runs in the page. Replaces the camera with a canvas showing the code.
    const original = navigator.mediaDevices && navigator.mediaDevices.getUserMedia;
    if (!original) return;
    navigator.mediaDevices.getUserMedia = async function () {
        const canvas = document.createElement('canvas');
        canvas.width = 640;
        canvas.height = 480;
        const context = canvas.getContext('2d');
        const started = performance.now();
        let image = null;
        let current = '';
        async function refresh() {
            try {
                const frame = await window.__harnessFrame();
                if (frame.png !== current) {
                    current = frame.png;
                    const next = new Image();
                    next.onload = () => { image = next; };
                    next.src = frame.png;
                }
            } catch (_) { /* page navigating */ }
        }
        refresh();
        const refresher = setInterval(refresh, 1000);
        const painter = setInterval(() => {
            context.fillStyle = '#ffffff';
            context.fillRect(0, 0, 640, 480);
            if (image && performance.now() - started > aimDelayMs) {
                context.drawImage(image, 170, 90, 300, 300);
            }
            // A changing pixel, so the stream always has a new frame.
            context.fillStyle = (Math.floor(performance.now() / 33) % 2) ? '#fefefe' : '#ffffff';
            context.fillRect(0, 0, 1, 1);
        }, 33);
        const stream = canvas.captureStream(30);
        const track = stream.getVideoTracks()[0];
        const stop = track.stop.bind(track);
        track.stop = () => { clearInterval(refresher); clearInterval(painter); stop(); };
        return stream;
    };
}

function fakeGeolocation(firstFixMs) {
    // Runs in the page. A phone's GPS as the page sees it: a first fix
    // firstFixMs after the page started, then one a second, each stamped
    // now. The position comes from the harness, so a scenario can drift it.
    // (Playwright's own emulation keeps the timestamp the position was set
    // with, so it ages like a phone that cannot get a new reading, and
    // refreshing it stalls while a page navigates.)
    const watchers = new Map();
    let nextId = 1;
    const born = Date.now();
    function toPosition(p) {
        return {
            coords: { latitude: p.latitude, longitude: p.longitude, accuracy: p.accuracy,
                      altitude: null, altitudeAccuracy: null, heading: null, speed: null },
            timestamp: Date.now(),
        };
    }
    async function deliver(ok, fail) {
        let p;
        try { p = await window.__harnessPosition(); } catch (_) { return; }
        if (p.error) { if (fail) fail({ code: p.error, message: 'harness' }); return; }
        ok(toPosition(p));
    }
    const firstDelay = () => Math.max(50, firstFixMs - (Date.now() - born));
    const geolocation = {
        getCurrentPosition(ok, fail) { setTimeout(() => deliver(ok, fail), firstDelay()); },
        watchPosition(ok, fail) {
            const id = nextId++;
            const timer = { interval: null };
            watchers.set(id, timer);
            setTimeout(() => {
                if (!watchers.has(id)) return;
                deliver(ok, fail);
                timer.interval = setInterval(() => deliver(ok, fail), 1000);
            }, firstDelay());
            return id;
        },
        clearWatch(id) {
            const timer = watchers.get(id);
            if (timer) clearInterval(timer.interval);
            watchers.delete(id);
        },
    };
    Object.defineProperty(navigator, 'geolocation', { value: geolocation, configurable: true });
}

let positionScenario = () => studentPosition();

if (SCENARIO === 'wander') {
    // Indoors the watch wanders: a good reading, then a poor one that has
    // drifted outside the fence, then a good one again. The student never
    // moved; the centre of the hall is 25m away.
    positionScenario = () => {
        const good = Math.floor(Date.now() / 1000) % 2 === 0;
        const offset = good ? 25 : 125;
        return {
            latitude: SEED.room.lat + offset / 111320,
            longitude: SEED.room.lon,
            accuracy: good ? 12 : 60,
        };
    };
}

function studentPosition() {
    // GPS_OFFSET_M north of the classroom pin.
    return {
        latitude: SEED.room.lat + GPS_OFFSET_M / 111320,
        longitude: SEED.room.lon,
        accuracy: GPS_ACCURACY,
    };
}

async function newContext(browser) {
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        permissions: ['camera'],
        viewport: { width: 412, height: 860 },
        userAgent: 'Mozilla/5.0 (Linux; Android 11; Infinix X657) AppleWebKit/537.36 ' +
            '(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36',
    });
    await context.exposeBinding('__harnessFrame', async () => {
        const response = await fetch(`${PROJECTOR}/frame?session=${SEED.session_id}`);
        return response.json();
    });
    await context.exposeBinding('__harnessPosition', async () => positionScenario());
    await context.addInitScript(fakeCamera, AIM_DELAY_MS);
    await context.addInitScript(fakeGeolocation, GPS_FIRST_FIX_MS);
    if (process.env.JOURNEY_DEBUG) {
        context.on('page', page => {
            page.on('console', message => console.error('[page]', message.text()));
            page.on('pageerror', error => console.error('[pageerror]', error.message));
        });
    }
    return context;
}

async function login(context, email) {
    const page = await context.request.get(`${BASE}/login`);
    const html = await page.text();
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)[1];
    const response = await context.request.post(`${BASE}/login`, {
        form: { csrf_token: csrf, email, password: SEED.password },
        headers: { Referer: `${BASE}/login`, Accept: 'application/json' },
    });
    const body = await response.json().catch(() => ({}));
    if (body.outcome !== 'success') throw new Error(`login failed for ${email}: ${JSON.stringify(body)}`);
}

async function timedLoad(page, url) {
    const before = await control('/stats');
    const started = Date.now();
    await page.goto(url, { waitUntil: 'load', timeout: 240000 });
    const elapsed = Date.now() - started;
    const after = await control('/stats');
    const paint = await page.evaluate(() => {
        const entry = performance.getEntriesByName('first-contentful-paint')[0];
        return entry ? Math.round(entry.startTime) : null;
    });
    return {
        load_ms: elapsed,
        fcp_ms: paint,
        bytes: (after.down_bytes - before.down_bytes) + (after.up_bytes - before.up_bytes),
        app_connections: after.connections_opened.app - before.connections_opened.app,
        cdn_connections: after.connections_opened.proxy - before.connections_opened.proxy,
    };
}

async function waitForServiceWorker(page) {
    try {
        await page.evaluate(() => Promise.race([
            navigator.serviceWorker ? navigator.serviceWorker.ready.then(() => true) : false,
            new Promise(resolve => setTimeout(() => resolve(false), 120000)),
        ]));
    } catch (_) { /* navigation */ }
}

/** Tap scan, follow whatever the page does, until a confirmation shows. */
async function scanUntilConfirmed(page, timeoutMs, onScannerOpen) {
    const started = Date.now();
    const seen = [];
    let clickedStart = false;
    let opened = false;
    await page.click('#scanBtn');
    let lastStatus = '';
    while (Date.now() - started < timeoutMs) {
        try {
            if (process.env.JOURNEY_DEBUG) {
                const badge = await page.locator('#status-badge').textContent().catch(() => '');
                if (badge && badge !== lastStatus) {
                    lastStatus = badge;
                    console.error(`[status +${Date.now() - started}ms]`, badge.trim());
                }
            }
            if (!opened && await page.locator('#scanner-container').isVisible()) {
                opened = true;
                if (onScannerOpen) await onScannerOpen();
            }
            const banner = page.locator('#result-banner');
            if (await banner.isVisible()) {
                const text = (await banner.textContent()).trim();
                const success = await banner.evaluate(el => el.classList.contains('alert-success'));
                if (!seen.includes(text)) seen.push(text);
                if (success) {
                    return { confirmed: true, scan_ms: Date.now() - started,
                             confirmed_at: Date.now(), messages: seen };
                }
            }
            if (!clickedStart && page.url().includes('/scan_page')) {
                const start = page.locator('button:has-text("Start Advanced Scanner")').first();
                if (await start.isVisible()) {
                    await start.click();
                    clickedStart = true;
                }
            }
        } catch (_) { /* mid-navigation */ }
        await sleep(50);
    }
    return { confirmed: false, scan_ms: null, messages: seen };
}

async function journeyRun(browser, email) {
    const context = await newContext(browser);
    await setProfile('fast');
    await login(context, email);
    const page = await context.newPage();

    await setProfile(PROFILE);
    await control('/reset');
    const cold = await timedLoad(page, `${BASE}/student_dashboard`);

    await waitForServiceWorker(page);
    await quietNetwork(180000);

    await control('/reset');
    const warm = await timedLoad(page, `${BASE}/student_dashboard`);
    await quietNetwork(60000);

    // The student sat through the start of the lecture: idle connections
    // have long been reaped by the time the code goes up.
    await control('/reset');
    const before = await control('/stats');
    const scan = await scanUntilConfirmed(page, 180000);
    const after = await control('/stats');
    await context.close();
    return {
        cold, warm, scan,
        scan_bytes: (after.down_bytes - before.down_bytes) + (after.up_bytes - before.up_bytes),
        scan_app_connections: after.connections_opened.app - before.connections_opened.app,
    };
}

async function outageRun(browser, email) {
    const context = await newContext(browser);
    await setProfile('fast');
    await login(context, email);
    const page = await context.newPage();
    await setProfile(PROFILE);
    await page.goto(`${BASE}/student_dashboard`, { waitUntil: 'load', timeout: 240000 });
    await waitForServiceWorker(page);
    await quietNetwork(180000);
    await page.goto(`${BASE}/student_dashboard`, { waitUntil: 'load', timeout: 240000 });
    await quietNetwork(60000);
    await control('/reset');

    let outageStarted = 0;
    let restoredAt = 0;
    let abandoned = false;
    const restore = (async () => {
        while (!outageStarted && !abandoned) await sleep(50);
        if (abandoned) return;
        await sleep(OUTAGE_SECONDS * 1000);
        await setProfile(PROFILE);
        restoredAt = Date.now();
    })();
    const result = await scanUntilConfirmed(page, OUTAGE_SECONDS * 1000 + 150000, async () => {
        // The camera is up; the code appears AIM_DELAY_MS later. Lose the
        // network now, so the scan is read and submitted into the outage.
        await control(OUTAGE === 'stall' ? '/set?stall=1' : '/set?drop=1');
        outageStarted = Date.now();
    });
    abandoned = true;
    await restore;
    await setProfile(PROFILE);
    await context.close();
    return { outage: OUTAGE, outage_seconds: OUTAGE_SECONDS, ...result,
             confirmed_during_outage: Boolean(result.confirmed && restoredAt === 0),
             confirmed_after_restore_ms: result.confirmed && restoredAt
                 ? result.confirmed_at - restoredAt : null };
}

(async () => {
    const browser = await chromium.launch({
        proxy: { server: CDN_PROXY, bypass: '127.0.0.1,localhost' },
        args: ['--disable-features=OptimizationHints', '--no-first-run'],
    });
    for (let run = 0; run < RUNS; run++) {
        const email = SEED.students[FIRST_STUDENT + run];
        let result;
        try {
            result = SCENARIO === 'outage'
                ? await outageRun(browser, email)
                : await journeyRun(browser, email);   // 'journey' and 'wander'
        } catch (error) {
            result = { error: String(error && error.stack || error) };
        }
        console.log(JSON.stringify({ label: LABEL, profile: PROFILE, scenario: SCENARIO,
                                     run, email, ...result }));
    }
    await browser.close();
})();
