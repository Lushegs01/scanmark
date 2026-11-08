/*
 * The projector's QR refresh in a real browser, against a real server.
 *
 *   python e2e/seed_e2e.py > /tmp/e2e-seed.json        # same env as the server
 *   E2E_BASE=http://127.0.0.1:8100 E2E_SEED=/tmp/e2e-seed.json \
 *       node --test e2e/qr_refresh.e2e.cjs
 *
 * An <img> error cannot tell a class that has ended (the image endpoint's
 * 409) from a Wi-Fi drop or a proxy's 502. These show that the page asks the
 * server before giving up: a blip leaves the QR refreshing, and only a real
 * End Class stops it. Ends the seed's `ending_session_id` class, never the
 * one manual_code.e2e.cjs uses.
 */
'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { chromium } = require('playwright');

const BASE = (process.env.E2E_BASE || 'http://127.0.0.1:8100').replace(/\/$/, '');
const SEED = JSON.parse(fs.readFileSync(process.env.E2E_SEED || '/tmp/e2e-seed.json', 'utf8'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

let browser;

before(async () => {
    browser = await chromium.launch();
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

/** The projector laptop: the lecturer, signed in, on the class's QR page. */
async function projector(sessionId) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    await signIn(context, SEED.lecturer);
    const page = await context.newPage();
    // Every QR image request and how it ended, in order.
    const loads = [];
    page.on('requestfinished', async request => {
        if (!request.url().includes(`/session/${sessionId}/live`)) return;
        const response = await request.response();
        loads.push({ ok: response.status() === 200, status: response.status(), at: Date.now() });
    });
    page.on('requestfailed', request => {
        if (request.url().includes(`/session/${sessionId}/live`)) {
            loads.push({ ok: false, status: 0, at: Date.now() });
        }
    });
    await page.goto(`${BASE}/session/${sessionId}/qr`);
    await qrDrawn(page);
    return { context, page, loads };
}

/** Wait until the QR on screen is a real, decoded image. */
function qrDrawn(page, timeout = 20000) {
    return page.waitForFunction(() => {
        const img = document.getElementById('qrImage');
        return img.complete && img.naturalWidth > 0
            && !document.getElementById('qrStage').classList.contains('is-qr-down');
    }, null, { timeout });
}

async function until(predicate, timeout, what) {
    const deadline = Date.now() + timeout;
    while (!predicate()) {
        if (Date.now() > deadline) assert.fail(`timed out waiting for ${what}`);
        await sleep(100);
    }
}

function text(page, selector) {
    return page.locator(selector).textContent();
}

// ---------------------------------------------------------------------------

test('a dropped connection and a proxy 502 leave the QR refreshing', async () => {
    const sid = SEED.session_id;
    const { context, page, loads } = await projector(sid);
    // Full screen, as in a lecture hall: a blip must not throw it out.
    await page.click('#qrFullscreenBtn');
    await page.locator('#qrStage.is-full').waitFor();

    // 1. The projector's Wi-Fi drops: nothing reaches the server at all,
    //    neither the image nor the page's question about it.
    let mode = 'offline';
    const statusChecks = [];
    await page.route(`**/session/${sid}/live**`, route => {
        if (mode === 'offline') return route.abort('internetdisconnected');
        if (mode === 'proxy') return route.fulfill({ status: 502, contentType: 'text/html',
                                                     body: '<h1>502 Bad Gateway</h1>' });
        return route.continue();
    });
    await page.route(`**/api/qr_data/${sid}`, route => {
        statusChecks.push(mode);
        return mode === 'offline' ? route.abort('internetdisconnected') : route.continue();
    });
    const failedBefore = loads.filter(l => !l.ok).length;
    // The next scheduled refresh (one QR_TOKEN_TTL, 12s by default) fails.
    await page.locator('#qrStage.is-qr-down').waitFor({ timeout: 20000 });
    assert.match(await text(page, '#qrStatus'), /Reconnecting to ScanMark/);
    assert.ok(await page.locator('#qrStatus').isVisible(), 'the message stands in for the QR');
    assert.ok(await page.locator('#qrStage.is-full').count(), 'still full screen');
    assert.equal(await page.locator('#qrCountdown').isVisible(), false, 'no countdown to a missing QR');
    assert.doesNotMatch(await text(page, '#locationStatus'), /ended/);
    assert.equal(await page.locator('#manualCode.is-ended').count(), 0);

    // It keeps trying, further apart each time, while the network is down.
    await until(() => loads.filter(l => !l.ok).length >= failedBefore + 3, 15000, 'two retries');
    const failed = loads.filter(l => !l.ok).slice(failedBefore);
    const firstGap = failed[1].at - failed[0].at;
    const secondGap = failed[2].at - failed[1].at;
    assert.ok(firstGap >= 700, `first retry after ${firstGap}ms`);
    assert.ok(secondGap > firstGap, `backoff grows: ${firstGap}ms then ${secondGap}ms`);
    await until(() => statusChecks.length >= 3, 5000, 'every failure to ask the server');

    // 2. The network is back but a proxy in front of the app answers 502 for
    //    the image. The server, asked directly, says the class is running.
    mode = 'proxy';
    const proxyBefore = loads.length;
    await until(() => loads.slice(proxyBefore).some(l => l.status === 502), 20000, 'a 502');
    await until(() => statusChecks.includes('proxy'), 10000, 'the page to ask the server');
    await sleep(500);
    assert.match(await text(page, '#qrStatus'), /Reconnecting to ScanMark/);
    assert.doesNotMatch(await text(page, '#locationStatus'), /ended/);

    // 3. Everything is back. The next retry restores the QR on its own —
    //    no reload — and the normal refresh carries on from there.
    mode = 'online';
    await qrDrawn(page, 30000);
    assert.ok(await page.locator('#qrStage.is-full').count(), 'still full screen after recovery');
    assert.equal(await page.locator('#qrStatus').isVisible(), false);
    assert.ok(await page.locator('#qrCountdown').isVisible());
    assert.match(await text(page, '#qrCountdown'), /QR code refreshes in \d+s/);
    // The next scheduled refresh draws a new image, as before the blip.
    const shownSrc = await page.locator('#qrImage').getAttribute('src');
    await page.waitForFunction(src => {
        const img = document.getElementById('qrImage');
        return img.getAttribute('src') !== src && img.complete && img.naturalWidth > 0;
    }, shownSrc, { timeout: 20000 });
    assert.equal(await page.locator('#qrStage.is-qr-down').count(), 0);
    assert.doesNotMatch(await text(page, '#locationStatus'), /ended/);
    await context.close();
});

test('a class ended from another device still ends the projector', async () => {
    const sid = SEED.ending_session_id;
    const { context, page, loads } = await projector(sid);
    await page.click('#qrFullscreenBtn');
    await page.locator('#qrStage.is-full').waitFor();

    // The lecturer's phone: its own sign-in, pressing End Class.
    const phone = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await signIn(phone, SEED.lecturer);
    const phonePage = await phone.newPage();
    await phonePage.goto(`${BASE}/session/${sid}/qr`);
    phonePage.once('dialog', dialog => dialog.accept());
    await phonePage.click('button:has-text("End Class")');
    await phonePage.waitForURL(/\/course\/\d+\/attendance/);
    await phone.close();
    const ended = await context.request.get(`${BASE}/api/qr_data/${sid}`);
    assert.equal(ended.status(), 409);

    // The projector finds out at its next refresh, and says so.
    await page.waitForFunction(() => /This class has ended/.test(
        document.getElementById('locationStatus').textContent), null, { timeout: 25000 });
    assert.match(await text(page, '#qrStatus'), /This class has ended/);
    assert.ok(await page.locator('#qrStatus').isVisible());
    assert.equal(await page.locator('#qrImage').isVisible(), false);
    assert.equal(await page.locator('#qrStage.is-full').count(), 0, 'out of full screen');
    if (await page.locator('#manualCode').count()) {
        await page.locator('#manualCode.is-ended').waitFor({ timeout: 5000 });
    }
    // And stops asking: no more images for a class that is over.
    const after = loads.length;
    await sleep(15000);
    assert.equal(loads.length, after, 'no QR requests after the class ended');
    await context.close();
});
