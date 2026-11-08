// Unit tests for the shared location logic (static/attendance-common.js),
// run with `node --test test_location_browser.cjs` — no browser, no network.
//
// Each test reproduces one way a real phone's Geolocation API misbehaves —
// a wrong clock, a broken timestamp, approximate-only permission, a watch
// that dies after a denial — with a scripted fake, and holds the behaviour
// that keeps a student in the room from being refused for it.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const common = require('./static/attendance-common.js');

const IPHONE_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) ' +
    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
const IPHONE_CHROME = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) ' +
    'AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1';
const ANDROID_CHROME = 'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';
const ANDROID_SAMSUNG = 'Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/** A scriptable navigator.geolocation that records what it was asked. */
function fakeGeolocation() {
    const fake = {
        watches: [],          // { success, failure, options, cleared }
        requests: [],         // { success, failure, options }
        onWatch: null,
        onRequest: null,
        watchPosition(success, failure, options) {
            const watch = { success, failure, options, cleared: false };
            fake.watches.push(watch);
            if (fake.onWatch) fake.onWatch(watch, fake.watches.length - 1);
            return fake.watches.length;
        },
        clearWatch(id) {
            if (fake.watches[id - 1]) fake.watches[id - 1].cleared = true;
        },
        getCurrentPosition(success, failure, options) {
            const request = { success, failure, options };
            fake.requests.push(request);
            if (fake.onRequest) fake.onRequest(request, fake.requests.length - 1);
        },
        get live() { return fake.watches.filter(watch => !watch.cleared); },
    };
    return fake;
}

const reading = (accuracy, timestamp, lat = 7.22, lon = 3.44) => ({
    coords: { latitude: lat, longitude: lon, accuracy },
    timestamp,
});

function locatorFor(geolocation, extra) {
    return common.createLocator(Object.assign({
        geolocation, maxLocationAccuracyM: 100, maxLocationAgeMs: 30000,
        retryHint: 'scan again',
    }, extra || {}));
}

// ---- Freshness -------------------------------------------------------------

test('a phone whose clock runs fast is not refused as stale for ever', async () => {
    // Android stamps fixes with GPS time, not the phone's clock. Two minutes
    // fast, every live fix looked two minutes old.
    const SKEW = 120000;
    const geo = fakeGeolocation();
    geo.onWatch = async watch => {
        watch.success(reading(15, Date.now() - SKEW));
        await sleep(300);
        watch.success(reading(12, Date.now() - SKEW));
    };
    const locator = locatorFor(geo, { budgetMs: 3000 });
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 12);
    const { location_age_ms: age } = locator.payload(position);
    assert.ok(age < 2000, `reported ${age}ms old`);
    locator.stopWatching();
});

test('a cached fix is still stale on a phone with a fast clock', async () => {
    const SKEW = 120000;
    const geo = fakeGeolocation();
    geo.onWatch = async watch => {
        // Android's last-known location, five minutes older than the stream.
        watch.success(reading(5, Date.now() - SKEW - 300000, 7.30, 3.50));
        await sleep(50);
        watch.success(reading(40, Date.now() - SKEW));
        await sleep(300);
        watch.success(reading(30, Date.now() - SKEW));
    };
    const locator = locatorFor(geo, { budgetMs: 3000, settleMs: 0 });
    const position = await locator.acquire(0);
    // Not the ±5m cached one, however precise it claims to be.
    assert.equal(position.coords.accuracy, 30);
    locator.stopWatching();
});

test("a cached last-known fix is never sent as a fresh one", async () => {
    const geo = fakeGeolocation();
    geo.onWatch = async watch => {
        watch.success(reading(8, Date.now() - 5 * 60 * 1000, 7.40, 3.60));
        await sleep(200);
        watch.success(reading(20, Date.now()));
    };
    const locator = locatorFor(geo, { budgetMs: 3000 });
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 20);
    locator.stopWatching();
});

test('microsecond and GPS-rollover timestamps do not make a fix unusable', async () => {
    for (const stamp of [Date.now() * 1000, Date.now() - 1024 * 7 * 86400 * 1000]) {
        const geo = fakeGeolocation();
        geo.onWatch = watch => watch.success(reading(10, stamp));
        const locator = locatorFor(geo, { budgetMs: 1000 });
        const position = await locator.acquire(0);
        assert.ok(locator.payload(position).location_age_ms < 1000, String(stamp));
        locator.stopWatching();
    }
});

test('age is measured from arrival, so a phone clock in the past does not freeze it', async () => {
    // Clock two minutes SLOW: the stamp is "in the future" and Date.now() -
    // timestamp stays negative (floored to 0) for two minutes — a cached fix
    // looked brand new the whole time.
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(10, Date.now() + 120000));
    const locator = locatorFor(geo, { budgetMs: 1000 });
    const position = await locator.acquire(0);
    await sleep(250);
    const age = locator.payload(position).location_age_ms;
    assert.ok(age >= 200 && age < 1000, `age ${age}`);
    locator.stopWatching();
});

test('when nothing in hand is fresh, a new reading is asked for at once', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(10, Date.now()));
    // A 400ms server limit puts the page's own limit at 200ms.
    const locator = locatorFor(geo, { maxLocationAgeMs: 400, budgetMs: 4000 });
    await locator.acquire(0);
    await sleep(300);                       // the phone lies still; iOS goes quiet
    geo.onRequest = request => setTimeout(() => request.success(reading(9, Date.now())), 20);
    const started = Date.now();
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 9);
    assert.equal(geo.requests[0].options.maximumAge, 0);
    assert.ok(Date.now() - started < 500, 'waited for half the budget first');
    locator.stopWatching();
});

// ---- Choosing a fix --------------------------------------------------------

test('glitches are waited past, not posted', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = async watch => {
        watch.success(reading(5, Date.now(), 0, 0));          // null island
        watch.success(reading(NaN, Date.now()));
        watch.success(reading(null, Date.now()));
        watch.success(reading(5, Date.now(), NaN, 3.44));
        await sleep(100);
        watch.success(reading(18, Date.now()));
    };
    const locator = locatorFor(geo, { budgetMs: 2000 });
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 18);
    assert.equal(position.coords.latitude, 7.22);
    locator.stopWatching();
});

test('a vague first fix waits briefly for the sharper one behind it', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = async watch => {
        watch.success(reading(85, Date.now()));     // network fix, accepted but drift-prone
        await sleep(300);
        watch.success(reading(9, Date.now()));      // GPS lands
    };
    const locator = locatorFor(geo, { budgetMs: 4000, settleMs: 1500 });
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 9);
    locator.stopWatching();
});

test('but not for long: a usable fix goes once the wait is up', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(85, Date.now()));
    const locator = locatorFor(geo, { budgetMs: 4000, settleMs: 300 });
    const started = Date.now();
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 85);
    assert.ok(Date.now() - started < 1200);
    locator.stopWatching();
});

test('a precise fix goes at once', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(14, Date.now()));
    const locator = locatorFor(geo, { settleMs: 5000 });
    const started = Date.now();
    await locator.acquire(0);
    assert.ok(Date.now() - started < 100);
    locator.stopWatching();
});

test('after a refusal, the same reading coming back from a cache is not "newer"', async () => {
    const geo = fakeGeolocation();
    const first = reading(30, Date.now());
    geo.onWatch = watch => watch.success(first);
    const locator = locatorFor(geo, { budgetMs: 3000, settleMs: 0 });
    const refused = await locator.acquire(0);
    // getCurrentPosition answers from its cache: an equal copy of the same fix.
    geo.onRequest = request => {
        request.success(reading(30, first.timestamp));
        setTimeout(() => geo.live[0].success(reading(25, Date.now(), 7.2201)), 150);
    };
    const next = await locator.acquire(locator.fixId(refused));
    assert.equal(next.coords.accuracy, 25);
    locator.stopWatching();
});

// ---- Precision the server will refuse --------------------------------------

test('an approximate-only location is explained quickly, not posted', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(2400, Date.now()));
    const locator = locatorFor(geo, { userAgent: IPHONE_SAFARI, approximateAfterMs: 200,
                                      budgetMs: 10000 });
    const started = Date.now();
    await assert.rejects(locator.acquire(0), error => {
        assert.equal(error.locationProblem, true);
        assert.equal(error.code, 'approximate');
        assert.match(error.message, /approximate location \(±2\.4km\)/);
        assert.match(error.message, /Safari Websites › Precise Location/);
        return true;
    });
    assert.ok(Date.now() - started < 1500, 'kept the student for the whole budget');
    locator.stopWatching();
});

test('on Android the approximate message names the browser and the switch', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(3000, Date.now()));
    const locator = locatorFor(geo, { userAgent: ANDROID_SAMSUNG, approximateAfterMs: 100 });
    await assert.rejects(locator.acquire(0),
                         /Use precise location” for Samsung Internet/);
    locator.stopWatching();
});

test('too vague at the end of the budget is explained, not posted to be refused', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => watch.success(reading(160, Date.now()));
    const locator = locatorFor(geo, { budgetMs: 400 });
    await assert.rejects(locator.acquire(0), error => {
        assert.equal(error.code, 'imprecise');
        assert.match(error.message, /±160m right now; it needs to be within ±100m/);
        assert.match(error.message, /Wi-Fi/);
        return true;
    });
    locator.stopWatching();
});

// ---- Permission ------------------------------------------------------------

test('a denial is reported at once, and the page is told while the student aims', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = watch => setTimeout(() => watch.failure({ code: 1 }), 5);
    let told = 0;
    const locator = locatorFor(geo, { userAgent: ANDROID_CHROME, onDenied: () => { told += 1; } });
    locator.startWatching();
    await sleep(30);
    assert.equal(told, 1);
    await assert.rejects(locator.acquire(0), error => {
        assert.equal(error.code, 1);
        assert.match(error.message, /Permissions › Location › Allow/);
        return true;
    });
    locator.stopWatching();
});

test('allowing location after a denial works without reloading the page', async () => {
    const geo = fakeGeolocation();
    let allowed = false;
    geo.onWatch = watch => setTimeout(() => (allowed
        ? watch.success(reading(12, Date.now()))
        : watch.failure({ code: 1 })), 5);
    const locator = locatorFor(geo);
    await assert.rejects(locator.acquire(0), error => error.code === 1);
    assert.equal(geo.live.length, 0, 'the dead watch was kept');

    allowed = true;                          // the student changed the setting
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 12);
    assert.equal(geo.watches.length, 2);
    locator.stopWatching();
});

test('a timeout while a watch keeps going is not a denial', async () => {
    const geo = fakeGeolocation();
    geo.onWatch = async watch => {
        watch.failure({ code: 3 });
        await sleep(100);
        watch.success(reading(20, Date.now()));
    };
    const locator = locatorFor(geo, { budgetMs: 2000 });
    const position = await locator.acquire(0);
    assert.equal(position.coords.accuracy, 20);
    locator.stopWatching();
});

test('denial messages name the switch on each kind of phone', () => {
    const say = ua => common.createLocator({ geolocation: fakeGeolocation(), userAgent: ua,
                                             retryHint: 'scan again' }).describeError({ code: 1 });
    assert.match(say(IPHONE_SAFARI), /Location Services.*Safari Websites.*aA › Website Settings/);
    assert.match(say(IPHONE_CHROME), /set Chrome to “While Using the App”/);
    assert.doesNotMatch(say(IPHONE_CHROME), /aA/);
    assert.match(say(ANDROID_CHROME), /icon left of the web address/);
    assert.match(say(''), /permission is off for this site.*then scan again/);
    for (const ua of [IPHONE_SAFARI, IPHONE_CHROME, ANDROID_CHROME, '']) {
        assert.match(say(ua), /scan again\.$/, ua);
    }
});

test('the platform is read from the user agent, including iPadOS posing as a Mac', () => {
    assert.deepEqual(common.platformOf(IPHONE_SAFARI),
                     { ios: true, android: false, browser: 'Safari' });
    assert.equal(common.platformOf(IPHONE_CHROME).browser, 'Chrome');
    assert.equal(common.platformOf(ANDROID_SAMSUNG).browser, 'Samsung Internet');
    assert.equal(common.platformOf(ANDROID_CHROME).android, true);
    const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 ' +
        '(KHTML, like Gecko) Version/18.1 Safari/605.1.15';
    assert.equal(common.platformOf(mac, { platform: 'MacIntel', maxTouchPoints: 5 }).ios, true);
    assert.equal(common.platformOf(mac, { platform: 'MacIntel', maxTouchPoints: 0 }).ios, false);
});

// ---- One GPS session per page ----------------------------------------------

test('the scanner and the code box on one page share a single watch', () => {
    const geo = fakeGeolocation();
    const scanner = locatorFor(geo);
    const codeBox = locatorFor(geo, { retryHint: 'try again' });
    scanner.startWatching();
    codeBox.startWatching();
    assert.equal(geo.watches.length, 1);
    assert.equal(geo.watches[0].options.enableHighAccuracy, true);
    assert.equal(geo.watches[0].options.maximumAge, 0);

    scanner.stopWatching();                  // camera closed; still typing
    assert.equal(geo.live.length, 1);
    codeBox.stopWatching();
    assert.equal(geo.live.length, 0, 'a GPS watch outlived every page that wanted it');
});
