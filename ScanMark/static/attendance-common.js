/*
 * What the QR scanner (scanner.js) and the manual attendance code
 * (manual-code.js) have in common, so the two ways of marking attendance
 * cannot drift apart on the parts that are the same:
 *
 *   - getting a location fix the server will accept (createLocator)
 *   - the per-installation device label (deviceId)
 *   - honouring the server's Retry-After (serverRetryDelay)
 *   - bumping the on-page counts after a confirmed record (bumpAttendance)
 *
 * Nothing here touches the camera: the manual path must work on a phone
 * whose camera is broken, blocked or absent.
 *
 * Plain script, no build step, like the rest of static/. In a browser it
 * defines window.ScanMarkAttendance; under Node (the unit tests) it exports
 * the same object.
 */
(function (root) {
    'use strict';

    // A stable per-installation identifier, so "this attendance came from the
    // same phone as that one" is answerable. NOT a credential: it is
    // client-generated, client-stored and trivially forged; the server treats
    // it as a diagnostic label and nothing else. Who marked attendance comes
    // from the signed-in session, never from anything the page sends.
    const DEVICE_ID_KEY = 'scanmark_device_id';

    function deviceId() {
        try {
            let stored = localStorage.getItem(DEVICE_ID_KEY);
            if (!stored) {
                stored = (crypto.randomUUID && crypto.randomUUID()) ||
                    // Older WebViews have getRandomValues without randomUUID.
                    Array.from(crypto.getRandomValues(new Uint8Array(16)))
                        .map(b => b.toString(16).padStart(2, '0')).join('');
                localStorage.setItem(DEVICE_ID_KEY, stored);
            }
            return stored;
        } catch (_) {
            // Private mode, or storage disabled. Say so rather than inventing
            // a fresh id per submission, which would look like many devices.
            return 'unavailable';
        }
    }

    /**
     * How long the server says to wait, in ms, or null if it did not say.
     *
     * ScanMark sends Retry-After exactly when it is shedding on purpose
     * (admission control, a saturated database, a locked-out code entry).
     * The server knows how long its own queue needs to drain; a client
     * guessing instead is wrong in both directions.
     *
     * Clamped, because the header is still input: a bad or hostile value
     * must not park the page for an hour or turn the backoff into a tight
     * loop. `capSeconds` lets a caller that DISPLAYS a lockout (rather than
     * retrying through it) keep the server's full number.
     */
    function serverRetryDelay(response, capSeconds, random) {
        const header = response && response.headers
            ? response.headers.get('Retry-After') : null;
        if (!header) return null;
        const seconds = Number(header);
        if (!Number.isFinite(seconds) || seconds < 0) return null;
        const clamped = Math.min(capSeconds || 30, seconds) * 1000;
        // Jitter even the server's number. Every phone in the room was shed
        // by the same response and would otherwise come back in the same
        // millisecond.
        const jitter = 0.75 + (random || Math.random)() * 0.5;
        return Math.max(250, Math.floor(clamped * jitter));
    }

    /**
     * Show the new count straight away instead of reloading the page for it.
     * Rows carry their numbers as data attributes; anything else is left as
     * the server rendered it.
     */
    function bumpAttendance(courseCode) {
        if (!courseCode || typeof document === 'undefined') return;
        document.querySelectorAll('[data-attended-for]').forEach(cell => {
            if (cell.getAttribute('data-attended-for') !== courseCode) return;
            const attended = Number(cell.getAttribute('data-attended')) + 1;
            const total = Number(cell.getAttribute('data-total')) || 0;
            cell.setAttribute('data-attended', String(attended));
            cell.textContent = total ? `${attended} / ${total}` : String(attended);
            const row = cell.closest('tr');
            const badge = row && row.querySelector('[data-pct-badge]');
            if (badge && total) {
                const pct = Math.min(100, Math.round(attended / total * 100));
                const onTrack = pct >= (Number(badge.getAttribute('data-threshold')) || 0);
                badge.textContent = `${pct}% · ${onTrack ? 'On Track' : 'At Risk'}`;
                const pill = badge.parentElement;
                if (pill) {
                    pill.classList.toggle('bg-danger', !onTrack);
                    pill.style.background = onTrack ? 'rgba(0,90,43,0.12)' : '';
                    pill.style.color = onTrack ? 'var(--green)' : '';
                }
            }
        });
        const totalAttended = document.querySelector('[data-total-attended]');
        if (totalAttended) {
            totalAttended.textContent = String(Number(totalAttended.textContent) + 1);
        }
    }

    // ---- Location ----------------------------------------------------------

    // A fix whose stamp is further than this from the phone's clock, either
    // way, is not a cached reading or a slightly wrong clock: it is a broken
    // stamp. Seen in the wild: microseconds instead of milliseconds (older
    // Firefox for Android), and fixes dated ~19.6 years ago by GPS chipsets
    // that mishandled the 2019 week-number rollover.
    const IMPLAUSIBLE_STAMP_MS = 24 * 60 * 60 * 1000;
    // Two consecutive readings whose stamps advance in step with when they
    // actually arrived (within this) are a live stream, not cached answers.
    const LIVE_PAIR_TOLERANCE_MS = 1500;
    // A live stream that still looks this old on arrival is the phone's
    // clock disagreeing with the fix's clock, not a stale fix. Below it, the
    // difference is ordinary delivery latency and is left alone.
    const MIN_CLOCK_SKEW_MS = 3000;

    /**
     * What sort of phone and browser this is, so a message can name the
     * actual switch to flip. A guess from the user agent and nothing more:
     * it only chooses wording, never what is allowed.
     */
    function platformOf(userAgent, nav) {
        const ua = String(userAgent || '');
        const iPadOS = Boolean(nav && nav.platform === 'MacIntel' && nav.maxTouchPoints > 1);
        const ios = /iPhone|iPad|iPod/.test(ua) || iPadOS;
        const android = /Android/i.test(ua);
        let browser = 'browser';
        if (/CriOS/.test(ua)) browser = 'Chrome';
        else if (/FxiOS/.test(ua)) browser = 'Firefox';
        else if (/EdgiOS|EdgA\//.test(ua)) browser = 'Edge';
        else if (/SamsungBrowser/.test(ua)) browser = 'Samsung Internet';
        else if (/OPiOS|OPR\//.test(ua)) browser = 'Opera';
        else if (/Firefox\//.test(ua)) browser = 'Firefox';
        else if (/Chrome\//.test(ua)) browser = 'Chrome';
        else if (ios) browser = 'Safari';
        return { ios, android, browser };
    }

    function sameReading(a, b) {
        return a.timestamp === b.timestamp
            && a.coords.latitude === b.coords.latitude
            && a.coords.longitude === b.coords.longitude
            && a.coords.accuracy === b.coords.accuracy;
    }

    /**
     * A reading the server could judge at all. Anything else is a glitch to
     * wait past, not a fix to post and be refused for.
     */
    function plausibleReading(position) {
        const coords = position && position.coords;
        if (!coords) return false;
        const { latitude, longitude, accuracy } = coords;
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)
            || Math.abs(latitude) > 90 || Math.abs(longitude) > 180) return false;
        // "Null island": what some Android GPS stacks report for a moment
        // before they have a fix. Nobody is taking a class there.
        if (latitude === 0 && longitude === 0) return false;
        // The server refuses a fix with no accuracy, so it is no use here
        // either (some WebViews report null while the provider warms up).
        return Number.isFinite(accuracy) && accuracy >= 0;
    }

    /**
     * Everything the phone has told us about where it is, shared by every
     * locator on the page.
     *
     * The student dashboard has both the scanner and the code box, and each
     * used to run its own high-accuracy watch: two GPS sessions, double the
     * battery, and on some browsers a second permission prompt. One watch
     * now runs while ANY of them wants it.
     */
    const sources = new Map();

    function sourceFor(geolocation, environment) {
        let source = sources.get(geolocation);
        if (!source) {
            source = createSource(geolocation, environment);
            sources.set(geolocation, source);
        }
        return source;
    }

    function createSource(geolocation, environment) {
        const env = environment || {};
        const fixes = [];
        const meta = new WeakMap();
        const consumers = new Set();
        let waiters = [];
        let watchId = null;
        let watchStartedAt = 0;
        let lastFixAt = 0;
        let lastError = null;
        let denied = false;
        let seenFix = false;
        let freshInFlight = false;
        let networkFixTimer = null;
        let watchdogTimer = null;
        let hiddenAt = 0;
        let sequence = 0;
        // The phone's clock minus the fix's clock, once a live stream has
        // shown what it is. See learnSkew.
        let clockSkewMs = 0;

        function wake() {
            const waiting = waiters;
            waiters = [];
            waiting.forEach(resolve => resolve());
        }

        function nextFix(timeoutMs) {
            return new Promise(resolve => {
                waiters.push(resolve);
                setTimeout(resolve, timeoutMs);
            });
        }

        /** The fix's own time, in ms since the epoch, or null if it has none. */
        function stampOf(position) {
            const stamp = Number(position.timestamp);
            if (!Number.isFinite(stamp) || stamp <= 0) return null;
            // Microseconds: a thousand times the present.
            return stamp > Date.now() * 100 ? stamp / 1000 : stamp;
        }

        /**
         * Learn how far the phone's clock is from the fix's.
         *
         * Android stamps a fix with the time the GPS computed it — satellite
         * time, not the phone's clock — and phones set by hand are often
         * minutes out. A phone running two minutes fast saw every fix as two
         * minutes old: refused as stale by this page and by the server, for
         * ever, however long the student stood in the hall. Two readings in a
         * row whose stamps advance exactly as fast as they arrive are being
         * produced live, so whatever "age" they share on arrival is the clock,
         * and is taken off every reading. A cached fix still looks old: its
         * stamp is older than the live ones by however old it really is.
         */
        function learnSkew(entry) {
            if (entry.lag === null) return;
            for (let index = fixes.length - 1; index >= 0; index -= 1) {
                const previous = fixes[index];
                if (previous.lag === null || previous.stamp === entry.stamp) continue;
                const stampStep = entry.stamp - previous.stamp;
                const arrivalStep = entry.perf - previous.perf;
                if (stampStep > 0 && Math.abs(stampStep - arrivalStep) <= LIVE_PAIR_TOLERANCE_MS) {
                    clockSkewMs = Math.min(entry.lag, previous.lag);
                }
                return;
            }
        }

        /**
         * How old a reading is now, in ms.
         *
         * Measured from when it ARRIVED, on a clock nothing can set: the
         * phone's wall clock can be wrong and the fix's stamp can be broken,
         * but the time since the callback ran is just elapsed time. To that is
         * added how old the reading already was when it arrived, from its
         * stamp, once the clock difference above is taken off. Both clocks are
         * consulted for the elapsed part and the larger wins, because iOS
         * pauses performance.now() while Safari is in the background.
         */
        function ageOf(entry) {
            const elapsed = Math.max(0, performance.now() - entry.perf, Date.now() - entry.wall);
            let atArrival;
            if (entry.lag === null) {
                // No usable stamp: trust only what was asked for. A reading
                // requested with maximumAge: 0 is fresh; one that may have
                // come from a cache is assumed to be as old as it was allowed.
                atArrival = entry.assumedAgeMs;
            } else {
                const skew = clockSkewMs >= MIN_CLOCK_SKEW_MS ? clockSkewMs : 0;
                atArrival = Math.max(0, entry.lag - skew);
            }
            return atArrival + elapsed;
        }

        function noteFix(position, assumedAgeMs) {
            if (!plausibleReading(position)) return;
            lastError = null;
            denied = false;
            seenFix = true;
            lastFixAt = performance.now();
            // A cached answer to getCurrentPosition is the reading we already
            // hold, not a second one: counting it as new would let a refused
            // fix come straight back as the "fresh" one.
            if (fixes.some(entry => sameReading(entry.position, position))) {
                wake();
                return;
            }
            const wall = Date.now();
            const stamp = stampOf(position);
            const lag = stamp === null || Math.abs(wall - stamp) > IMPLAUSIBLE_STAMP_MS
                ? null : wall - stamp;
            const entry = {
                position, stamp, lag, wall,
                perf: lastFixAt,
                assumedAgeMs: assumedAgeMs || 0,
                seq: (sequence += 1),
            };
            learnSkew(entry);
            fixes.push(entry);
            meta.set(position, entry);
            while (fixes.length > 30) fixes.shift();
            wake();
        }

        function noteDenied(error) {
            lastError = error || { code: 1 };
            denied = true;
            // The browser has stopped this watch for good. Forgetting it is
            // what lets the next attempt start a new one — after the student
            // has changed the setting — instead of every later attempt failing
            // on the strength of this one until the page is reloaded.
            stopWatch();
            wake();
            consumers.forEach(consumer => {
                if (consumer.onDenied) {
                    try { consumer.onDenied(); } catch (_) { /* the page's problem */ }
                }
            });
        }

        function startWatch() {
            if (!geolocation || watchId !== null) return;
            watchStartedAt = performance.now();
            watchId = geolocation.watchPosition(
                position => noteFix(position, 0),
                // A watch reports errors as they happen and keeps going; only
                // a denial is final.
                error => {
                    if (error && error.code === 1) noteDenied(error);
                    else lastError = error;
                },
                { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
            );
            clearTimeout(networkFixTimer);
            // A high-accuracy watch indoors can go quiet for a long time while
            // it hunts for satellites. The network (Wi-Fi/cell) position
            // answers in about a second and, inside a building with Wi-Fi, is
            // often the more accurate of the two.
            networkFixTimer = setTimeout(() => {
                if (watchId !== null && !seenFix) {
                    request(false, env.positionMaxAgeMs);
                }
            }, env.networkFixAfterMs);
        }

        function stopWatch() {
            clearTimeout(networkFixTimer);
            clearTimeout(watchdogTimer);
            if (watchId !== null && geolocation) geolocation.clearWatch(watchId);
            watchId = null;
        }

        function restartWatch() {
            stopWatch();
            if (consumers.size) startWatch();
        }

        /**
         * One reading, outside the watch. With maximumAge 0 it is the way to
         * get a fresh fix out of a phone whose watch has gone quiet (iOS stops
         * reporting a phone that is not moving) or keeps handing back an old
         * one (Android's last-known location indoors).
         */
        function request(highAccuracy, maximumAge) {
            if (!geolocation) return;
            const age = maximumAge || 0;
            if (age === 0) {
                if (freshInFlight) return;
                freshInFlight = true;
            }
            geolocation.getCurrentPosition(
                position => {
                    if (age === 0) freshInFlight = false;
                    noteFix(position, age);
                },
                error => {
                    if (age === 0) freshInFlight = false;
                    if (error && error.code === 1) noteDenied(error);
                    else if (!seenFix) lastError = error;
                    wake();
                },
                { enableHighAccuracy: highAccuracy !== false, timeout: 10000, maximumAge: age }
            );
        }

        /**
         * Coming back to the page.
         *
         * iOS Safari suspends a watch while the page is hidden and, often,
         * never resumes it: the student flips to WhatsApp for the code, comes
         * back, and no fix ever arrives again. And whatever was read before
         * they left says where they WERE, which after more than a few seconds
         * away is not evidence of where they are.
         */
        function onVisible() {
            if (hiddenAt && performance.now() - hiddenAt > 5000) fixes.length = 0;
            hiddenAt = 0;
            if (watchId === null) return;
            const visibleAt = performance.now();
            clearTimeout(watchdogTimer);
            watchdogTimer = setTimeout(() => {
                if (watchId !== null && lastFixAt < visibleAt) restartWatch();
            }, 3000);
        }

        let listening = false;
        function listen() {
            if (listening) return;
            listening = true;
            const doc = env.document;
            if (doc && doc.addEventListener) {
                doc.addEventListener('visibilitychange', () => {
                    if (doc.visibilityState === 'hidden') hiddenAt = performance.now();
                    else onVisible();
                });
            }
            const win = env.window;
            if (win && win.addEventListener) {
                win.addEventListener('pageshow', event => {
                    if (event && event.persisted) {
                        hiddenAt = hiddenAt || 1;
                        onVisible();
                    }
                });
            }
            // When the student allows location in settings and comes back,
            // start again on our own rather than waiting to be asked.
            const permissions = env.permissions;
            if (permissions && permissions.query) {
                try {
                    permissions.query({ name: 'geolocation' }).then(status => {
                        if (!status) return;
                        const changed = () => {
                            if (status.state === 'granted' && consumers.size
                                    && (denied || watchId === null)) {
                                denied = false;
                                lastError = null;
                                restartWatch();
                            }
                        };
                        if (status.addEventListener) status.addEventListener('change', changed);
                        else status.onchange = changed;
                    }).catch(() => {});
                } catch (_) {
                    // Safari before 16 throws for 'geolocation'.
                }
            }
        }

        return {
            want(consumer) {
                consumers.add(consumer);
                listen();
                if (watchId !== null) return;
                // An earlier denial is not a reason to stop asking: the
                // student may just have changed the setting. A browser that is
                // still blocked answers at once, so this costs nothing.
                if (denied) {
                    denied = false;
                    lastError = null;
                }
                startWatch();
            },
            release(consumer) {
                consumers.delete(consumer);
                if (!consumers.size) stopWatch();
            },
            request,
            nextFix,
            ageOf,
            entryFor: position => meta.get(position) || null,
            fixes: () => fixes,
            get watching() { return watchId !== null; },
            get watchAgeMs() { return watchId === null ? 0 : performance.now() - watchStartedAt; },
            get denied() { return denied; },
            get lastError() { return lastError; },
            get seenFix() { return seenFix; },
            get clockSkewMs() { return clockSkewMs; },
        };
    }

    /**
     * A location fix the server will accept — the same rules for both ways
     * of marking attendance, because the server applies the same geofence to
     * both.
     *
     * options:
     *   maxLocationAgeMs      the server's freshness limit
     *   maxLocationAccuracyM  the server's precision limit
     *   retryHint             how the error messages end ("scan again")
     *   onDenied              called as soon as location is refused, so the
     *                         page can say so before the student does the
     *                         rest of the work
     *   geolocation           injectable for tests (navigator.geolocation)
     *   userAgent             injectable for tests (navigator.userAgent)
     *   budgetMs, settleMs, approximateAfterMs   timings, for tests
     */
    function createLocator(options) {
        const opts = options || {};
        const injected = opts.geolocation !== undefined;
        const nav = typeof navigator !== 'undefined' ? navigator : undefined;
        const geolocation = injected ? opts.geolocation : (nav ? nav.geolocation : undefined);
        const retryHint = opts.retryHint || 'scan again';
        const platform = platformOf(opts.userAgent !== undefined ? opts.userAgent
            : (nav && nav.userAgent), injected ? null : nav);

        // What the SERVER will refuse. Sent by the page; the fallback matches
        // GEOFENCE_MAX_LOCATION_AGE_MS's own default.
        const SERVER_MAX_AGE_MS = Number(opts.maxLocationAgeMs) > 0
            ? Number(opts.maxLocationAgeMs) : 30000;
        // How old a fix may be before we look for a better one. Deliberately
        // tighter than the server's limit — at most half of it, should it
        // ever be set below the usual 30s — so there is room to get a fresh
        // fix and still post inside it.
        const POSITION_MAX_AGE_MS = Math.min(10000, SERVER_MAX_AGE_MS / 2);
        // The worst accuracy the server accepts. Posting a fix it will refuse
        // as imprecise is a wasted round trip and a red banner; waiting a few
        // seconds for the watch to narrow is usually all it takes.
        const MAX_ACCURACY_M = Number(opts.maxLocationAccuracyM) > 0
            ? Number(opts.maxLocationAccuracyM) : 100;
        // Precise enough to go at once. A fix between this and MAX_ACCURACY_M
        // is accepted by the server, but it is the reading most likely to
        // have drifted outside the fence; a watch that has only just started
        // usually has a much better one a second or two away.
        const GOOD_ACCURACY_M = Math.min(MAX_ACCURACY_M, Math.max(20, MAX_ACCURACY_M * 0.35));
        // How long a usable-but-vague fix waits for a better one. Bounded
        // tightly: the scan should feel instant.
        const SETTLE_MS = Number(opts.settleMs) >= 0 && opts.settleMs !== undefined
            ? Number(opts.settleMs) : 2000;
        // A watch that has been running this long has done its narrowing:
        // what it has now is what there is.
        const WATCH_SETTLED_MS = 4000;
        // How long a submission waits for a usable fix in all.
        const LOCATION_BUDGET_MS = Number(opts.budgetMs) > 0 ? Number(opts.budgetMs) : 12000;
        // Worse than this is not a GPS that needs a moment: it is a phone
        // sharing only an approximate location (iOS with Precise Location
        // off, Android's "approximate" permission — both report one to
        // several kilometres) or one with no Wi-Fi or GPS at all. Neither
        // improves by waiting, so the student is told what to change instead
        // of being kept for the whole budget and then refused.
        const APPROXIMATE_M = 1000;
        const APPROXIMATE_AFTER_MS = Number(opts.approximateAfterMs) > 0
            ? Number(opts.approximateAfterMs) : 5000;

        const source = geolocation ? sourceFor(geolocation, {
            document: injected ? null : (typeof document !== 'undefined' ? document : null),
            window: injected ? null : (typeof window !== 'undefined' ? window : null),
            permissions: injected ? opts.permissions : (nav && nav.permissions),
            positionMaxAgeMs: POSITION_MAX_AGE_MS,
            networkFixAfterMs: 3000,
        }) : null;
        const consumer = { onDenied: opts.onDenied };

        /**
         * A problem with the fix itself, not with the network.
         *
         * Retrying it immediately gets the same cached fix, so these are
         * handed back to the student with the reason rather than swallowed by
         * a transient-retry path — which is what used to happen to a GPS
         * permission denial, reported as "Network busy" while the network was
         * fine.
         */
        function locationError(message, code, extra) {
            const error = new Error(message);
            error.locationProblem = true;
            error.code = code;
            Object.assign(error, extra || {});
            return error;
        }

        function appName() {
            return platform.browser === 'Safari' ? 'Safari Websites' : platform.browser;
        }

        function describeLocationError(error) {
            // Different problems with different fixes, and on each phone the
            // switch is somewhere else. "Allow GPS access" told a student
            // whose permission was fine, indoors, to do something they had
            // already done.
            const code = error && error.code;
            if (code === 1) {
                if (platform.ios) {
                    return 'Location is blocked. On your iPhone open Settings › Privacy & ' +
                        `Security › Location Services: turn it on, and set ${appName()} to ` +
                        '“While Using the App” with Precise Location on. ' +
                        (platform.browser === 'Safari'
                            ? 'If this site is still blocked, tap aA › Website Settings › Location › Allow. '
                            : '') +
                        `Then ${retryHint}.`;
                }
                if (platform.android) {
                    return 'Location is blocked for this site. Tap the icon left of the ' +
                        'web address › Permissions › Location › Allow, and check Location ' +
                        `is on in your phone's quick settings. Then ${retryHint}.`;
                }
                return 'Location permission is off for this site. Allow location ' +
                    `(precise) in your browser settings, then ${retryHint}.`;
            }
            if (code === 2) {
                if (platform.ios) {
                    return 'Your iPhone could not work out where it is. Check Settings › ' +
                        'Privacy & Security › Location Services is on, and turn on Wi-Fi ' +
                        `(it helps indoors, even unconnected). Then ${retryHint}.`;
                }
                return 'Your phone could not work out where it is. Turn on Location (GPS) ' +
                    'in your phone settings, and Wi-Fi (it helps indoors, even unconnected), ' +
                    `then ${retryHint}.`;
            }
            return 'Could not get a location fix in time. Turn on Wi-Fi if it is off, ' +
                `step towards a window or doorway for a moment, then ${retryHint}.`;
        }

        function describeImprecise(accuracy) {
            const rounded = Math.round(accuracy);
            if (accuracy > APPROXIMATE_M) {
                const km = Math.round(accuracy / 100) / 10;
                const where = `(±${km}km)`;
                if (platform.ios) {
                    return `Your iPhone is only sharing an approximate location ${where}. ` +
                        'Turn on Precise Location: Settings › Privacy & Security › Location ' +
                        `Services › ${appName()} › Precise Location. Then ${retryHint}.`;
                }
                if (platform.android) {
                    return `Your phone is only sharing an approximate location ${where}. ` +
                        'Turn on “Use precise location” for ' +
                        `${platform.browser === 'browser' ? 'your browser' : platform.browser} ` +
                        '(Settings › Location › App location permissions), and check Wi-Fi is on. ' +
                        `Then ${retryHint}.`;
                }
                return `This device can only place itself to within ${where}. Allow precise ` +
                    `location for this browser and turn on Wi-Fi, then ${retryHint}.`;
            }
            return `Your location is only accurate to ±${rounded}m right now; it needs to ` +
                `be within ±${Math.round(MAX_ACCURACY_M)}m to confirm you are in the classroom. ` +
                'Turn on Wi-Fi (it helps your phone find itself indoors, even unconnected), ' +
                `step towards a window or doorway for a moment, then ${retryHint}.`;
        }

        function imprecise(position) {
            const accuracy = position.coords.accuracy;
            return locationError(describeImprecise(accuracy),
                                 accuracy > APPROXIMATE_M ? 'approximate' : 'imprecise',
                                 { accuracyM: accuracy });
        }

        function positionAge(position) {
            const entry = source && source.entryFor(position);
            if (entry) return source.ageOf(entry);
            // Clock skew between the fix's stamp and now can read negative;
            // the server floors it at zero, so judge it the same way here.
            return Math.max(0, Date.now() - position.timestamp);
        }

        /**
         * The most precise recent fix, not merely the latest.
         *
         * A watch reports a coarse network position first and narrows from
         * there, and indoors it wanders: one reading ±15m, the next ±60m.
         * Taking whichever arrived last meant a submission could carry the
         * worst reading of the last ten seconds — and be told the student
         * was too far away.
         *
         * `newerThan` is a fixId(): only readings that arrived after that
         * one count (after a refusal, the same reading gets the same answer).
         */
        function bestEntry(newerThan) {
            if (!source) return null;
            let best = null;
            for (const entry of source.fixes()) {
                if (newerThan && entry.seq <= newerThan) continue;
                if (source.ageOf(entry) > POSITION_MAX_AGE_MS) continue;
                const accuracy = entry.position.coords.accuracy;
                const bestAccuracy = best && best.position.coords.accuracy;
                if (!best || accuracy < bestAccuracy - 1
                    || (Math.abs(accuracy - bestAccuracy) <= 1 && entry.seq > best.seq)) {
                    best = entry;
                }
            }
            return best;
        }

        function bestFix(newerThan) {
            const entry = bestEntry(newerThan);
            return entry ? entry.position : null;
        }

        /**
         * Keep a fix arriving while the student is getting ready.
         *
         * A position fetched only at the moment of submitting is the slowest
         * possible way to get one: the GPS is cold exactly when the student
         * is waiting. Watching from the moment they start (opening the
         * camera, or focusing the code box) means there is usually a recent
         * fix in hand before they press anything.
         */
        function startWatching() {
            if (source) source.want(consumer);
        }

        function stopWatching() {
            if (source) source.release(consumer);
        }

        /**
         * A fix the server will accept, or an error saying why there is none.
         *
         * maximumAge is a hint, not a promise: Android's fused provider hands
         * back a last-known location — minutes or hours old — whenever it
         * cannot get a fresh one, typically indoors, which is exactly where a
         * lecture happens. Fixes older than the server allows are never
         * chosen, and when the page has nothing fresh one new reading is
         * forced with maximumAge: 0 — at once if location is already known to
         * work, otherwise halfway through the budget.
         *
         * `onProgress(best)` is called while waiting, with the best fix so
         * far (or null), so the page can say what it is doing.
         */
        async function acquire(newerThan, onProgress) {
            if (!source) {
                throw locationError('Geolocation is not supported by this browser.');
            }
            startWatching();
            const started = performance.now();
            let forced = false;
            if (source.seenFix && !bestEntry(newerThan)) {
                // Location works here, but nothing in hand is recent: a phone
                // lying still on the desk, which iOS stops reporting. Ask now
                // rather than sitting out half the budget first.
                forced = true;
                source.request(true, 0);
            }
            for (;;) {
                const waited = performance.now() - started;
                const best = bestEntry(newerThan);
                if (best) {
                    const accuracy = best.position.coords.accuracy;
                    const settled = waited >= SETTLE_MS || source.watchAgeMs >= WATCH_SETTLED_MS;
                    if (accuracy <= GOOD_ACCURACY_M || (accuracy <= MAX_ACCURACY_M && settled)) {
                        return best.position;
                    }
                }
                if (source.denied) {
                    throw locationError(describeLocationError(source.lastError), 1);
                }
                // Every fresh reading so far is kilometres wide, and has been
                // for long enough that a GPS warming up would have done better.
                const freshest = bestEntry(0);
                if (freshest && freshest.position.coords.accuracy > APPROXIMATE_M
                        && Math.max(waited, source.watchAgeMs) >= APPROXIMATE_AFTER_MS) {
                    throw imprecise(freshest.position);
                }
                if (waited >= LOCATION_BUDGET_MS) break;
                if (onProgress) onProgress(best ? best.position : null);
                if (!forced && waited >= LOCATION_BUDGET_MS / 2) {
                    forced = true;
                    source.request(true, 0);
                }
                await source.nextFix(Math.min(500, LOCATION_BUDGET_MS - waited));
            }
            const best = bestEntry(newerThan);
            if (best && best.position.coords.accuracy <= MAX_ACCURACY_M) return best.position;
            // Out of time with nothing the server would take. Posting it
            // anyway was a round trip to be refused, then three automatic
            // retries of twelve seconds each, then the same refusal: say now
            // what would help.
            const anything = best || bestEntry(0);
            if (anything) throw imprecise(anything.position);
            const error = source.lastError;
            throw locationError(describeLocationError(error), error && error.code);
        }

        /** The fields the server's geofence reads, from one fix. */
        function payload(position) {
            return {
                lat: position.coords.latitude,
                lon: position.coords.longitude,
                accuracy_m: position.coords.accuracy,
                location_age_ms: Math.round(positionAge(position)),
            };
        }

        /** Identifies a fix for acquire(newerThan): "one that came after this". */
        function fixId(position) {
            const entry = source && position && source.entryFor(position);
            return entry ? entry.seq : 0;
        }

        return {
            acquire,
            startWatching,
            stopWatching,
            bestFix,
            payload,
            positionAge,
            fixId,
            describeError: describeLocationError,
            describeImprecise,
            platform,
            get watching() { return Boolean(source && source.watching); },
        };
    }

    const api = { deviceId, serverRetryDelay, bumpAttendance, createLocator, platformOf };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.ScanMarkAttendance = api;
}(typeof window !== 'undefined' ? window : null));
