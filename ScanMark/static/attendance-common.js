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

    /**
     * A location fix the server will accept — the same rules for both ways
     * of marking attendance, because the server applies the same geofence to
     * both.
     *
     * options:
     *   maxLocationAgeMs      the server's freshness limit
     *   maxLocationAccuracyM  the server's precision limit
     *   retryHint             how the error messages end ("scan again")
     *   geolocation           injectable for tests (navigator.geolocation)
     */
    function createLocator(options) {
        const opts = options || {};
        const geolocation = opts.geolocation !== undefined ? opts.geolocation
            : (typeof navigator !== 'undefined' ? navigator.geolocation : undefined);
        const retryHint = opts.retryHint || 'scan again';

        // How old a fix may be before we look for a better one. Deliberately
        // tighter than the server's limit, so there is room to get a fresh
        // fix and still post inside it.
        const POSITION_MAX_AGE_MS = 10000;
        // What the SERVER will refuse. Sent by the page; the fallback matches
        // GEOFENCE_MAX_LOCATION_AGE_MS's own default.
        const SERVER_MAX_AGE_MS = Number(opts.maxLocationAgeMs) > 0
            ? Number(opts.maxLocationAgeMs) : 30000;
        // The worst accuracy the server accepts. Posting a fix it will refuse
        // as imprecise is a wasted round trip and a red banner; waiting a few
        // seconds for the watch to narrow is usually all it takes.
        const MAX_ACCURACY_M = Number(opts.maxLocationAccuracyM) > 0
            ? Number(opts.maxLocationAccuracyM) : 100;
        // How long a submission waits for a usable fix before it goes with
        // the best one it has (or explains why there is none).
        const LOCATION_BUDGET_MS = Number(opts.budgetMs) > 0 ? Number(opts.budgetMs) : 12000;
        // A high-accuracy watch indoors can go quiet for a long time while it
        // hunts for satellites. The network (Wi-Fi/cell) position answers in
        // about a second and, inside a building with Wi-Fi, is often the more
        // accurate of the two. Asked for after this long without any fix.
        const NETWORK_FIX_AFTER_MS = 3000;

        const fixes = [];
        let fixWaiters = [];
        let watchId = null;
        let lastLocationError = null;
        let networkFixTimer = null;

        /**
         * A problem with the fix itself, not with the network.
         *
         * Retrying it immediately gets the same cached fix, so these are
         * handed back to the student with the reason rather than swallowed by
         * a transient-retry path — which is what used to happen to a GPS
         * permission denial, reported as "Network busy" while the network was
         * fine.
         */
        function locationError(message, code) {
            const error = new Error(message);
            error.locationProblem = true;
            error.code = code;
            return error;
        }

        function positionAge(position) {
            // Clock skew between the fix's stamp and now can read negative;
            // the server floors it at zero, so judge it the same way here.
            return Math.max(0, Date.now() - position.timestamp);
        }

        function describeLocationError(error) {
            // Three different problems with three different fixes. All three
            // used to read "Allow GPS access" — including a timeout indoors,
            // where permission was granted and the student could do nothing
            // about the message they were given.
            if (error && error.code === 1) {
                return 'Location permission is off for this site. Allow location ' +
                    `(precise) in your browser settings, then ${retryHint}.`;
            }
            if (error && error.code === 2) {
                return 'Your phone could not work out where it is. Turn on Location ' +
                    `(GPS) in your phone settings, then ${retryHint}.`;
            }
            return 'Could not get a location fix in time. Step towards a window or ' +
                `doorway for a moment, then ${retryHint}.`;
        }

        function noteFix(position) {
            lastLocationError = null;
            fixes.push(position);
            // Nothing older than the server will accept is worth keeping.
            while (fixes.length && (fixes.length > 20 || positionAge(fixes[0]) > SERVER_MAX_AGE_MS)) {
                fixes.shift();
            }
            const waiters = fixWaiters;
            fixWaiters = [];
            waiters.forEach(resolve => resolve());
        }

        function nextFix(timeoutMs) {
            return new Promise(resolve => {
                fixWaiters.push(resolve);
                setTimeout(resolve, timeoutMs);
            });
        }

        /**
         * The most precise recent fix, not merely the latest.
         *
         * A watch reports a coarse network position first and narrows from
         * there, and indoors it wanders: one reading ±15m, the next ±60m.
         * Taking whichever arrived last meant a submission could carry the
         * worst reading of the last ten seconds — and be told the student
         * was too far away.
         */
        function bestFix(newerThan) {
            let best = null;
            for (const position of fixes) {
                if (positionAge(position) > POSITION_MAX_AGE_MS) continue;
                if (newerThan && position.timestamp <= newerThan) continue;
                if (!best || position.coords.accuracy < best.coords.accuracy - 1
                    || (Math.abs(position.coords.accuracy - best.coords.accuracy) <= 1
                        && position.timestamp > best.timestamp)) {
                    best = position;
                }
            }
            return best;
        }

        function requestPosition(maximumAge, highAccuracy) {
            return new Promise((resolve, reject) => {
                if (!geolocation) {
                    reject(locationError('Geolocation is not supported by this browser.'));
                    return;
                }
                geolocation.getCurrentPosition(
                    position => {
                        noteFix(position);
                        resolve(position);
                    },
                    error => {
                        lastLocationError = error;
                        reject(locationError(describeLocationError(error), error && error.code));
                    },
                    { enableHighAccuracy: highAccuracy !== false, timeout: 10000, maximumAge: maximumAge }
                );
            });
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
            if (!geolocation || watchId !== null) return;
            watchId = geolocation.watchPosition(
                noteFix,
                // A watch reports errors as they happen and keeps going; only
                // a denial is final. Waiters are woken so a denial is
                // reported now rather than at the end of the budget.
                error => {
                    lastLocationError = error;
                    if (error.code === 1) {
                        const waiters = fixWaiters;
                        fixWaiters = [];
                        waiters.forEach(resolve => resolve());
                    }
                },
                { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
            );
            clearTimeout(networkFixTimer);
            networkFixTimer = setTimeout(() => {
                if (watchId !== null && !bestFix()) {
                    requestPosition(POSITION_MAX_AGE_MS, false).catch(() => {});
                }
            }, NETWORK_FIX_AFTER_MS);
        }

        function stopWatching() {
            clearTimeout(networkFixTimer);
            if (watchId === null || !geolocation) return;
            geolocation.clearWatch(watchId);
            watchId = null;
        }

        /**
         * A fix the server will accept, or an error saying why there is none.
         *
         * maximumAge is a hint, not a promise: Android's fused provider hands
         * back a last-known location — minutes or hours old — whenever it
         * cannot get a fresh one, typically indoors, which is exactly where a
         * lecture happens. Fixes older than the server allows are never
         * chosen; when nothing usable has arrived halfway through the budget,
         * one fresh reading is forced with maximumAge: 0.
         *
         * `onProgress(best)` is called while waiting, with the best fix so
         * far (or null), so the page can say what it is doing.
         */
        async function acquire(newerThan, onProgress) {
            if (!geolocation) {
                throw locationError('Geolocation is not supported by this browser.');
            }
            startWatching();
            const started = performance.now();
            let forced = false;
            for (;;) {
                const best = bestFix(newerThan);
                if (best && best.coords.accuracy <= MAX_ACCURACY_M) return best;
                if (lastLocationError && lastLocationError.code === 1) {
                    throw locationError(describeLocationError(lastLocationError), 1);
                }
                const waited = performance.now() - started;
                if (waited >= LOCATION_BUDGET_MS) break;
                if (onProgress) onProgress(best);
                if (!forced && waited >= LOCATION_BUDGET_MS / 2) {
                    forced = true;
                    requestPosition(0).catch(() => {});
                }
                await nextFix(Math.min(1000, LOCATION_BUDGET_MS - waited));
            }
            // Out of time. The best reading there is still goes, and the
            // server explains in its own words if it is not good enough.
            const best = bestFix(newerThan);
            if (best) return best;
            throw locationError(describeLocationError(lastLocationError),
                                lastLocationError && lastLocationError.code);
        }

        /** The fields the server's geofence reads, from one fix. */
        function payload(position) {
            return {
                lat: position.coords.latitude,
                lon: position.coords.longitude,
                accuracy_m: position.coords.accuracy,
                location_age_ms: positionAge(position),
            };
        }

        return {
            acquire,
            startWatching,
            stopWatching,
            bestFix,
            payload,
            positionAge,
            describeError: describeLocationError,
            get watching() { return watchId !== null; },
        };
    }

    const api = { deviceId, serverRetryDelay, bumpAttendance, createLocator };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.ScanMarkAttendance = api;
}(typeof window !== 'undefined' ? window : null));
