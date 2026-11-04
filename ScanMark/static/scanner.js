(function () {
    'use strict';

    const config = window.SCANMARK_SCANNER_CONFIG || {};

    // A stable per-installation identifier, so "this scan came from the same
    // phone as that one" is answerable. Every scan used to report the literal
    // string 'browser', which made the column useless for the one thing it is
    // good for: spotting one device marking six people present.
    //
    // NOT a credential. It is client-generated, client-stored and trivially
    // forged; the server treats it as a diagnostic label and nothing else.
    // Anything that needs to be true about who scanned comes from the session.
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
            // a fresh id per scan, which would look like many devices.
            return 'unavailable';
        }
    }

    const DEVICE_ID = deviceId();
    const analysisCanvas = document.getElementById('processing-canvas');
    if (!analysisCanvas) return;          // a page without the scanner markup
    const context = analysisCanvas.getContext('2d', { willReadFrequently: true });
    const video = document.getElementById('camera-feed');
    const container = document.getElementById('scanner-container');
    const loader = document.getElementById('loader');
    const statusBadge = document.getElementById('status-badge');
    const scanFrame = document.getElementById('scan-frame');
    const zoomSlider = document.getElementById('zoom-slider');
    const zoomLabel = document.getElementById('zoom-label');
    const torchButton = document.getElementById('torch-btn');
    const focusButton = document.getElementById('focus-btn');
    const cameraInfo = document.getElementById('camera-info');
    const resultBanner = document.getElementById('result-banner');

    // ---- How hard the scanner hunts -------------------------------------
    //
    // A code across a lecture hall covers very few pixels. Cropping the middle
    // of the frame and rendering it larger is a free digital zoom: the decoder
    // gets the same photons spread over more samples, which is often all its
    // grid-fitting needs to lock on. Past about 2x it is inventing detail.
    const MAX_UPSCALE = 2;
    // Regions of the frame's short edge, cycled one per frame so no single
    // frame pays for all of them — the whole view first (a code held close, or
    // off to one side), then progressively tighter middles for one far away.
    //
    // `width` is what each is worth analysing at. The wide pass exists to
    // catch a code that is already large or off-centre, and does not need the
    // full working resolution to do it; spending it there doubled the cost of
    // the most common frame for nothing.
    const WIDE = { fraction: 1, width: 512 };
    const MIDDLE = { fraction: 0.55, width: 720 };
    const CENTRE = { fraction: 0.32, width: 720 };
    // The back of a lecture hall. From 14m a projected code lands on one or
    // two camera pixels per module, which no decoder's finder-pattern scan
    // locks onto. Rendered 3x it gets edges it can place between pixels; the
    // detail is not new, but the decoder could not use it at 1x. Only this
    // pass pays for that, and it is small: a fifth of the short edge.
    const FAR = { fraction: 0.2, width: 720, upscale: 3 };
    const HUNT_REGIONS = [WIDE, MIDDLE, CENTRE, MIDDLE, FAR];
    const TARGET_INTERVAL_MS = 70;
    // While a scan is already in hand and only waiting on the network, the
    // camera is kept reading purely to pick up the NEXT code the projector
    // shows. That needs a look every quarter second, not fourteen a second.
    const REFRESH_INTERVAL_MS = 250;
    // Consecutive frames that find nothing before the scanner changes
    // something about how it is looking. Roughly a second of not finding it.
    const ESCALATE_AFTER_MISSES = 10;
    // Light/dark crossings per sampled pixel, in the busiest patch of the
    // middle of the frame, above which it holds something finely striped — a
    // code too small or too blurred to decode, rather than a wall.
    const PATTERN_THRESHOLD = 0.03;
    // How far either side of the middle of a patch's range a pixel must be to
    // count as light or dark. Well above sensor noise, well below the
    // black-to-white swing of even a washed-out projected code.
    const PATTERN_HYSTERESIS = 16;
    // Patches per side of the region judged. A distant code fills one of
    // them; averaged over the whole middle it would vanish into the wall.
    const PATTERN_TILES = 5;

    // ---- Location ----------------------------------------------------------
    //
    // How old a fix may be before we look for a better one. Deliberately
    // tighter than the server's limit, so there is room to get a fresh fix
    // and still post inside it.
    const POSITION_MAX_AGE_MS = 10000;
    // What the SERVER will refuse. Sent by the page; the fallback matches
    // GEOFENCE_MAX_LOCATION_AGE_MS's own default.
    const SERVER_MAX_AGE_MS = Number(config.maxLocationAgeMs) > 0
        ? Number(config.maxLocationAgeMs) : 30000;
    // The worst accuracy the server accepts. Posting a fix it will refuse
    // as imprecise is a wasted round trip and a red banner; waiting a few
    // seconds for the watch to narrow is usually all it takes.
    const MAX_ACCURACY_M = Number(config.maxLocationAccuracyM) > 0
        ? Number(config.maxLocationAccuracyM) : 100;
    // How long a scan waits for a usable fix before it goes with the best
    // one it has (or explains why there is none).
    const LOCATION_BUDGET_MS = 12000;
    // A high-accuracy watch indoors can go quiet for a long time while it
    // hunts for satellites. The network (Wi-Fi/cell) position answers in
    // about a second and, inside a building with Wi-Fi, is often the more
    // accurate of the two. Asked for after this long without any fix.
    const NETWORK_FIX_AFTER_MS = 3000;
    // Automatic goes at a fresh fix after the server said this one was too
    // far, too vague or too old. Indoor fixes drift: the next reading is
    // often 30-60m closer to the truth, and asking the student to tap again
    // for it is the "you are too far" error a student sitting in the hall
    // used to get.
    const LOCATION_RETRY_LIMIT = 3;

    // ---- Submission --------------------------------------------------------
    //
    //: Marks that this page already reloaded itself once to recover a
    //  session/CSRF mismatch, so it cannot do it again in a loop.
    const RELOADED_FOR_SESSION_KEY = 'scanmark-reloaded-for-session';
    // How many times we may re-read the projected code and resubmit on our
    // own after the server refused the CODE (expired, not read just now).
    // Past this the camera stops and waits for a deliberate tap. Without the
    // cap a rejected phone re-reads the screen forever, which is the whole
    // class's worth of wasted requests for the rest of the lecture.
    const AUTO_RESUBMIT_LIMIT = 3;
    // One request's patience. A 2G POST on a cold connection is two round
    // trips of set-up plus one for the request: a few seconds. Past this it
    // is more likely stuck behind a dead radio than slow, and a fresh
    // attempt (with the newest code) beats waiting on it.
    const REQUEST_TIMEOUT_MS = 15000;
    // How long a scan already read keeps trying to reach the server before
    // the page gives up on it. Long, on purpose: as long as the camera can
    // see the projector, every retry carries a code that is seconds old, so
    // the server's replay window never runs out on a student whose network
    // did.
    const PENDING_GIVE_UP_MS = 300000;
    // Keep a connection open while the scanner waits for the code to go up:
    // the scan then rides it instead of paying TCP + TLS set-up — two round
    // trips, which on 2G is the better part of two seconds. Below the
    // ~60s idle reaping of most routers and carrier NATs.
    const WARM_INTERVAL_MS = 45000;
    // What a ScanMark code looks like. Anything else is somebody else's QR
    // on the slide; posting it costs the student a request from their
    // ten-a-minute allowance to be told so.
    const TOKEN_PATTERN = /^S(\d+)\|(\d+)\|[0-9a-f]{16}$/;
    const QR_WINDOW_SECONDS = Number(config.qrWindowSeconds) > 0
        ? Number(config.qrWindowSeconds) : 45;

    let stream = null;
    let track = null;
    let capabilities = {};
    let detector = null;
    let active = false;
    let decodePending = false;
    let frameNumber = 0;
    let lastAnalysisAt = 0;
    let analysisIntervalMs = TARGET_INTERVAL_MS;
    let animationFrameId = null;
    let focusIntervalId = null;
    let bannerTimeoutId = null;
    let warmIntervalId = null;
    let cameraStartedAt = 0;
    let cameraReadyMs = 0;
    let lastDecodeMs = 0;
    let torchEnabled = false;
    // The student tapped the flashlight themselves. The automatic hunt below
    // then leaves it alone — a control that fights the person holding it is
    // worse than no control.
    let torchManual = false;
    let frameCallbackId = null;
    let missStreak = 0;
    let enhancing = false;
    let adapting = false;
    let resolutionRaised = false;
    // The zoom the page wants the camera at: null when it cannot zoom. Kept
    // here rather than read back from the track, because a camera restarted
    // for a new resolution comes back at its default and has to be told again.
    let zoomLevel = null;
    // Where this camera starts. Not necessarily the minimum: a phone that
    // exposes its ultra-wide lens as 0.5x opens at 1x, and "undoing" a zoom
    // to 0.5x would swap to the soft, fixed-focus lens.
    let zoomDefault = null;
    // The student moved the zoom slider. Like the torch, the hunt then leaves
    // zoom alone: it used to put the camera back at 1x a couple of seconds
    // after every drag, which is exactly when someone at the back had just
    // framed the code.
    let zoomManual = false;
    let zoomPending = null;
    let zoomApplying = false;

    // ---- The scan in hand --------------------------------------------------
    //
    // Once a code has been read, it is a PENDING scan until the server gives
    // a definitive answer. Everything that can go wrong in between — no
    // signal, a stalled request, a busy server, a GPS fix that drifted — is
    // handled by trying again, automatically, with the newest code the camera
    // has seen and the best fix the phone has. The student does not rescan.
    let pending = null;
    let inFlight = false;
    let retryTimeoutId = null;
    let transientAttempts = 0;
    let codeRejections = 0;
    let locationRetries = 0;
    let csrfRefreshes = 0;
    // The timestamp of a fix the server refused. The next attempt waits for
    // a NEWER one; resubmitting the same reading gets the same answer.
    let refusedFixAt = 0;
    // Server clock minus ours, learned from a response's Date header. A
    // phone whose clock is a minute out used to have every scan refused as
    // "not read from the screen just now", because the capture time it
    // reported was compared against the server's token time.
    let serverOffsetMs = null;
    let lastWarmAt = 0;

    function status(message, type) {
        statusBadge.textContent = message;
        statusBadge.className = `status-badge ${type}`;
    }

    function result(message, kind) {
        if (!resultBanner) return;
        resultBanner.textContent = message;
        resultBanner.className = `alert mt-3 text-center fw-bold fs-5 alert-${kind}`;
        resultBanner.classList.remove('d-none');
        clearTimeout(bannerTimeoutId);
        bannerTimeoutId = setTimeout(() => resultBanner.classList.add('d-none'), 9000);
    }

    // ---- Clock and connection ----------------------------------------------

    function noteServerDate(response) {
        const header = response && response.headers ? response.headers.get('Date') : null;
        const parsed = header ? Date.parse(header) : NaN;
        // The header is truncated to the second; the middle of that second
        // is the best guess.
        if (Number.isFinite(parsed)) serverOffsetMs = parsed + 500 - Date.now();
        return response;
    }

    function serverNow() {
        return Date.now() + (serverOffsetMs || 0);
    }

    /**
     * Open (or keep open) the connection the scan will be posted on.
     *
     * Same credentials mode as the scan itself: browsers keep separate
     * connection pools for credentialed and anonymous requests, and warming
     * the wrong one would be a round trip spent on nothing.
     */
    function warmConnection() {
        if (!config.warmUrl) return;
        lastWarmAt = Date.now();
        fetch(config.warmUrl, { method: 'HEAD', cache: 'no-store' })
            .then(noteServerDate)
            .catch(() => {});
    }

    // ---- Decoders ----------------------------------------------------------

    let jsqrRequested = null;

    /**
     * Load the software decoder only when it is needed.
     *
     * Phones whose browser has BarcodeDetector (most Android Chrome) never
     * use jsQR, and it is the heaviest file on the page. It used to be a
     * parser-blocking script on the scan page; now it is fetched in the
     * background, from the service worker's cache after the first visit.
     */
    function loadJsQR() {
        if (typeof window.jsQR === 'function') return Promise.resolve();
        if (!jsqrRequested && config.jsqrUrl) {
            jsqrRequested = new Promise(resolve => {
                const script = document.createElement('script');
                script.src = config.jsqrUrl;
                script.async = true;
                script.onload = resolve;
                script.onerror = () => { jsqrRequested = null; resolve(); };
                document.head.appendChild(script);
            });
        }
        return jsqrRequested || Promise.resolve();
    }

    async function configureDetector() {
        detector = null;
        if (!('BarcodeDetector' in window)) return;
        try {
            const formats = await window.BarcodeDetector.getSupportedFormats();
            if (formats.includes('qr_code')) {
                detector = new window.BarcodeDetector({ formats: ['qr_code'] });
            }
        } catch (_) {
            detector = null;
        }
    }

    // Asking the platform which formats it supports can take a few hundred
    // milliseconds the first time (it loads the barcode model). That used to
    // happen after the tap, in series with opening the camera; it now runs
    // while the page is still being read.
    const detectorReady = configureDetector().then(() => {
        if (!detector) loadJsQR();
    });

    // ---- Location ----------------------------------------------------------

    const fixes = [];
    let fixWaiters = [];
    let watchId = null;
    let lastLocationError = null;
    let networkFixTimer = null;

    /**
     * A problem with the fix itself, not with the network.
     *
     * Retrying it immediately gets the same cached fix, so these are handed
     * back to the student with the reason rather than swallowed by the
     * transient-retry path — which is what used to happen to a GPS permission
     * denial, reported as "Network busy" while the network was fine.
     */
    function locationError(message) {
        const error = new Error(message);
        error.locationProblem = true;
        return error;
    }

    function positionAge(position) {
        // Clock skew between the fix's stamp and now can read negative; the
        // server floors it at zero, so judge it the same way here.
        return Math.max(0, Date.now() - position.timestamp);
    }

    function describeLocationError(error) {
        // Three different problems with three different fixes. All three
        // used to read "Allow GPS access" — including a timeout indoors,
        // where permission was granted and the student could do nothing
        // about the message they were given.
        if (error && error.code === 1) {
            return 'Location permission is off for this site. Allow location ' +
                '(precise) in your browser settings, then scan again.';
        }
        if (error && error.code === 2) {
            return 'Your phone could not work out where it is. Turn on Location ' +
                '(GPS) in your phone settings, then scan again.';
        }
        return 'Could not get a location fix in time. Step towards a window or ' +
            'doorway for a moment, then scan again.';
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
     * there, and indoors it wanders: one reading ±15m, the next ±60m. Taking
     * whichever arrived last meant a scan could carry the worst reading of
     * the last ten seconds — and be told the student was too far away.
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
            if (!navigator.geolocation) {
                reject(locationError('Geolocation is not supported by this browser.'));
                return;
            }
            navigator.geolocation.getCurrentPosition(
                position => {
                    noteFix(position);
                    resolve(position);
                },
                error => {
                    lastLocationError = error;
                    reject(locationError(describeLocationError(error)));
                },
                { enableHighAccuracy: highAccuracy !== false, timeout: 10000, maximumAge: maximumAge }
            );
        });
    }

    /**
     * Keep a fix arriving while the camera is open.
     *
     * A position fetched only at the moment of a scan is the slowest possible
     * way to get one: the GPS is cold exactly when the student is waiting.
     * Watching from camera start means there is usually a recent fix in hand
     * before the code is even read.
     */
    function startWatchingLocation() {
        if (!navigator.geolocation || watchId !== null) return;
        watchId = navigator.geolocation.watchPosition(
            noteFix,
            // A watch reports errors as they happen and keeps going; only a
            // denial is final. Waiters are woken so a denial is reported now
            // rather than at the end of the budget.
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

    function stopWatchingLocation() {
        clearTimeout(networkFixTimer);
        if (watchId === null) return;
        navigator.geolocation.clearWatch(watchId);
        watchId = null;
    }

    /**
     * A fix the server will accept, or an error saying why there is none.
     *
     * maximumAge is a hint, not a promise: Android's fused provider hands
     * back a last-known location — minutes or hours old — whenever it cannot
     * get a fresh one, typically indoors, which is exactly where a lecture
     * happens. Fixes older than the server allows are never chosen; when
     * nothing usable has arrived halfway through the budget, one fresh
     * reading is forced with maximumAge: 0.
     */
    async function acquirePosition(newerThan) {
        if (!navigator.geolocation) {
            throw locationError('Geolocation is not supported by this browser.');
        }
        startWatchingLocation();
        const started = performance.now();
        let forced = false;
        for (;;) {
            const best = bestFix(newerThan);
            if (best && best.coords.accuracy <= MAX_ACCURACY_M) return best;
            if (lastLocationError && lastLocationError.code === 1) {
                throw locationError(describeLocationError(lastLocationError));
            }
            const waited = performance.now() - started;
            if (waited >= LOCATION_BUDGET_MS) break;
            status(best
                ? `Sharpening your location (±${Math.round(best.coords.accuracy)}m)...`
                : 'Finding your location...', 'scanning');
            if (!forced && waited >= LOCATION_BUDGET_MS / 2) {
                forced = true;
                requestPosition(0).catch(() => {});
            }
            await nextFix(Math.min(1000, LOCATION_BUDGET_MS - waited));
        }
        // Out of time. The best reading there is still goes, and the server
        // explains in its own words if it is not good enough.
        const best = bestFix(newerThan);
        if (best) return best;
        throw locationError(describeLocationError(lastLocationError));
    }

    function applyCameraSettings() {
        capabilities = (track && track.getCapabilities && track.getCapabilities()) || {};
        zoomLevel = zoomDefault = capabilities.zoom
            ? clampZoom(trackSetting('zoom', capabilities.zoom.min || 1)) : null;
        syncZoomSlider();
        // Continuous focus was already asked for in getUserMedia. Repeating
        // it explicitly helps some cameras, but nothing has to wait for it:
        // it used to be awaited before the first frame was looked at, which
        // put a constraint round trip into every camera start.
        if (capabilities.focusMode && capabilities.focusMode.includes('continuous')) {
            applyAdvanced({ focusMode: 'continuous' });
        }
    }

    function clampZoom(level) {
        const range = capabilities.zoom;
        return Math.min(range.max, Math.max(range.min, Number(level)));
    }

    function showZoom(level, moveSlider) {
        // Not while the student is dragging it: the value just applied is
        // already behind their finger, and writing it back yanks the thumb.
        if (moveSlider) zoomSlider.value = level;
        zoomLabel.textContent = `${Number(level).toFixed(1)}x`;
    }

    /**
     * Fit the slider to the camera's zoom range, or hide it when there is
     * none: a slider that moves while the picture does not reads as broken.
     */
    function syncZoomSlider() {
        const range = capabilities.zoom;
        zoomSlider.parentElement.style.display = range ? '' : 'none';
        if (!range) return;
        zoomSlider.min = range.min;
        zoomSlider.max = range.max;
        zoomSlider.step = range.step || 0.1;
        if (zoomLevel !== null) showZoom(zoomLevel, true);
    }

    /**
     * Apply the newest slider position, coalescing the rest.
     *
     * One drag fires dozens of input events. Awaiting each in turn queues
     * constraint changes the camera is still working through long after the
     * finger has stopped; only the last position matters.
     */
    async function requestZoom(level) {
        zoomLevel = clampZoom(level);
        zoomPending = zoomLevel;
        showZoom(zoomLevel, false);
        if (zoomApplying) return;
        zoomApplying = true;
        try {
            while (zoomPending !== null && track) {
                const next = zoomPending;
                zoomPending = null;
                await applyAdvanced({ zoom: next });
            }
        } finally {
            zoomApplying = false;
        }
    }

    function waitForVideo() {
        if (video.readyState >= 2 && video.videoWidth) return Promise.resolve();
        return new Promise(resolve => video.addEventListener('loadedmetadata', resolve, { once: true }));
    }

    let cameraGeneration = 0;

    async function startScanner() {
        stopCamera();
        const generation = cameraGeneration;
        // A deliberate tap is a fresh start: give the automatic-resubmit
        // budget back rather than inheriting the previous attempt's streak,
        // and begin the hunt from an un-adapted camera so a zoom left over
        // from the last room does not narrow this one's first look.
        codeRejections = 0;
        locationRetries = 0;
        missStreak = 0;
        enhancing = false;
        resolutionRaised = false;
        torchManual = false;
        torchEnabled = false;
        zoomManual = false;
        zoomPending = null;
        cameraStartedAt = performance.now();
        // Everything the scan will need is started now, side by side, rather
        // than one after another once the code is in view: the GPS watch,
        // the connection the result will be posted on, and the decoder.
        startWatchingLocation();
        if (Date.now() - lastWarmAt > 5000) warmConnection();
        warmIntervalId = setInterval(() => {
            if (!inFlight) warmConnection();
        }, WARM_INTERVAL_MS);
        container.style.display = 'block';
        document.body.style.overflow = 'hidden';
        loader.style.display = 'block';
        status(pending ? 'Point at the code on screen to finish...' : 'Opening camera...',
               'scanning');
        try {
            const opened = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: { ideal: 'environment' },
                    // Start modest. Distance is a resolution problem before
                    // it is anything else, but most scans are of a code a few
                    // metres away and 720p reads those in half the time. The
                    // hunt raises this to 1080p the moment it starts failing,
                    // which is the only time the extra pixels earn their cost.
                    width: { ideal: 1280 },
                    height: { ideal: 720 },
                    focusMode: { ideal: 'continuous' }
                },
                audio: false
            });
            if (generation !== cameraGeneration) {
                // Closed while the camera was opening: do not leave it on
                // behind a hidden overlay.
                opened.getTracks().forEach(mediaTrack => mediaTrack.stop());
                return;
            }
            stream = opened;
            video.srcObject = stream;
            await waitForVideo();
            await video.play();
            if (generation !== cameraGeneration) return;
            track = stream.getVideoTracks()[0];
            applyCameraSettings();
            cameraReadyMs = performance.now() - cameraStartedAt;
            announce('');
            loader.style.display = 'none';
            active = true;
            if (!pending) {
                status(detector ? 'Scanning (native detector)...' : 'Scanning...', 'scanning');
            }
            focusIntervalId = setInterval(nudgeFocus, 4000);
            scheduleFrame();
            // A detector can fail at runtime and fall back to software, so
            // have jsQR on its way unless the platform one is in hand.
            detectorReady.then(() => { if (!detector) loadJsQR(); });
        } catch (error) {
            if (generation !== cameraGeneration) return;
            stopScanner();
            result(`Camera error: ${error.message || error}`, 'danger');
        }
    }

    function stopCamera() {
        cameraGeneration += 1;
        active = false;
        decodePending = false;
        clearInterval(focusIntervalId);
        clearInterval(warmIntervalId);
        if (animationFrameId !== null) cancelAnimationFrame(animationFrameId);
        if (frameCallbackId !== null && video.cancelVideoFrameCallback) {
            video.cancelVideoFrameCallback(frameCallbackId);
        }
        focusIntervalId = warmIntervalId = animationFrameId = frameCallbackId = null;
        if (stream) stream.getTracks().forEach(mediaTrack => mediaTrack.stop());
        stream = track = null;
        video.srcObject = null;
        video.style.width = '';
        loader.style.display = 'none';
        container.style.display = 'none';
        document.body.style.overflow = '';
    }

    function stopScanner() {
        stopCamera();
        // The watch exists to have a fix ready for a scan. With the camera
        // closed and no scan still being sent there is nothing to fix, and a
        // live GPS watch is one of the most expensive things a page can
        // leave running on a phone.
        if (!pending) stopWatchingLocation();
    }

    /** The close button: the camera goes, a scan already read does not. */
    function closeScanner() {
        stopScanner();
        if (pending && pending.needsFreshCode) {
            // The code in hand is spent and the camera that would have read
            // the next one is gone: there is nothing left to send.
            abandon('Scan not sent: that code had expired. Open the scanner and scan again.',
                    'warning');
        } else if (pending) {
            result('Your scan is still being sent. Keep this page open until it is confirmed.',
                   'warning');
        }
    }

    /**
     * Put one region of the live frame on the analysis canvas.
     *
     * `fraction` is how much of the frame's short edge to take from the
     * middle. Small fractions are rendered back UP towards the analysis
     * width, which is the whole trick for distance: a 60-pixel code becomes a
     * 120-pixel one, and the decoder's threshold and grid-fitting stages have
     * something to work with.
     */
    function drawRegion(region) {
        const sourceWidth = video.videoWidth;
        const sourceHeight = video.videoHeight;
        const cropSize = Math.max(16,
            Math.floor(Math.min(sourceWidth, sourceHeight) * region.fraction));
        const sourceX = Math.floor((sourceWidth - cropSize) / 2);
        const sourceY = Math.floor((sourceHeight - cropSize) / 2);
        const output = Math.min(region.width,
            Math.floor(cropSize * (region.upscale || MAX_UPSCALE)));
        if (analysisCanvas.width !== output || analysisCanvas.height !== output) {
            analysisCanvas.width = output;
            analysisCanvas.height = output;
        }
        context.drawImage(video, sourceX, sourceY, cropSize, cropSize, 0, 0, output, output);
        return { whole: region.fraction >= 1 };
    }

    /**
     * Grey copy of the analysis canvas, and what the light in it is doing.
     *
     * One pass, because this runs on every frame on a phone: the luma values
     * feed the contrast stretch, and the histogram is what tells a frame that
     * is too dark from one that is blown out — which for a projected code in
     * a dark hall is the failure that actually happens.
     */
    function readFrame(image) {
        const data = image.data;
        const pixels = data.length >> 2;
        const grey = new Uint8Array(pixels);
        const histogram = new Uint32Array(256);
        let total = 0;
        for (let index = 0, g = 0; g < pixels; index += 4, g++) {
            // Rec. 601 luma, in integers: this is the hottest loop here.
            const luma = (data[index] * 77 + data[index + 1] * 150 + data[index + 2] * 29) >> 8;
            grey[g] = luma;
            histogram[luma]++;
            total += luma;
        }
        return { grey, histogram, pixels, mean: total / pixels };
    }

    /**
     * Roughly: is there something finely striped in the middle of this?
     *
     * A QR code is dense black-and-white transitions; a wall, a face or an
     * empty screen is not. Counting them along a few sampled rows is cheap
     * and separates the two well enough to steer the camera. Lots of
     * transitions and still no decode means a real code that is too small or
     * too blurred — worth zooming into. None means there is nothing here, and
     * zooming would only narrow the search.
     *
     * Judged per patch, and the busiest patch wins: a code at the back of the
     * hall fills one patch, and averaged over the whole middle it used to
     * read as a blank wall — so the hunt never zoomed for exactly the scan
     * that needed it. A crossing is a swing from the dark side of the patch's
     * range to the light side, which still counts the soft, upscaled edges
     * of a distant code and the grey "black" of a projector, where a fixed
     * step between neighbouring pixels did not.
     */
    function patternEnergy(grey, width, height) {
        const size = Math.floor(Math.min(width, height) / PATTERN_TILES);
        if (size < 8) return 0;
        // Patches overlap by half, so a code sitting where four of them meet
        // still lands whole in one.
        const stride = size >> 1;
        const rowsPerTile = 6;
        const sampled = rowsPerTile * size;
        let best = 0;
        for (let y0 = 0; y0 + size <= height; y0 += stride) {
            const rows = [];
            for (let r = 1; r <= rowsPerTile; r++) {
                rows.push((y0 + Math.floor(size * r / (rowsPerTile + 1))) * width);
            }
            for (let x0 = 0; x0 + size <= width; x0 += stride) {
                let low = 255;
                let high = 0;
                for (const y of rows) {
                    for (let x = x0; x < x0 + size; x++) {
                        const value = grey[y + x];
                        if (value < low) low = value;
                        if (value > high) high = value;
                    }
                }
                if (high - low < 2 * PATTERN_HYSTERESIS) continue;   // flat: noise only
                // The middle of the patch's own range, not its mean: a code
                // on a white slide is mostly white, and its mean sits so close
                // to white that nothing in it reads as lighter.
                const middle = (low + high) / 2;
                const dark = middle - PATTERN_HYSTERESIS;
                const light = middle + PATTERN_HYSTERESIS;
                let crossings = 0;
                for (const y of rows) {
                    let state = 0;
                    for (let x = x0; x < x0 + size; x++) {
                        const value = grey[y + x];
                        if (value > light && state !== 1) {
                            if (state) crossings++;
                            state = 1;
                        } else if (value < dark && state !== -1) {
                            if (state) crossings++;
                            state = -1;
                        }
                    }
                }
                best = Math.max(best, crossings / sampled);
            }
        }
        return best;
    }

    /**
     * Stretch the frame's contrast across the full range, in place.
     *
     * Clips the top and bottom 2% first, so one glare highlight or one dark
     * corner cannot flatten everything else. This is what rescues a washed-out
     * projector screen or a code in shadow — both of which are a QR whose
     * black and white are simply too close together for a threshold to split.
     */
    function enhance(image, frame) {
        const { grey, histogram, pixels } = frame;
        const clip = Math.max(1, Math.floor(pixels * 0.02));
        let low = 0;
        let high = 255;
        for (let value = 0, seen = 0; value < 256; value++) {
            seen += histogram[value];
            if (seen > clip) { low = value; break; }
        }
        for (let value = 255, seen = 0; value >= 0; value--) {
            seen += histogram[value];
            if (seen > clip) { high = value; break; }
        }
        if (high - low < 16) return false;   // already flat; nothing to gain
        const scale = 255 / (high - low);
        const data = image.data;
        for (let g = 0, index = 0; g < pixels; g++, index += 4) {
            const stretched = (grey[g] - low) * scale;
            const clamped = stretched < 0 ? 0 : stretched > 255 ? 255 : stretched;
            data[index] = data[index + 1] = data[index + 2] = clamped;
        }
        return true;
    }

    /**
     * Change some camera settings without losing the zoom.
     *
     * applyConstraints REPLACES the track's constraints; it does not add to
     * them. A torch or focus change that leaves zoom out of the set leaves the
     * browser free to put the lens back at its default — which some do — so
     * every change here carries the zoom the page wants along with it.
     */
    async function applyAdvanced(settings) {
        if (!track) return false;
        const merged = zoomLevel !== null && settings.zoom === undefined
            ? Object.assign({ zoom: zoomLevel }, settings) : settings;
        try {
            await track.applyConstraints({ advanced: [merged] });
            return true;
        } catch (_) {
            return false;
        }
    }

    function trackSetting(name, fallback) {
        if (!track || !track.getSettings) return fallback;
        const value = track.getSettings()[name];
        return value === undefined ? fallback : value;
    }

    async function stepZoom(direction) {
        const range = capabilities.zoom;
        if (!range || zoomManual || zoomLevel === null) return false;
        const step = (range.max - range.min) / 4 || range.step || 0.5;
        const next = clampZoom(zoomLevel + direction * step);
        if (Math.abs(next - zoomLevel) < 1e-3) return false;
        if (!await applyAdvanced({ zoom: next })) return false;
        if (zoomManual) {
            // The student grabbed the slider while that was applying: theirs
            // is the zoom that has to end up on the camera.
            await requestZoom(zoomLevel);
            return true;
        }
        zoomLevel = next;
        showZoom(next, true);
        return true;
    }

    async function stepExposure(direction) {
        const range = capabilities.exposureCompensation;
        if (!range) return false;
        const step = (range.step || 0.33) * 3;
        const current = trackSetting('exposureCompensation', 0);
        const next = Math.min(range.max, Math.max(range.min, current + direction * step));
        if (Math.abs(next - current) < 1e-3) return false;
        return applyAdvanced({ exposureCompensation: next });
    }

    async function setTorch(on) {
        if (!capabilities.torch || torchManual || torchEnabled === on) return false;
        if (!await applyAdvanced({ torch: on })) return false;
        torchEnabled = on;
        torchButton.classList.toggle('active', on);
        return true;
    }

    function announce(note) {
        const size = trackSetting('width', video.videoWidth) + 'x' +
            trackSetting('height', video.videoHeight);
        cameraInfo.textContent = note ? `${size} · ${note}` : size;
    }

    /**
     * Change one thing about how the camera is looking, then let it try again.
     *
     * Ordered by how likely each is to be the actual problem and how cheap it
     * is to undo. Software enhancement first, because it is free and
     * reversible. Then exposure — a code projected in a dark hall is BLOWN
     * OUT, not dark, because the camera meters for the room and lets the
     * screen saturate to white, and no amount of zoom fixes that. Then the
     * torch, for a code printed on paper. Then optical zoom, but only when
     * there is something patterned in the middle worth zooming into.
     */
    async function escalate(frame) {
        // Not while a scan is already in hand: the camera is only reading
        // for a newer code by then, and a torch or zoom change on a phone
        // that has been lowered helps nobody.
        if (adapting || pending) return;
        adapting = true;
        try {
            if (!enhancing) {
                enhancing = true;
                announce('sharpening');
                return;
            }
            if (await raiseResolution()) {
                announce('looking closer');
                return;
            }
            if (!frame) return;
            const blownOut =
                (frame.histogram[255] + frame.histogram[254]) > frame.pixels * 0.06;
            if (blownOut && await stepExposure(-1)) {
                announce('dimming for the screen');
                return;
            }
            if (!blownOut && frame.mean < 70 && await setTorch(true)) {
                announce('flashlight on');
                return;
            }
            if (canZoomIn() && centreEnergy() > PATTERN_THRESHOLD && await stepZoom(1)) {
                announce('zooming in');
                return;
            }
            // Nothing left to try. Undo the narrowing, so a code that has since
            // been brought closer is not missed by a camera still zoomed past
            // it, and start the ladder again.
            await resetOptics();
            announce('');
        } finally {
            adapting = false;
        }
    }

    /**
     * Ask the camera for every pixel it has, once the easy attempts have
     * failed.
     *
     * This is the single biggest lever on how far away a code can be read —
     * at 720p one across a hall lands on too few samples to decode at all,
     * and no amount of cropping invents them back. It is not the starting
     * point only because it roughly doubles the per-frame cost, which is a
     * bad trade for the close-up scan that most students are doing.
     */
    async function raiseResolution() {
        if (resolutionRaised || !track) return false;
        const range = capabilities.width;
        if (!range || !range.max || range.max <= 1280) return false;
        // The preview is drawn at the stream's own size, so more pixels would
        // otherwise make it jump bigger on screen just as the student has the
        // code lined up. Keep it where it is.
        const shownWidth = video.getBoundingClientRect().width;
        try {
            await track.applyConstraints({
                width: { ideal: Math.min(1920, range.max) },
                height: { ideal: 1080 }
            });
        } catch (_) {
            return false;
        }
        if (!track) return false;            // closed while that was applying
        resolutionRaised = true;
        if (shownWidth) video.style.width = `${shownWidth}px`;
        // A new resolution can mean a restarted camera, back at its default
        // zoom with the slider still showing the old one. Its zoom range can
        // differ at the new size, too.
        capabilities = (track.getCapabilities && track.getCapabilities()) || capabilities;
        if (capabilities.zoom && zoomLevel !== null) {
            zoomLevel = clampZoom(zoomLevel);
            await applyAdvanced({ zoom: zoomLevel });
        }
        syncZoomSlider();
        return true;
    }

    async function resetOptics() {
        if (capabilities.zoom && !zoomManual && zoomDefault !== null
            && await applyAdvanced({ zoom: zoomDefault })) {
            zoomLevel = zoomDefault;
            showZoom(zoomDefault, true);
        }
        if (capabilities.exposureCompensation) await applyAdvanced({ exposureCompensation: 0 });
        await setTorch(false);
    }

    function canZoomIn() {
        return Boolean(capabilities.zoom) && !zoomManual && zoomLevel !== null
            && zoomLevel < capabilities.zoom.max - 1e-3;
    }

    /**
     * Pattern energy in the middle fifth of the view, which every zoom step
     * keeps in frame.
     *
     * Measured on its own crop rather than on whichever hunt region the
     * deciding frame happened to be: on the wide pass a code at the back of
     * the hall is a speck, and the hunt would conclude there is nothing to
     * zoom into. Only computed when zoom is the next thing to try.
     */
    function centreEnergy() {
        drawRegion(FAR);
        const image = context.getImageData(0, 0, analysisCanvas.width, analysisCanvas.height);
        return patternEnergy(readFrame(image).grey, image.width, image.height);
    }

    /**
     * One pass over the current frame: native detector, then software, then
     * software again on an enhanced copy once the easy attempts have failed.
     */
    async function huntCurrentFrame() {
        const region = drawRegion(HUNT_REGIONS[frameNumber % HUNT_REGIONS.length]);
        const started = performance.now();
        let value = null;

        // The platform's own detector is hardware-backed and better than
        // anything achievable in JavaScript. Give it the zoomed crop, and on
        // the wide pass the untouched video frame as well — some
        // implementations do noticeably better without the canvas round trip.
        if (detector) {
            value = await detectWith(analysisCanvas);
            if (!value && region.whole) value = await detectWith(video);
        }

        let frame = null;
        if (!value && typeof window.jsQR === 'function') {
            const image = context.getImageData(0, 0, analysisCanvas.width, analysisCanvas.height);
            const plain = window.jsQR(image.data, image.width, image.height,
                                      { inversionAttempts: 'dontInvert' });
            value = plain && plain.data;
            if (!value) {
                // readFrame walks every pixel, so it is deliberately NOT on the
                // path taken when the plain pass succeeds — which is the common
                // one. It is computed only to enhance, or on the frame that is
                // about to decide what to change about the camera.
                const deciding = (missStreak + 1) % ESCALATE_AFTER_MISSES === 0;
                if (enhancing || deciding) {
                    frame = readFrame(image);
                    if (enhancing && enhance(image, frame)) {
                        // Both polarities now: a code shown white-on-dark is a
                        // real thing, and the extra pass has earned itself by
                        // this point.
                        const boosted = window.jsQR(image.data, image.width, image.height,
                                                    { inversionAttempts: 'attemptBoth' });
                        value = boosted && boosted.data;
                    }
                }
            }
        }

        lastDecodeMs = performance.now() - started;
        // Back off on slow hardware so the preview stays live; a frozen
        // viewfinder makes people move the phone, which is the opposite of
        // what helps.
        analysisIntervalMs = lastDecodeMs > 110 ? 200
            : lastDecodeMs > 60 ? 120 : TARGET_INTERVAL_MS;

        if (value) return value;

        missStreak += 1;
        if (missStreak % ESCALATE_AFTER_MISSES === 0) await escalate(frame);
        return null;
    }


    async function detectWith(source) {
        try {
            const codes = await detector.detect(source);
            return codes.length ? codes[0].rawValue : null;
        } catch (_) {
            detector = null;
            return null;
        }
    }

    function scheduleFrame() {
        if (!active) return;
        // requestVideoFrameCallback fires when a NEW frame is actually
        // available, rather than once per compositor tick — so no frame is
        // analysed twice and none is missed while one is in flight.
        if (typeof video.requestVideoFrameCallback === 'function') {
            frameCallbackId = video.requestVideoFrameCallback(
                () => analyseFrame(performance.now()));
        } else {
            animationFrameId = requestAnimationFrame(analyseFrame);
        }
    }

    async function analyseFrame(now) {
        if (!active) return;
        const interval = pending
            ? Math.max(analysisIntervalMs, REFRESH_INTERVAL_MS) : analysisIntervalMs;
        if (decodePending || video.readyState < 2 || now - lastAnalysisAt < interval) {
            scheduleFrame();
            return;
        }
        lastAnalysisAt = now;
        decodePending = true;
        frameNumber += 1;
        let value = null;
        try {
            value = await huntCurrentFrame();
        } finally {
            decodePending = false;
        }
        if (value && active) qrDetected(value);
        scheduleFrame();
    }

    // ---- From a read code to a recorded one -------------------------------

    // Refusals of the CODE, which a newer code can cure.
    const CODE_REFUSALS = new Set(['invalid_qr', 'capture_out_of_window']);
    // Refusals of the FIX, which a newer fix can cure.
    const LOCATION_REFUSALS = new Set(['outside_geofence', 'imprecise_location',
                                       'stale_location']);

    function parseToken(text) {
        const match = TOKEN_PATTERN.exec(String(text || ''));
        return match ? { sessionId: match[1], issuedAt: Number(match[2]) } : null;
    }

    function pendingKey() {
        return pending
            ? `${config.userMarker || 'anonymous'}:${pending.token.sessionId}` : null;
    }

    /** ms until the server stops accepting this code, or null if unknown. */
    function codeLifeLeftMs(token) {
        if (serverOffsetMs === null) return null;
        return (token.issuedAt + QR_WINDOW_SECONDS) * 1000 - serverNow();
    }

    let lastForeignCodeAt = 0;

    function qrDetected(qrData) {
        const token = parseToken(qrData);
        if (!token) {
            // Somebody else's QR on the slide. Say so and keep looking,
            // rather than spending one of the student's requests on it.
            if (Date.now() - lastForeignCodeAt > 3000) {
                lastForeignCodeAt = Date.now();
                status("That isn't a ScanMark code. Point at the attendance code.", 'error');
            }
            return;
        }
        if (pending) {
            // The projector moved on to a newer code for the same class:
            // that is now the one in hand, so whatever is sent next is as
            // fresh as the screen. This is what lets a scan outlast a dead
            // network without ever stretching the server's replay window.
            if (token.sessionId === pending.token.sessionId
                    && token.issuedAt > pending.token.issuedAt) {
                pending.qrData = qrData;
                pending.token = token;
                pending.capturedAt = Date.now();
                pending.capturedPerf = performance.now();
                if (pending.needsFreshCode) {
                    pending.needsFreshCode = false;
                    attempt();
                }
            }
            return;
        }
        pending = {
            qrData, token,
            // When the camera READ the code — not when the request goes, which
            // on a slow GPS fix or a dead network can be much later.
            capturedAt: Date.now(),
            capturedPerf: performance.now(),
            since: performance.now(),
            needsFreshCode: false,
        };
        window.__scanmarkPendingKey = pendingKey();
        transientAttempts = 0;
        csrfRefreshes = 0;
        refusedFixAt = 0;
        scanFrame.classList.add('success');
        status('QR code found', 'success');
        if (navigator.vibrate) navigator.vibrate(120);
        attempt();
    }

    function settle() {
        clearTimeout(retryTimeoutId);
        retryTimeoutId = null;
        pending = null;
        window.__scanmarkPendingKey = null;
        transientAttempts = 0;
        codeRejections = 0;
        locationRetries = 0;
        refusedFixAt = 0;
        if (!stream) stopWatchingLocation();
    }

    function abandon(message, kind) {
        settle();
        result(message, kind);
        stopScanner();
    }

    function succeed(payload) {
        settle();
        result(payload.message || 'Attendance marked successfully!', 'success');
        bumpAttendance(payload.course_code);
        stopScanner();
    }

    /** The code in hand is spent; the next one the projector shows is not. */
    function awaitFreshCode(message) {
        if (!stream) {
            abandon(`${message} Open the scanner and point it at the code again.`, 'warning');
            return;
        }
        pending.needsFreshCode = true;
        scanFrame.classList.remove('success');
        status(message, 'error');
    }

    async function attempt() {
        if (!pending || inFlight) return;
        clearTimeout(retryTimeoutId);
        retryTimeoutId = null;
        const left = codeLifeLeftMs(pending.token);
        if (left !== null && left < 0) {
            // Known dead on the server's own clock: posting it only buys a
            // refusal. The camera is still reading; the next code will do.
            awaitFreshCode('That code has expired. Hold the camera on the screen...');
            return;
        }
        inFlight = true;
        let position;
        const gpsStarted = performance.now();
        try {
            status('Confirming location...', 'scanning');
            position = await acquirePosition(refusedFixAt);
        } catch (error) {
            inFlight = false;
            if (error && error.locationProblem && pending) {
                abandon(`${error.message} Tap the scan button to try again.`,
                        'danger');
                return;
            }
            throw error;
        }
        const gpsWaitMs = performance.now() - gpsStarted;
        if (!pending) {             // settled meanwhile (the service worker's copy landed)
            inFlight = false;
            return;
        }
        const scan = pending;
        scan.attempts = (scan.attempts || 0) + 1;
        status('Marking attendance...', 'scanning');
        let response;
        try {
            response = await postScan(scan, position, gpsWaitMs);
        } catch (_) {
            inFlight = false;
            transient(null, 'network');
            return;
        }
        inFlight = false;
        noteServerDate(response);
        if (pending !== scan) return;
        await handleResponse(response, position);
    }

    async function postScan(scan, position, gpsWaitMs) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        try {
            return await fetch(config.endpoint || '/mark_attendance', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': config.csrfToken || ''
                },
                body: JSON.stringify({
                    qr_data: scan.qrData,
                    lat: position.coords.latitude,
                    lon: position.coords.longitude,
                    accuracy_m: position.coords.accuracy,
                    location_age_ms: Math.max(0, Date.now() - position.timestamp),
                    // On the SERVER's clock, which is what the token's own
                    // timestamp is on. Corrected only when a response has
                    // told us the offset; otherwise the phone's own clock.
                    captured_at: new Date(scan.capturedAt + (serverOffsetMs || 0)).toISOString(),
                    user_marker: config.userMarker,
                    device_id: DEVICE_ID,
                    client_metrics: {
                        camera_ready_ms: cameraReadyMs,
                        qr_decode_ms: lastDecodeMs,
                        gps_wait_ms: gpsWaitMs,
                        capture_to_request_ms: performance.now() - scan.capturedPerf
                    }
                }),
                signal: controller.signal
            });
        } finally {
            clearTimeout(timeout);
        }
    }

    /**
     * How long the server says to wait, in ms, or null if it did not say.
     *
     * ScanMark sends Retry-After on exactly the two responses that mean "we
     * are shedding on purpose": 429 from the per-session admission bucket
     * (sub-second — it is smoothing a microburst, not queueing attendance)
     * and 503 when the database connection pool is exhausted (seconds). The
     * server knows how long its own queue needs to drain; a client guessing
     * instead is wrong in both directions. Guessing LONGER than the shed
     * interval wastes the QR window and can let the token expire; guessing
     * SHORTER is 2,000 phones coming back before there is anywhere to put
     * them, which is the burst again.
     *
     * Clamped, because the header is still input: a bad or hostile value
     * must not park the scanner for an hour or turn the backoff into a
     * tight loop.
     */
    function serverRetryDelay(response) {
        const header = response && response.headers
            ? response.headers.get('Retry-After') : null;
        if (!header) return null;
        const seconds = Number(header);
        if (!Number.isFinite(seconds) || seconds < 0) return null;
        const clamped = Math.min(30, seconds) * 1000;
        // Jitter even the server's number. Every phone in the room was shed
        // by the same response and would otherwise come back in the same
        // millisecond.
        return Math.max(250, Math.floor(clamped * (0.75 + Math.random() * 0.5)));
    }

    /**
     * Not an answer yet: no signal, a stalled request, or a busy server.
     *
     * Retried automatically with jittered, capped backoff — or at the pace
     * the server asked for — for as long as it takes, up to a generous
     * ceiling. Requests are idempotent on the server (one row per student per
     * class, enforced by a unique index; a repeat is answered "already
     * marked"), so a retry of a request that DID land is harmless.
     */
    function transient(delayHint, reason) {
        if (!pending) return;
        transientAttempts += 1;
        if (performance.now() - pending.since > PENDING_GIVE_UP_MS) {
            abandon('ScanMark could not be reached for several minutes, so this scan ' +
                    'was not recorded. Check your connection, then scan the code again.',
                    'danger');
            return;
        }
        const delay = delayHint !== null && delayHint !== undefined
            ? delayHint
            : Math.floor(Math.min(8000, 1000 * (2 ** Math.min(transientAttempts - 1, 3)))
                         * (0.75 + Math.random() * 0.5));
        const seconds = Math.max(1, Math.ceil(delay / 1000));
        const keepPointing = stream ? ' Keep the code in view.' : '';
        status(reason === 'server'
            ? `ScanMark is busy; retrying in ${seconds}s.${keepPointing}`
            : `Waiting for signal; retrying in ${seconds}s.${keepPointing}`, 'error');
        retryTimeoutId = setTimeout(attempt, delay);
    }

    function handleLocationRefusal(payload, message, position) {
        const distance = Number(payload.distance_m);
        const radius = Number(payload.radius_m);
        // Kilometres off is not drift; it is somewhere else. Say so now
        // rather than after three more round trips.
        const elsewhere = payload.outcome === 'outside_geofence'
            && Number.isFinite(distance) && Number.isFinite(radius)
            && distance - radius > Math.max(150, 3 * (position.coords.accuracy || 0));
        if (!LOCATION_REFUSALS.has(payload.outcome) || elsewhere
                || locationRetries >= LOCATION_RETRY_LIMIT) {
            abandon(`${message} Tap the scan button to try again.`, 'danger');
            return;
        }
        // Indoor fixes wander. The next reading is often much closer to the
        // truth, so wait for a NEWER one and go again on our own.
        locationRetries += 1;
        refusedFixAt = position.timestamp;
        status('Your location reading was off; taking a fresh one...', 'scanning');
        retryTimeoutId = setTimeout(attempt, 250);
    }

    function handleCodeRefusal(message) {
        codeRejections += 1;
        if (codeRejections >= AUTO_RESUBMIT_LIMIT) {
            abandon(`${message} Tap the scan button to try again.`, 'danger');
            return;
        }
        awaitFreshCode(`${message} Hold the camera on the screen...`);
    }

    async function handleResponse(response, position) {
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            // A non-JSON body from a 4xx is the CSRF guard rejecting a page
            // whose token no longer matches the session, from a server too
            // old to say so in JSON (current ones send `csrf_expired` with a
            // fresh token, handled below without a reload). Retrying cannot
            // fix it; reloading can, because the reloaded page carries a
            // token minted against whatever session the server is using NOW.
            //
            // Once only: a sessionStorage marker means a fault that survives
            // the reload shows the message instead of looping, and the
            // marker is cleared as soon as a scan gets a real answer.
            if (response.status < 500 && response.status !== 429) {
                settle();
                stopScanner();
                if (!sessionStorage.getItem(RELOADED_FOR_SESSION_KEY)) {
                    sessionStorage.setItem(RELOADED_FOR_SESSION_KEY, '1');
                    result('Reconnecting…', 'warning');
                    setTimeout(() => location.reload(), 400);
                    return;
                }
                result('Your session expired. Reload this page, then scan again.', 'danger');
                return;
            }
            transient(serverRetryDelay(response), 'server');
            return;
        }
        let payload;
        try {
            payload = await response.json();
        } catch (_) {
            transient(null, 'network');
            return;
        }
        // A real answer means whatever the reload was for is resolved.
        try { sessionStorage.removeItem(RELOADED_FOR_SESSION_KEY); } catch (_) { /* private mode */ }

        if (response.ok && payload.status === 'success') {
            succeed(payload);
            return;
        }
        if (payload.status === 'queued') {
            // No signal at all. The service worker kept a copy that it will
            // send on its own if this page goes away; meanwhile this page
            // keeps trying, with whichever code is newest.
            transient(null, 'offline');
            return;
        }
        if (payload.outcome === 'csrf_expired' && payload.csrf_token && csrfRefreshes < 2) {
            // The page outlived its form token. The server sent a new one;
            // use it and go straight back, with no reload and nothing lost.
            csrfRefreshes += 1;
            config.csrfToken = payload.csrf_token;
            attempt();
            return;
        }
        // Server fault or deliberate shedding: back off and try again, at the
        // pace the server asked for where it gave one.
        if (response.status === 429 || response.status >= 500) {
            transient(serverRetryDelay(response), 'server');
            return;
        }

        transientAttempts = 0;
        const message = payload.message || 'Attendance could not be marked.';

        if (response.status === 422) {
            handleLocationRefusal(payload, message, position);
            return;
        }
        if (response.status === 400 && CODE_REFUSALS.has(payload.outcome)) {
            handleCodeRefusal(message);
            return;
        }

        // Already on the register: good news, not an error. Most often
        // it is this phone's own retry — the first attempt was saved but
        // its answer never came back (slow mobile data, a busy server),
        // so the scanner asked again. It used to be shown in red, which
        // told a student who WAS marked that scanning had failed.
        if (response.status === 409 && payload.outcome === 'duplicate') {
            if (pending.attempts > 1) {
                // An earlier try of THIS scan landed and only its answer was
                // lost: to the student that is simply "marked", and the
                // count on the page has not been bumped for it yet.
                const course = payload.course_code ? ` for ${payload.course_code}` : '';
                succeed({ message: `Marked present${course}.`, course_code: payload.course_code });
                return;
            }
            settle();
            result(message, 'success');
            stopScanner();
            return;
        }

        // Terminal: nothing about pointing the camera again can change
        // the answer. 403 not enrolled, 404 no such session, 409 the class
        // has ended or a queued scan from another account.
        if (response.status === 403 || response.status === 404 || response.status === 409) {
            abandon(message, 'danger');
            return;
        }
        abandon(`${message} Tap the scan button to try again.`, 'danger');
    }

    /**
     * Show the new count straight away instead of reloading the page for it.
     * Rows carry their numbers as data attributes; anything else is left as
     * the server rendered it.
     */
    function bumpAttendance(courseCode) {
        if (!courseCode) return;
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

    function nudgeFocus() {
        // Only while the hunt is struggling. Re-applying continuous focus
        // restarts the focus sweep on some cameras, so doing it every four
        // seconds regardless blurred a code that was already sharp.
        if (missStreak >= ESCALATE_AFTER_MISSES && !pending) triggerFocus();
    }

    async function triggerFocus() {
        if (!track || !capabilities.focusMode) return;
        if (capabilities.focusMode.includes('continuous')) {
            await applyAdvanced({ focusMode: 'continuous' });
        }
    }

    zoomSlider.addEventListener('input', () => {
        if (!track || !capabilities.zoom) return;
        zoomManual = true;
        requestZoom(Number(zoomSlider.value));
    });

    torchButton.addEventListener('click', async () => {
        if (!track || !capabilities.torch) {
            result('Flashlight control is not available on this camera.', 'warning');
            return;
        }
        // From here on the hunt stops touching the torch: whatever the student
        // chose, they can see the result and the code cannot.
        torchManual = true;
        torchEnabled = !torchEnabled;
        if (await applyAdvanced({ torch: torchEnabled })) {
            torchButton.classList.toggle('active', torchEnabled);
        } else {
            torchEnabled = !torchEnabled;
        }
    });

    focusButton.addEventListener('click', triggerFocus);
    window.addEventListener('pagehide', stopScanner);
    // The radio came back: do not sit out the rest of a backoff.
    window.addEventListener('online', () => {
        if (pending && !inFlight) attempt();
    });

    if (navigator.serviceWorker) {
        // The service worker sent its stored copy of this scan and got an
        // answer first. Anything other than "recorded" is left to this page,
        // whose own attempts carry a newer code than that copy did.
        navigator.serviceWorker.addEventListener('message', event => {
            const data = event.data || {};
            if (data.type !== 'scan-sync' || !pending || data.key !== pendingKey()) return;
            if (data.outcome === 'success' || data.outcome === 'duplicate') {
                succeed({ message: data.message, course_code: data.course_code });
            }
        });
    }

    // Opening the scanner is a click handler, not a page load: the dashboard
    // used to navigate to a separate scan page and make the student tap a
    // second button there. A link keeps working if this script has not
    // arrived yet.
    document.querySelectorAll('[data-open-scanner]').forEach(trigger => {
        trigger.addEventListener('click', event => {
            event.preventDefault();
            startScanner();
        });
    });

    window.startScanner = startScanner;
    window.stopScanner = closeScanner;
    if (config.autoStart) startScanner();
}());
