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

    const MAX_ANALYSIS_WIDTH = 960;
    const TARGET_INTERVAL_MS = 125;
    // How old a fix may be before we look for a better one. Deliberately
    // tighter than the server's limit, so there is room to get a fresh fix
    // and still post inside it.
    const POSITION_MAX_AGE_MS = 10000;
    // What the SERVER will refuse. Sent by the page; the fallback matches
    // GEOFENCE_MAX_LOCATION_AGE_MS's own default.
    const SERVER_MAX_AGE_MS = Number(config.maxLocationAgeMs) > 0
        ? Number(config.maxLocationAgeMs) : 30000;
    const TRANSIENT_RETRY_LIMIT = 3;
    // How many times we may re-read the same projected code and resubmit on
    // our own after a rejection the student could plausibly fix (an expired
    // code, a GPS fix that was too far out). Past this the camera stops and
    // waits for a deliberate tap. Without the cap a rejected phone re-reads
    // the screen every ~1.2s forever, which is the whole class's worth of
    // wasted requests for the rest of the lecture.
    const AUTO_RESUBMIT_LIMIT = 3;

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
    let resumeTimeoutId = null;
    let bannerTimeoutId = null;
    let latestPosition = null;
    let watchId = null;
    let cameraStartedAt = 0;
    let cameraReadyMs = 0;
    let qrCapturedAt = 0;
    // Wall-clock instant the camera actually decoded the code. Distinct from
    // qrCapturedAt, which is a performance.now() reading used for local
    // timing: the server needs a real timestamp to compare against the
    // token's own, and it must be the moment of the READ — not the moment of
    // the POST, which on a slow GPS fix can be seconds later.
    let qrCapturedAtEpoch = 0;
    let lastDecodeMs = 0;
    let retryAttempt = 0;
    let rejectionStreak = 0;
    let torchEnabled = false;

    function status(message, type) {
        statusBadge.textContent = message;
        statusBadge.className = `status-badge ${type}`;
    }

    function result(message, kind) {
        resultBanner.textContent = message;
        resultBanner.className = `alert mt-3 text-center fw-bold fs-5 alert-${kind}`;
        resultBanner.classList.remove('d-none');
        clearTimeout(bannerTimeoutId);
        bannerTimeoutId = setTimeout(() => resultBanner.classList.add('d-none'), 7000);
    }

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
            position => { latestPosition = position; },
            () => {},        // failures are reported at scan time, not here
            { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
        );
    }

    function stopWatchingLocation() {
        if (watchId === null) return;
        navigator.geolocation.clearWatch(watchId);
        watchId = null;
    }

    function recentPosition() {
        if (!latestPosition) return null;
        return positionAge(latestPosition) <= POSITION_MAX_AGE_MS
            ? latestPosition : null;
    }

    function requestPosition(maximumAge) {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                reject(locationError('Geolocation is not supported by this browser.'));
                return;
            }
            navigator.geolocation.getCurrentPosition(
                position => {
                    latestPosition = position;
                    resolve(position);
                },
                () => reject(locationError(
                    'Location is required. Allow GPS access and scan again.')),
                { enableHighAccuracy: true, timeout: 10000, maximumAge: maximumAge }
            );
        });
    }

    /**
     * A fix the server will accept, or an error saying why not.
     *
     * maximumAge is a hint, not a promise: Android's fused provider hands
     * back a last-known location — minutes or hours old — whenever it cannot
     * get a fresh one, typically indoors, which is exactly where a lecture
     * happens. Posting that earns "Location fix is stale" from the server
     * after a pointless round trip, so ask again with maximumAge: 0 to force
     * a real fix, and only give up when that is stale too.
     */
    async function acquirePosition() {
        const cached = recentPosition();
        if (cached) return cached;

        let position = await requestPosition(POSITION_MAX_AGE_MS);
        if (positionAge(position) > SERVER_MAX_AGE_MS) {
            status('Getting a fresh location...', 'scanning');
            try {
                position = await requestPosition(0);
            } catch (_) {
                // Keep the stale one's error below rather than the timeout's:
                // "your phone gave us an old fix" is the useful sentence.
            }
        }
        if (positionAge(position) > SERVER_MAX_AGE_MS) {
            throw locationError(
                'Your phone is reporting a location from ' +
                `${Math.round(positionAge(position) / 1000)}s ago, which is too ` +
                'old to prove you are in the classroom. Move near a window or ' +
                'step outside for a moment, then scan again.');
        }
        return position;
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

    async function applyCameraSettings() {
        if (!track || !track.getCapabilities) return;
        capabilities = track.getCapabilities() || {};
        const settings = {};
        if (capabilities.focusMode && capabilities.focusMode.includes('continuous')) {
            settings.focusMode = 'continuous';
        }
        if (Object.keys(settings).length) {
            try { await track.applyConstraints({ advanced: [settings] }); } catch (_) {}
        }
        if (capabilities.zoom) {
            const current = track.getSettings().zoom || capabilities.zoom.min || 1;
            zoomSlider.min = capabilities.zoom.min;
            zoomSlider.max = capabilities.zoom.max;
            zoomSlider.step = capabilities.zoom.step || 0.1;
            zoomSlider.value = current;
            zoomLabel.textContent = `${Number(current).toFixed(1)}x`;
        }
    }

    function waitForVideo() {
        if (video.readyState >= 2 && video.videoWidth) return Promise.resolve();
        return new Promise(resolve => video.addEventListener('loadedmetadata', resolve, { once: true }));
    }

    async function startScanner() {
        stopScanner();
        // A deliberate tap is a fresh start: give the automatic-resubmit
        // budget back rather than inheriting the previous attempt's streak.
        rejectionStreak = 0;
        retryAttempt = 0;
        cameraStartedAt = performance.now();
        startWatchingLocation();
        container.style.display = 'block';
        document.body.style.overflow = 'hidden';
        loader.style.display = 'block';
        status('Opening camera...', 'scanning');
        try {
            await configureDetector();
            stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: { ideal: 'environment' },
                    width: { ideal: 1280 },
                    height: { ideal: 720 },
                    focusMode: { ideal: 'continuous' }
                },
                audio: false
            });
            video.srcObject = stream;
            await waitForVideo();
            await video.play();
            track = stream.getVideoTracks()[0];
            await applyCameraSettings();
            cameraReadyMs = performance.now() - cameraStartedAt;
            const settings = track.getSettings();
            cameraInfo.textContent = `${settings.width || video.videoWidth}x${settings.height || video.videoHeight}`;
            loader.style.display = 'none';
            active = true;
            status(detector ? 'Scanning (native detector)...' : 'Scanning...', 'scanning');
            focusIntervalId = setInterval(triggerFocus, 4000);
            animationFrameId = requestAnimationFrame(analyseFrame);
        } catch (error) {
            stopScanner();
            result(`Camera error: ${error.message || error}`, 'danger');
        }
    }

    function stopScanner() {
        active = false;
        decodePending = false;
        // The watch exists to have a fix ready for a scan. With the camera
        // closed there is nothing to scan, and a live GPS watch is one of the
        // most expensive things a page can leave running on a phone.
        stopWatchingLocation();
        clearInterval(focusIntervalId);
        clearTimeout(resumeTimeoutId);
        if (animationFrameId !== null) cancelAnimationFrame(animationFrameId);
        focusIntervalId = resumeTimeoutId = animationFrameId = null;
        if (stream) stream.getTracks().forEach(mediaTrack => mediaTrack.stop());
        stream = track = null;
        video.srcObject = null;
        loader.style.display = 'none';
        container.style.display = 'none';
        document.body.style.overflow = '';
    }

    function drawAnalysisFrame() {
        const fullFrame = frameNumber % 8 === 0;
        const sourceWidth = video.videoWidth;
        const sourceHeight = video.videoHeight;
        const cropSize = fullFrame ? Math.min(sourceWidth, sourceHeight)
            : Math.floor(Math.min(sourceWidth, sourceHeight) * 0.72);
        const sourceX = Math.floor((sourceWidth - cropSize) / 2);
        const sourceY = Math.floor((sourceHeight - cropSize) / 2);
        const outputWidth = Math.min(MAX_ANALYSIS_WIDTH, cropSize);
        const outputHeight = outputWidth;
        if (analysisCanvas.width !== outputWidth || analysisCanvas.height !== outputHeight) {
            analysisCanvas.width = outputWidth;
            analysisCanvas.height = outputHeight;
        }
        context.drawImage(
            video, sourceX, sourceY, cropSize, cropSize,
            0, 0, outputWidth, outputHeight
        );
    }

    async function decodeCurrentFrame() {
        const started = performance.now();
        let value = null;
        if (detector) {
            try {
                const codes = await detector.detect(analysisCanvas);
                value = codes.length ? codes[0].rawValue : null;
            } catch (_) {
                detector = null;
            }
        }
        if (!value && typeof window.jsQR === 'function') {
            const image = context.getImageData(0, 0, analysisCanvas.width, analysisCanvas.height);
            const code = window.jsQR(image.data, image.width, image.height, {
                inversionAttempts: 'dontInvert'
            });
            value = code && code.data;
        }
        lastDecodeMs = performance.now() - started;
        analysisIntervalMs = lastDecodeMs > 80 ? 220 : lastDecodeMs > 40 ? 160 : TARGET_INTERVAL_MS;
        return value;
    }

    async function analyseFrame(now) {
        if (!active) return;
        animationFrameId = requestAnimationFrame(analyseFrame);
        if (decodePending || video.readyState < 2 || now - lastAnalysisAt < analysisIntervalMs) return;
        lastAnalysisAt = now;
        decodePending = true;
        frameNumber += 1;
        try {
            drawAnalysisFrame();
            const value = await decodeCurrentFrame();
            if (value && active) await qrDetected(value);
        } finally {
            decodePending = false;
        }
    }

    async function qrDetected(qrData) {
        active = false;
        qrCapturedAt = performance.now();
        qrCapturedAtEpoch = Date.now();
        scanFrame.classList.add('success');
        status('QR code found', 'success');
        if (navigator.vibrate) navigator.vibrate(120);
        await submitAttendance(qrData);
    }

    function resumeScanning(delayMs) {
        clearTimeout(resumeTimeoutId);
        resumeTimeoutId = setTimeout(() => {
            if (!stream) return;
            scanFrame.classList.remove('success');
            status('Scanning...', 'scanning');
            active = true;
            animationFrameId = requestAnimationFrame(analyseFrame);
        }, delayMs);
    }

    function retryDelay() {
        const base = Math.min(15000, 1500 * (2 ** retryAttempt));
        retryAttempt += 1;
        return Math.floor(base * (0.75 + Math.random() * 0.5));
    }

    async function submitAttendance(qrData) {
        const gpsStarted = performance.now();
        try {
            status('Confirming location...', 'scanning');
            const position = await acquirePosition();
            const gpsWaitMs = performance.now() - gpsStarted;
            const requestStarted = performance.now();
            status('Marking attendance...', 'scanning');
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 20000);
            let response;
            try {
                response = await fetch(config.endpoint || '/mark_attendance', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': config.csrfToken || ''
                    },
                    body: JSON.stringify({
                        qr_data: qrData,
                        lat: position.coords.latitude,
                        lon: position.coords.longitude,
                        accuracy_m: position.coords.accuracy,
                        location_age_ms: Math.max(0, Date.now() - position.timestamp),
                        captured_at: new Date(qrCapturedAtEpoch || Date.now()).toISOString(),
                        user_marker: config.userMarker,
                        device_id: DEVICE_ID,
                        client_metrics: {
                            camera_ready_ms: cameraReadyMs,
                            qr_decode_ms: lastDecodeMs,
                            gps_wait_ms: gpsWaitMs,
                            capture_to_request_ms: requestStarted - qrCapturedAt
                        }
                    }),
                    signal: controller.signal
                });
            } finally {
                clearTimeout(timeout);
            }

            const contentType = response.headers.get('content-type') || '';
            if (!contentType.includes('application/json')) {
                // A non-JSON body from a 4xx is almost always the CSRF guard
                // rejecting a page that has been open longer than the token
                // lives. Retrying cannot fix that; reloading can.
                if (response.status < 500 && response.status !== 429) {
                    retryAttempt = 0;
                    rejectionStreak = 0;
                    result('Your session expired. Reload this page, then scan again.', 'danger');
                    stopScanner();
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const payload = await response.json();

            if (response.ok && payload.status === 'success') {
                retryAttempt = 0;
                rejectionStreak = 0;
                result(payload.message, 'success');
                stopScanner();
                return;
            }
            if (payload.status === 'queued') {
                result(payload.message, 'warning');
                stopScanner();
                return;
            }
            // Server fault or rate limit: back off and try the same code again.
            if (response.status === 429 || response.status >= 500) {
                throw new Error(payload.message || `HTTP ${response.status}`);
            }

            retryAttempt = 0;
            const message = payload.message || 'Attendance could not be marked.';

            // Terminal: nothing about pointing the camera again can change
            // the answer. 403 not enrolled, 404 no such session, 409 already
            // marked or a queued scan from another account.
            if (response.status === 403 || response.status === 404 || response.status === 409) {
                rejectionStreak = 0;
                result(message, 'danger');
                stopScanner();
                return;
            }

            // Recoverable: an expired code (400) or a location problem (422).
            // Give it a bounded number of automatic goes, then hand control
            // back to the student instead of looping forever.
            rejectionStreak += 1;
            if (rejectionStreak >= AUTO_RESUBMIT_LIMIT) {
                rejectionStreak = 0;
                result(`${message} Tap "Start Advanced Scanner" to try again.`, 'danger');
                stopScanner();
                return;
            }
            result(message, 'danger');
            resumeScanning(1200);
        } catch (error) {
            if (error && error.locationProblem) {
                retryAttempt = 0;
                rejectionStreak = 0;
                result(`${error.message} Tap "Start Advanced Scanner" to try again.`,
                       'danger');
                stopScanner();
                return;
            }
            if (retryAttempt < TRANSIENT_RETRY_LIMIT) {
                const delay = retryDelay();
                status(`Network busy; retrying in ${Math.ceil(delay / 1000)}s`, 'error');
                resumeTimeoutId = setTimeout(() => submitAttendance(qrData), delay);
            } else {
                retryAttempt = 0;
                result('Could not reach the server. Check your connection and scan again.', 'danger');
                resumeScanning(1200);
            }
        }
    }

    async function triggerFocus() {
        if (!track || !capabilities.focusMode) return;
        try {
            if (capabilities.focusMode.includes('continuous')) {
                await track.applyConstraints({ advanced: [{ focusMode: 'continuous' }] });
            }
        } catch (_) {}
    }

    zoomSlider.addEventListener('input', async event => {
        if (!track || !capabilities.zoom) return;
        const zoom = Number(event.target.value);
        zoomLabel.textContent = `${zoom.toFixed(1)}x`;
        try { await track.applyConstraints({ advanced: [{ zoom }] }); } catch (_) {}
    });

    torchButton.addEventListener('click', async () => {
        if (!track || !capabilities.torch) {
            result('Flashlight control is not available on this camera.', 'warning');
            return;
        }
        torchEnabled = !torchEnabled;
        try {
            await track.applyConstraints({ advanced: [{ torch: torchEnabled }] });
            torchButton.classList.toggle('active', torchEnabled);
        } catch (_) { torchEnabled = !torchEnabled; }
    });

    focusButton.addEventListener('click', triggerFocus);
    window.addEventListener('pagehide', stopScanner);
    window.startScanner = startScanner;
    window.stopScanner = stopScanner;
}());
