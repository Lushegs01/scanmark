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
    const HUNT_REGIONS = [
        { fraction: 1, width: 512 },
        { fraction: 0.55, width: 720 },
        { fraction: 0.32, width: 720 },
        { fraction: 0.55, width: 720 }
    ];
    const TARGET_INTERVAL_MS = 70;
    // Consecutive frames that find nothing before the scanner changes
    // something about how it is looking. Roughly a second of not finding it.
    const ESCALATE_AFTER_MISSES = 10;
    // Transitions per sampled pixel above which the middle of the frame holds
    // something finely striped — a code too small or too blurred to decode,
    // rather than a wall. Calibrated well above sensor noise.
    const PATTERN_THRESHOLD = 0.03;
    // How old a fix may be before we look for a better one. Deliberately
    // tighter than the server's limit, so there is room to get a fresh fix
    // and still post inside it.
    const POSITION_MAX_AGE_MS = 10000;
    // What the SERVER will refuse. Sent by the page; the fallback matches
    // GEOFENCE_MAX_LOCATION_AGE_MS's own default.
    const SERVER_MAX_AGE_MS = Number(config.maxLocationAgeMs) > 0
        ? Number(config.maxLocationAgeMs) : 30000;
    const TRANSIENT_RETRY_LIMIT = 3;
    //: Marks that this page already reloaded itself once to recover a
    //  session/CSRF mismatch, so it cannot do it again in a loop.
    const RELOADED_FOR_SESSION_KEY = 'scanmark-reloaded-for-session';
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
    // The student tapped the flashlight themselves. The automatic hunt below
    // then leaves it alone — a control that fights the person holding it is
    // worse than no control.
    let torchManual = false;
    let frameCallbackId = null;
    let missStreak = 0;
    let enhancing = false;
    let adapting = false;
    let resolutionRaised = false;

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
        // budget back rather than inheriting the previous attempt's streak,
        // and begin the hunt from an un-adapted camera so a zoom left over
        // from the last room does not narrow this one's first look.
        rejectionStreak = 0;
        retryAttempt = 0;
        missStreak = 0;
        enhancing = false;
        resolutionRaised = false;
        torchManual = false;
        torchEnabled = false;
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
            video.srcObject = stream;
            await waitForVideo();
            await video.play();
            track = stream.getVideoTracks()[0];
            await applyCameraSettings();
            cameraReadyMs = performance.now() - cameraStartedAt;
            announce('');
            loader.style.display = 'none';
            active = true;
            status(detector ? 'Scanning (native detector)...' : 'Scanning...', 'scanning');
            focusIntervalId = setInterval(triggerFocus, 4000);
            scheduleFrame();
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
        if (frameCallbackId !== null && video.cancelVideoFrameCallback) {
            video.cancelVideoFrameCallback(frameCallbackId);
        }
        focusIntervalId = resumeTimeoutId = animationFrameId = frameCallbackId = null;
        if (stream) stream.getTracks().forEach(mediaTrack => mediaTrack.stop());
        stream = track = null;
        video.srcObject = null;
        loader.style.display = 'none';
        container.style.display = 'none';
        document.body.style.overflow = '';
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
        const output = Math.min(region.width, Math.floor(cropSize * MAX_UPSCALE));
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
     * empty screen is not. Counting transitions along a few sampled rows is
     * cheap and separates the two well enough to steer the camera. Lots of
     * transitions and still no decode means a real code that is too small or
     * too blurred — worth zooming into. None means there is nothing here, and
     * zooming would only narrow the search.
     */
    function patternEnergy(grey, width, height) {
        const rows = 16;
        let transitions = 0;
        let sampled = 0;
        for (let row = 1; row <= rows; row++) {
            const y = Math.floor(height * row / (rows + 1)) * width;
            let previous = grey[y];
            for (let x = 1; x < width; x++) {
                const value = grey[y + x];
                if (Math.abs(value - previous) > 40) transitions++;
                previous = value;
            }
            sampled += width;
        }
        return sampled ? transitions / sampled : 0;
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

    async function applyAdvanced(settings) {
        if (!track) return false;
        try {
            await track.applyConstraints({ advanced: [settings] });
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
        if (!range) return false;
        const step = (range.max - range.min) / 4 || range.step || 0.5;
        const current = trackSetting('zoom', range.min || 1);
        const next = Math.min(range.max, Math.max(range.min, current + direction * step));
        if (Math.abs(next - current) < 1e-3) return false;
        if (!await applyAdvanced({ zoom: next })) return false;
        zoomSlider.value = next;
        zoomLabel.textContent = `${Number(next).toFixed(1)}x`;
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
    async function escalate(frame, energy) {
        if (adapting) return;
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
            if (energy > PATTERN_THRESHOLD && await stepZoom(1)) {
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
        try {
            await track.applyConstraints({
                width: { ideal: Math.min(1920, range.max) },
                height: { ideal: 1080 }
            });
        } catch (_) {
            return false;
        }
        resolutionRaised = true;
        return true;
    }

    async function resetOptics() {
        if (capabilities.zoom) {
            const min = capabilities.zoom.min || 1;
            if (await applyAdvanced({ zoom: min })) {
                zoomSlider.value = min;
                zoomLabel.textContent = `${Number(min).toFixed(1)}x`;
            }
        }
        if (capabilities.exposureCompensation) await applyAdvanced({ exposureCompensation: 0 });
        await setTorch(false);
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
        let energy = 0;
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
                    if (deciding) energy = patternEnergy(frame.grey, image.width, image.height);
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
        if (missStreak % ESCALATE_AFTER_MISSES === 0) await escalate(frame, energy);
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
        if (decodePending || video.readyState < 2 || now - lastAnalysisAt < analysisIntervalMs) {
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
        if (value && active) {
            await qrDetected(value);
            return;                 // found: qrDetected owns what happens next
        }
        scheduleFrame();
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
            // The code was found once, so whatever the camera had adapted to
            // was working. Keep it rather than starting the hunt over.
            missStreak = 0;
            scheduleFrame();
        }, delayMs);
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
                // rejecting a page whose token no longer matches the session:
                // the page has been open longer than the token lives, or the
                // session store failed over and the server is now issuing
                // cookie sessions. Retrying cannot fix either; reloading can,
                // because the reloaded page carries a token minted against
                // whatever session the server is using NOW.
                //
                // So do it, rather than asking 2,000 students in a lecture
                // theatre to each read an instruction and tap Reload. Once
                // only: a sessionStorage marker means a fault that survives
                // the reload shows the message instead of looping, and the
                // marker is cleared as soon as a scan gets a real answer.
                if (response.status < 500 && response.status !== 429) {
                    retryAttempt = 0;
                    rejectionStreak = 0;
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
                throw new Error(`HTTP ${response.status}`);
            }
            // A real answer means whatever the reload was for is resolved.
            sessionStorage.removeItem(RELOADED_FOR_SESSION_KEY);

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
            // Server fault or deliberate shedding: back off and try the same
            // code again, at the pace the server asked for where it gave one.
            if (response.status === 429 || response.status >= 500) {
                const error = new Error(payload.message || `HTTP ${response.status}`);
                error.retryAfterMs = serverRetryDelay(response);
                throw error;
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
                retryAttempt += 1;
                const delay = error && error.retryAfterMs !== null
                    && error.retryAfterMs !== undefined
                    ? error.retryAfterMs
                    : Math.floor(Math.min(15000, 1500 * (2 ** (retryAttempt - 1)))
                                 * (0.75 + Math.random() * 0.5));
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
        // From here on the hunt stops touching the torch: whatever the student
        // chose, they can see the result and the code cannot.
        torchManual = true;
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
