/*
 * Mark attendance by typing the eight-digit code shown under the QR.
 *
 * For a student whose camera cannot read the projector: broken, blocked,
 * unfocusable, absent, or simply too far away. Nothing here asks for the
 * camera. Location is still required, because the server applies the same
 * classroom geofence it applies to a scan.
 *
 * What it promises the student:
 *   - "Attendance successfully marked" appears ONLY after the server has
 *     written the record and said so. Nothing is queued for later replay:
 *     a code is only good for about a minute, so a submission that cannot
 *     reach the server is reported as NOT recorded, and the student types
 *     the current code once they have signal.
 *   - One request at a time. A second tap while one is in flight does
 *     nothing; the button stays disabled until there is an answer.
 *   - Every refusal says what to do next: type the new code, choose the
 *     class, move towards a window, wait out a lockout.
 *
 * The pure helpers at the top are exported for the Node unit tests
 * (test_manual_code_browser.cjs); the DOM wiring below them runs only in a
 * browser page that has the form.
 */
'use strict';

const CODE_LENGTH = 8;

/** The digits of whatever was typed or pasted, at most eight. */
function codeDigits(text) {
    return String(text == null ? '' : text).replace(/\D/g, '').slice(0, CODE_LENGTH);
}

/** True when the text holds something other than digits and separators. */
function hasStrayCharacters(text) {
    return /[^\d\s\- .]/.test(String(text == null ? '' : text));
}

/** '48269137' -> '4826 9137'; partial input groups as it grows. */
function formatCode(digits) {
    const clean = codeDigits(digits);
    return clean.length > 4 ? `${clean.slice(0, 4)} ${clean.slice(4)}` : clean;
}

/**
 * Where the caret belongs after reformatting: just after the same number
 * of digits it was after before. Keeps typing and correcting in the middle
 * of the code natural instead of throwing the caret to the end.
 */
function caretForDigits(formatted, digitsBefore) {
    if (digitsBefore <= 0) return 0;
    let seen = 0;
    for (let index = 0; index < formatted.length; index++) {
        if (/\d/.test(formatted[index])) {
            seen += 1;
            if (seen === digitsBefore) return index + 1;
        }
    }
    return formatted.length;
}

function digitsBeforeCaret(text, caret) {
    return codeDigits(String(text).slice(0, Math.max(0, caret))).length;
}

const LOCATION_REFUSALS = new Set(['outside_geofence', 'imprecise_location', 'stale_location']);
const BUSY_OUTCOMES = new Set(['admission_throttled', 'database_saturated']);
const TERMINAL_OUTCOMES = new Set([
    'not_enrolled', 'not_student', 'session_ended', 'course_archived',
    'manual_code_disabled', 'wrong_user', 'not_authenticated',
]);

/**
 * What the page should do with one response, from its status and JSON.
 *
 * Kinds:
 *   success        recorded (or already recorded by this same submission)
 *   already        recorded earlier — by QR or code — so nothing to do
 *   wrong_code     re-type it; maybe now locked out
 *   expired        the code rotated; type the new one
 *   format         not eight digits
 *   choose         several classes open: pick one
 *   no_session     nothing open for this student right now
 *   location       the fix was refused; may retry with a fresh one
 *   locked         too many wrong codes: wait `retryAfterSeconds`
 *   unavailable    the server cannot check codes (fail-closed): wait, or scan
 *   busy           shedding load: retry after the server's delay
 *   csrf           the page's form token expired; a fresh one is attached
 *   terminal       nothing typing again can change
 *   error          an unexpected failure; the student may try again
 */
function classifyResponse(status, payload, attempts) {
    const body = payload || {};
    const outcome = body.outcome || '';
    const retryAfterSeconds = Number(body.retry_after_seconds) || 0;
    if (status === 200 && body.status === 'success') return { kind: 'success' };
    if (outcome === 'duplicate') {
        // Our own earlier attempt landed and only its answer was lost (slow
        // network, a dropped connection): to the student, that is success.
        return { kind: attempts > 1 ? 'success' : 'already' };
    }
    if (outcome === 'csrf_expired' && body.csrf_token) return { kind: 'csrf' };
    if (outcome === 'invalid_code') {
        return { kind: 'wrong_code', retryAfterSeconds,
                 attemptsRemaining: Number(body.attempts_remaining) };
    }
    if (outcome === 'code_expired') return { kind: 'expired' };
    if (outcome === 'invalid_code_format') return { kind: 'format' };
    if (outcome === 'session_required') return { kind: 'choose', sessions: body.sessions || [] };
    if (outcome === 'no_active_session') return { kind: 'no_session' };
    if (status === 422) return { kind: 'location', outcome };
    if (outcome === 'verification_unavailable') return { kind: 'unavailable', retryAfterSeconds };
    if (outcome === 'rate_limited') {
        // The wrong-code lockout says how long; the request limiter sends
        // `retry_after` (seconds) instead.
        return { kind: 'locked',
                 retryAfterSeconds: retryAfterSeconds || Number(body.retry_after) || 60 };
    }
    if (BUSY_OUTCOMES.has(outcome) || status === 429 || status >= 500 && outcome !== 'server_error') {
        return { kind: 'busy' };
    }
    if (TERMINAL_OUTCOMES.has(outcome) || status === 401 || status === 403 || status === 409) {
        return { kind: 'terminal', outcome };
    }
    return { kind: 'error', outcome };
}

function formatWait(seconds) {
    const total = Math.max(0, Math.ceil(seconds));
    const minutes = Math.floor(total / 60);
    return minutes ? `${minutes}:${String(total % 60).padStart(2, '0')}` : `${total}s`;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        codeDigits, hasStrayCharacters, formatCode, caretForDigits,
        digitsBeforeCaret, classifyResponse, formatWait,
    };
}

// ===========================================================================
// The page
// ===========================================================================

if (typeof document !== 'undefined') (function () {
    const config = window.SCANMARK_MANUAL_CONFIG;
    const shared = window.ScanMarkAttendance;
    const form = document.getElementById('manualCodeForm');
    if (!config || !shared || !form) return;

    const card = document.getElementById('attendance-code');
    const input = document.getElementById('manualCodeInput');
    const button = document.getElementById('manualCodeSubmit');
    const buttonLabel = button.querySelector('[data-label]');
    const spinner = button.querySelector('[data-spinner]');
    const feedback = document.getElementById('manualCodeFeedback');
    const sessionArea = document.getElementById('manualSession');

    // One request's patience. A 2G POST on a cold connection is a few
    // seconds; past this it is more likely stuck behind a dead radio than
    // slow, and the student is better told so while the code still works.
    const REQUEST_TIMEOUT_MS = 15000;
    // Automatic retries when the SERVER asked us to come back (shedding,
    // saturation). Bounded: the code in hand only lives about a minute.
    const BUSY_RETRY_LIMIT = 4;
    // A fresh fix after a refused one, as the scanner does: indoor fixes
    // drift, and the next one is often much closer to the truth.
    const LOCATION_RETRY_LIMIT = 2;
    // One quiet retry after a dropped connection. The server is idempotent
    // (one record per student per class), so a retry of a request that DID
    // land is answered "already marked" and shown as the success it is.
    const NETWORK_RETRY_LIMIT = 1;

    const locator = shared.createLocator({
        maxLocationAgeMs: config.maxLocationAgeMs,
        maxLocationAccuracyM: config.maxLocationAccuracyM,
        retryHint: 'try again',
        // Refused as soon as the student focused the box: tell them before
        // they type eight digits that cannot be submitted.
        onDenied: () => {
            if (!inFlight) show(locator.describeError({ code: 1 }), 'danger');
        },
    });

    let sessions = null;          // the student's open classes, once loaded
    let sessionsLoading = null;
    let chosenSessionId = null;
    let inFlight = false;
    let lockedUntil = 0;
    let lockTimer = null;
    let started = false;

    // ---- Small DOM helpers -------------------------------------------------

    function setBusy(busy, message) {
        button.disabled = busy || Date.now() < lockedUntil;
        button.setAttribute('aria-busy', busy ? 'true' : 'false');
        spinner.classList.toggle('d-none', !busy);
        buttonLabel.textContent = busy ? 'Submitting…' : 'Submit Code';
        input.readOnly = busy;
        if (message) show(message, 'progress');
    }

    /**
     * Put a message in the status region. `kind` is one of progress,
     * success, info, warning, danger. Built from text nodes only: server
     * messages are never treated as HTML.
     */
    function show(message, kind, details) {
        feedback.replaceChildren();
        feedback.className = `manual-feedback is-${kind}`;
        const line = document.createElement('p');
        line.className = 'manual-feedback-message';
        line.textContent = message;
        feedback.appendChild(line);
        (details || []).forEach(detail => {
            const extra = document.createElement('p');
            extra.className = 'manual-feedback-detail';
            extra.textContent = detail;
            feedback.appendChild(extra);
        });
        feedback.classList.remove('d-none');
    }

    function markInvalid(invalid) {
        if (invalid) input.setAttribute('aria-invalid', 'true');
        else input.removeAttribute('aria-invalid');
    }

    function focusCode(selectAll) {
        input.focus();
        if (selectAll && input.value) input.setSelectionRange(0, input.value.length);
    }

    // ---- The code box ------------------------------------------------------

    function reformat(digitsAtCaret) {
        const formatted = formatCode(input.value);
        if (input.value !== formatted) input.value = formatted;
        if (document.activeElement === input && digitsAtCaret !== undefined) {
            const caret = caretForDigits(formatted, digitsAtCaret);
            input.setSelectionRange(caret, caret);
        }
    }

    input.addEventListener('beforeinput', event => {
        // Backspace just after the space (or Delete just before it) would
        // remove the separator, which reformatting puts straight back — so
        // the key would seem dead. Remove the digit on the far side instead.
        const start = input.selectionStart;
        const end = input.selectionEnd;
        if (start !== end || start === null) return;
        const value = input.value;
        let digitIndex = null;
        if (event.inputType === 'deleteContentBackward' && value[start - 1] === ' ') {
            digitIndex = digitsBeforeCaret(value, start) - 1;
        } else if (event.inputType === 'deleteContentForward' && value[start] === ' ') {
            digitIndex = digitsBeforeCaret(value, start);
        }
        if (digitIndex === null || digitIndex < 0) return;
        event.preventDefault();
        const digits = codeDigits(value);
        input.value = formatCode(digits.slice(0, digitIndex) + digits.slice(digitIndex + 1));
        const caret = caretForDigits(input.value, digitIndex);
        input.setSelectionRange(caret, caret);
        markInvalid(false);
    });

    input.addEventListener('input', () => {
        const raw = input.value;
        const caretDigits = digitsBeforeCaret(raw, input.selectionStart === null
            ? raw.length : input.selectionStart);
        if (hasStrayCharacters(raw)) {
            show('The code is numbers only — letters and symbols are ignored.', 'info');
        } else if (feedback.classList.contains('is-info')) {
            feedback.classList.add('d-none');
        }
        markInvalid(false);
        reformat(Math.min(caretDigits, CODE_LENGTH));
    });

    // Start the location fix and fetch the class list the moment the student
    // shows intent, so by the time eight digits are typed both are ready —
    // the code only lives a minute, and a cold GPS can take ten seconds.
    function begin() {
        if (started) return;
        started = true;
        locator.startWatching();
        loadSessions();
    }
    // Focus, not touch: a finger landing on the card to scroll past it is not
    // a reason to ask for location.
    form.addEventListener('focusin', begin);

    // ---- Which class -------------------------------------------------------

    function describeSession(entry) {
        const when = entry.started_at_local ? ` · started ${entry.started_at_local}` : '';
        return `${entry.course_code} — ${entry.course_title}${when}`;
    }

    function renderSessions(list, message) {
        sessions = list;
        sessionArea.replaceChildren();
        const open = list.filter(entry => !entry.already_marked);
        if (message) {
            const note = document.createElement('p');
            note.className = 'small mb-2';
            note.textContent = message;
            sessionArea.appendChild(note);
        }
        if (list.length === 0) {
            chosenSessionId = null;
            const none = document.createElement('p');
            none.className = 'manual-session-line small mb-2';
            none.textContent = 'None of your classes is taking attendance right now. ' +
                'Once your lecturer starts the class, enter the code from the screen.';
            sessionArea.append(none, refreshButton());
            return;
        }
        if (list.length === 1) {
            const entry = list[0];
            chosenSessionId = entry.session_id;
            const line = document.createElement('p');
            line.className = 'manual-session-line small mb-2';
            if (entry.already_marked) {
                line.textContent = `You are already marked present for ${entry.course_code}` +
                    ` (${entry.submission_method_label || 'recorded'}` +
                    `${entry.marked_at_local ? ` at ${entry.marked_at_local}` : ''}). Nothing more to do.`;
                line.classList.add('is-done');
            } else {
                const label = document.createElement('span');
                label.className = 'fw-semibold';
                label.textContent = 'Class: ';
                line.append(label, document.createTextNode(describeSession(entry)));
            }
            sessionArea.appendChild(line);
            return;
        }
        // Several classes are open. Never guess between them: the student
        // chooses, and an already-marked one is shown but cannot be chosen.
        const label = document.createElement('label');
        label.className = 'form-label fw-semibold mb-1';
        label.htmlFor = 'manualSessionSelect';
        label.textContent = 'Which class are you in?';
        const select = document.createElement('select');
        select.id = 'manualSessionSelect';
        select.className = 'form-select mb-2';
        select.required = true;
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = 'Choose your class…';
        select.appendChild(placeholder);
        list.forEach(entry => {
            const option = document.createElement('option');
            option.value = String(entry.session_id);
            option.textContent = entry.already_marked
                ? `${entry.course_code} — already marked (${entry.submission_method_label || 'recorded'})`
                : describeSession(entry);
            option.disabled = Boolean(entry.already_marked);
            select.appendChild(option);
        });
        const keep = list.find(entry => String(entry.session_id) === String(chosenSessionId)
                               && !entry.already_marked);
        chosenSessionId = keep ? keep.session_id : (open.length === 1 && list.length === 1
            ? open[0].session_id : null);
        select.value = chosenSessionId ? String(chosenSessionId) : '';
        select.addEventListener('change', () => {
            chosenSessionId = select.value ? Number(select.value) : null;
            select.removeAttribute('aria-invalid');
        });
        sessionArea.append(label, select);
    }

    function refreshButton() {
        const again = document.createElement('button');
        again.type = 'button';
        again.className = 'btn btn-outline-success btn-sm mb-2';
        again.textContent = 'Check again';
        again.addEventListener('click', () => loadSessions(true));
        return again;
    }

    async function loadSessions(force) {
        if (sessionsLoading && !force) return sessionsLoading;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        sessionsLoading = (async () => {
            try {
                const response = await fetch(config.sessionsUrl, {
                    headers: { Accept: 'application/json' },
                    credentials: 'same-origin', cache: 'no-store',
                    signal: controller.signal,
                });
                if (!response.ok) return;
                const data = await response.json();
                if (data && Array.isArray(data.sessions)) renderSessions(data.sessions);
            } catch (_) {
                // No list is not fatal: with one open class the server works
                // out which it is on its own.
            } finally {
                clearTimeout(timeout);
                sessionsLoading = null;
            }
        })();
        return sessionsLoading;
    }

    // ---- Lockout -----------------------------------------------------------

    function lockFor(seconds, message) {
        lockedUntil = Date.now() + seconds * 1000;
        clearInterval(lockTimer);
        const tick = () => {
            const left = (lockedUntil - Date.now()) / 1000;
            if (left <= 0) {
                clearInterval(lockTimer);
                lockTimer = null;
                lockedUntil = 0;
                button.disabled = inFlight;
                buttonLabel.textContent = 'Submit Code';
                return;
            }
            button.disabled = true;
            buttonLabel.textContent = `Try again in ${formatWait(left)}`;
        };
        tick();
        lockTimer = setInterval(tick, 1000);
        show(message, 'warning');
    }

    // ---- Submitting --------------------------------------------------------

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async function post(submission, position) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        try {
            const body = {
                code: submission.code,
                user_marker: config.userMarker,
                device_id: shared.deviceId(),
                ...locator.payload(position),
            };
            if (submission.sessionId) body.session_id = submission.sessionId;
            return await fetch(config.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                    'X-CSRFToken': config.csrfToken || '',
                },
                credentials: 'same-origin',
                cache: 'no-store',
                body: JSON.stringify(body),
                signal: controller.signal,
            });
        } finally {
            clearTimeout(timeout);
        }
    }

    function finish() {
        inFlight = false;
        setBusy(false);
    }

    function succeed(payload) {
        finish();
        const course = payload.course_code || 'your class';
        const details = [];
        if (payload.course_title) details.push(payload.course_title);
        const when = payload.marked_at_local ? `at ${payload.marked_at_local}` : '';
        details.push(['Recorded', when, '· attendance code'].filter(Boolean).join(' '));
        show(`Attendance successfully marked for ${course}.`, 'success', details);
        shared.bumpAttendance(payload.course_code);
        input.value = '';
        markInvalid(false);
        locator.stopWatching();
        if (sessions) {
            sessions = sessions.map(entry => (
                entry.session_id === payload.session_id
                    ? { ...entry, already_marked: true,
                        submission_method_label: 'Manual code',
                        marked_at_local: payload.marked_at_local }
                    : entry));
            renderSessions(sessions);
        }
        // Move focus to the confirmation so a screen reader reads it.
        feedback.setAttribute('tabindex', '-1');
        feedback.focus({ preventScroll: true });
    }

    async function run(submission) {
        let position;
        try {
            position = await locator.acquire(submission.refusedFixAt, best => setBusy(true, best
                ? `Sharpening your location (±${Math.round(best.coords.accuracy)}m)…`
                : 'Finding your location…'));
        } catch (error) {
            finish();
            show(error && error.locationProblem ? error.message
                : 'Your location could not be read. Allow location for this site and try again.',
                 'danger');
            return;
        }

        setBusy(true, 'Marking attendance…');
        submission.attempts += 1;
        let response;
        try {
            response = await post(submission, position);
        } catch (_) {
            if (submission.networkRetries < NETWORK_RETRY_LIMIT && navigator.onLine !== false) {
                submission.networkRetries += 1;
                setBusy(true, 'Connection dropped; trying once more…');
                await sleep(1500);
                return run(submission);
            }
            finish();
            show('No connection — your attendance was NOT recorded.', 'danger',
                 ['Check your signal, then press Submit Code again. If the code on the ' +
                  'screen has changed, enter the new one.']);
            return;
        }

        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            finish();
            if (response.status >= 500 || response.status === 429) {
                show('ScanMark is busy — your attendance was not recorded. Try again in a moment.',
                     'warning');
            } else {
                show('Your session has expired. Reload this page, then enter the code again.',
                     'danger');
            }
            return;
        }
        let payload;
        try {
            payload = await response.json();
        } catch (_) {
            finish();
            show('ScanMark sent an answer this page could not read. Your attendance was not ' +
                 'recorded; please try again.', 'danger');
            return;
        }
        handle(submission, response, payload, position);
    }

    function handle(submission, response, payload, position) {
        const verdict = classifyResponse(response.status, payload, submission.attempts);
        const message = payload.message || 'Attendance could not be marked.';
        switch (verdict.kind) {
        case 'success':
            succeed(payload);
            return;
        case 'already': {
            finish();
            const how = payload.submission_method_label
                ? ` (${payload.submission_method_label}` +
                  `${payload.marked_at_local ? ` at ${payload.marked_at_local}` : ''})` : '';
            show(`You are already marked present for ${payload.course_code || 'this class'}${how}.`,
                 'success', ['Nothing more to do.']);
            input.value = '';
            return;
        }
        case 'csrf':
            if (submission.csrfRefreshes < 2) {
                submission.csrfRefreshes += 1;
                config.csrfToken = payload.csrf_token;
                run(submission);
                return;
            }
            finish();
            show('Your session has expired. Reload this page, then enter the code again.', 'danger');
            return;
        case 'wrong_code':
            finish();
            markInvalid(true);
            if (verdict.retryAfterSeconds) {
                lockFor(verdict.retryAfterSeconds, message);
            } else {
                show(message, 'danger');
            }
            focusCode(true);
            return;
        case 'expired':
            finish();
            input.value = '';
            markInvalid(true);
            show(message, 'warning');
            focusCode(false);
            return;
        case 'format':
            finish();
            markInvalid(true);
            show(message, 'danger');
            focusCode(false);
            return;
        case 'choose':
            finish();
            renderSessions(verdict.sessions, message);
            show('Choose your class, then press Submit Code.', 'warning');
            {
                const select = document.getElementById('manualSessionSelect');
                if (select) select.focus();
            }
            return;
        case 'no_session':
            finish();
            renderSessions([]);
            show(message, 'warning');
            return;
        case 'location': {
            const distance = Number(payload.distance_m);
            const radius = Number(payload.radius_m);
            // Kilometres off is not drift; it is somewhere else.
            const elsewhere = payload.outcome === 'outside_geofence'
                && Number.isFinite(distance) && Number.isFinite(radius)
                && distance - radius > Math.max(150, 3 * (position.coords.accuracy || 0));
            if (LOCATION_REFUSALS.has(verdict.outcome) && !elsewhere
                    && submission.locationRetries < LOCATION_RETRY_LIMIT) {
                submission.locationRetries += 1;
                submission.refusedFixAt = locator.fixId(position);
                setBusy(true, 'Your location reading was off; taking a fresh one…');
                setTimeout(() => run(submission), 250);
                return;
            }
            finish();
            show(message, 'danger', ['Your attendance was not recorded.']);
            return;
        }
        case 'locked':
            finish();
            markInvalid(false);
            lockFor(verdict.retryAfterSeconds, message);
            return;
        case 'unavailable':
            finish();
            lockFor(Math.min(60, verdict.retryAfterSeconds || 15), message);
            return;
        case 'busy': {
            if (submission.busyRetries < BUSY_RETRY_LIMIT) {
                submission.busyRetries += 1;
                const delay = shared.serverRetryDelay(response)
                    || Math.floor(1000 * 2 ** submission.busyRetries * (0.75 + Math.random() * 0.5));
                setBusy(true, `ScanMark is busy; trying again in ${Math.max(1, Math.round(delay / 1000))}s…`);
                setTimeout(() => run(submission), delay);
                return;
            }
            finish();
            show('ScanMark is very busy — your attendance was not recorded yet.', 'warning',
                 ['Press Submit Code again in a moment, or scan the QR code.']);
            return;
        }
        case 'terminal':
            finish();
            show(message, 'danger');
            return;
        default:
            finish();
            show(message, 'danger', ['Your attendance was not recorded. Please try again.']);
        }
    }

    form.addEventListener('submit', event => {
        event.preventDefault();
        if (inFlight || Date.now() < lockedUntil) return;
        begin();
        const code = codeDigits(input.value);
        if (code.length !== CODE_LENGTH) {
            markInvalid(true);
            show(code.length
                ? `That is ${code.length} digit${code.length === 1 ? '' : 's'}. Enter all 8 digits of the code.`
                : 'Enter the 8-digit code shown under the QR on the screen.', 'danger');
            focusCode(false);
            return;
        }
        const select = document.getElementById('manualSessionSelect');
        if (select && !chosenSessionId) {
            select.setAttribute('aria-invalid', 'true');
            show('Choose your class first.', 'danger');
            select.focus();
            return;
        }
        if (sessions && sessions.length === 1 && sessions[0].already_marked) {
            show(`You are already marked present for ${sessions[0].course_code}. Nothing more to do.`,
                 'success');
            return;
        }
        inFlight = true;
        setBusy(true, 'Checking your location…');
        run({
            code,
            sessionId: chosenSessionId,
            attempts: 0,
            locationRetries: 0,
            networkRetries: 0,
            busyRetries: 0,
            csrfRefreshes: 0,
            refusedFixAt: 0,
        });
    });

    // The scanner could not open a camera: this is the way in instead.
    window.addEventListener('scanmark:camera-unavailable', () => {
        if (card) card.classList.add('is-suggested');
        begin();
    });

    // Arriving from the scan page's "enter the code instead" link.
    if (window.location.hash === '#attendance-code') {
        setTimeout(() => focusCode(false), 0);
    }
}());
