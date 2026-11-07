// Injected by the /service-worker.js route from the server's hash of
// everything in static/. Naming the cache after it means a deploy that
// changes an asset lands in a NEW cache and deletes the old one on
// activate — the hand-edited 'v3' before this could not do that, so a
// stylesheet cached under it outlived every deploy that followed.
const ASSET_VERSION = self.SCANMARK_ASSET_VERSION || 'dev';
const CACHE_NAME = `scanmark-cache-${ASSET_VERSION}`;
// The student pages, kept so the scanner opens with no signal at all. Not
// versioned with the assets: a deploy should not throw away the one copy a
// student underground has.
const PAGE_CACHE = 'scanmark-pages-v1';

// What the scanner needs to start with no network, fetched once in the
// background after the first visit. Pages ask for these with ?v=<hash>.
const PRECACHE_VERSIONED = [
    '/static/style.css',
    '/static/attendance-common.js',
    '/static/scanner.js',
    '/static/manual-code.js',
    '/static/vendor/jsQR.min.js',
    '/static/vendor/bootstrap/bootstrap.min.css',
    '/static/vendor/bootstrap/bootstrap.bundle.min.js',
    '/static/vendor/poppins/poppins.css',
    '/static/vendor/fontawesome/css/all.min.css',
    '/static/logo-192.png'
];
// Asked for by bare path: by the manifest, and by the stylesheets above
// (a font URL inside a stylesheet carries no ?v=).
const PRECACHE_BARE = [
    '/static/manifest.json',
    '/static/logo.png',
    '/static/logo-192.png',
    '/static/vendor/fontawesome/webfonts/fa-solid-900.woff2',
    '/static/vendor/poppins/poppins-400-latin.woff2',
    '/static/vendor/poppins/poppins-600-latin.woff2',
    '/static/vendor/poppins/poppins-700-latin.woff2'
];
const OFFLINE_PAGES = ['/student_dashboard', '/scan_page'];
// How long a page load waits on the network before the saved copy is shown
// instead. Long enough that a merely slow 2G answer still wins.
const PAGE_NETWORK_TIMEOUT_MS = 7000;

const versioned = path => `${path}?v=${ASSET_VERSION}`;

self.addEventListener('install', event => {
    self.skipWaiting();
    // Fetched at the versioned URL, so the browser's own HTTP cache cannot
    // hand the install a copy from the previous deploy. One at a time and
    // each on its own: addAll() fails the whole install if any single file
    // does, which left a phone with no worker at all over one font.
    event.waitUntil(caches.open(CACHE_NAME).then(async cache => {
        for (const url of PRECACHE_VERSIONED.map(versioned).concat(PRECACHE_BARE)) {
            try {
                await cache.add(url);
            } catch (_) { /* fetched on first use instead */ }
        }
    }));
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys.filter(key => key !== CACHE_NAME && key !== PAGE_CACHE)
                .map(key => caches.delete(key))
        )).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', event => {
    const request = event.request;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;
    if (url.pathname === '/mark_attendance' && request.method === 'POST') {
        event.respondWith(handleAttendanceRequest(event));
        return;
    }
    // POST /api/attendance/manual is deliberately NOT queued here. A typed
    // code lives about a minute, so an offline replay could only be refused
    // later — after the page had implied it might still count. It goes
    // straight to the network (below: non-GETs pass through), and the page
    // says plainly that nothing was recorded if it cannot get there.
    if (url.pathname === '/logout' && request.method === 'POST') {
        // Never show the next person on this phone the last one's page.
        event.waitUntil(caches.delete(PAGE_CACHE));
        return;
    }
    if (request.method !== 'GET') return;
    if (request.mode === 'navigate' && OFFLINE_PAGES.includes(url.pathname)) {
        event.respondWith(networkFirstPage(event));
        return;
    }
    if (url.pathname.startsWith('/static/')) {
        event.respondWith(isImmutable(url) ? cacheFirst(event) : staleWhileRevalidate(event));
    }
});

/**
 * Whether this URL's bytes can never change under it: anything carrying
 * this deploy's ?v= hash, and the vendored libraries (a new version goes in
 * under a new path, never over the old one).
 */
function isImmutable(url) {
    return url.searchParams.get('v') === ASSET_VERSION ||
        url.pathname.startsWith('/static/vendor/');
}

/**
 * From the cache with no network at all, once it is there.
 *
 * This used to be stale-while-revalidate for everything, so every page view
 * re-requested every script and stylesheet in the background — on a shared
 * 2G cell, competing with the very scan the page was opened for, to fetch
 * files whose URL guarantees they have not changed.
 *
 * The match is deliberately exact — NOT ignoreSearch. During a deploy the
 * outgoing worker is still the one answering, and with ignoreSearch its
 * previous-version entry happily answers a request for the new ?v=, which
 * is the whole bug: the page asks for the new stylesheet and is handed the
 * old one. An exact match misses, so the request reaches the network.
 */
async function cacheFirst(event) {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(event.request);
    if (cached) return cached;
    const response = await fetch(event.request);
    if (response && response.ok && response.type === 'basic') {
        event.waitUntil(cache.put(event.request, response.clone()));
    }
    return response;
}

/**
 * Answer from the cache so a scan still works underground, but refetch in
 * the background, so the worst a changed unversioned file can cost is one
 * page load.
 */
function staleWhileRevalidate(event) {
    const request = event.request;
    return caches.open(CACHE_NAME).then(cache =>
        cache.match(request).then(cached => {
            const network = fetch(request).then(response => {
                if (response && response.ok) cache.put(request, response.clone());
                return response;
            });
            if (cached) {
                event.waitUntil(network.catch(() => {}));
                return cached;
            }
            return network.catch(() => cached);
        })
    );
}

/**
 * The live page whenever the network answers; the last good copy when it
 * does not — no signal, or nothing back within PAGE_NETWORK_TIMEOUT_MS.
 *
 * The copy is marked so the page can say it is a saved one. It still works
 * for scanning: the scan itself always goes to the server, and a form token
 * that has aged out is replaced by the server's own refusal (csrf_expired).
 * A redirect (signed out, profile incomplete) is never saved, and drops the
 * saved copies: whatever they showed no longer applies.
 */
async function networkFirstPage(event) {
    const request = event.request;
    const cache = await caches.open(PAGE_CACHE);
    const network = fetch(request).then(async response => {
        if (response.ok && !response.redirected && response.type === 'basic') {
            await cache.put(request.url.split('?')[0], response.clone());
        } else if (response.redirected || response.type === 'opaqueredirect') {
            await caches.delete(PAGE_CACHE);
        }
        return response;
    });
    event.waitUntil(network.catch(() => {}));
    const saved = () => cache.match(request.url.split('?')[0]).then(markSaved);
    const timeout = new Promise(resolve => setTimeout(resolve, PAGE_NETWORK_TIMEOUT_MS, null));
    try {
        const first = await Promise.race([network, timeout.then(saved)]);
        if (first) return first;
        return await network;           // no saved copy: keep waiting
    } catch (_) {
        const copy = await saved();
        if (copy) return copy;
        throw _;
    }
}

async function markSaved(response) {
    if (!response) return null;
    const html = await response.text();
    // The original headers, so the copy keeps its Content-Security-Policy
    // and friends — minus the ones describing the bytes, which are now
    // decoded and edited.
    const headers = new Headers(response.headers);
    headers.delete('Content-Encoding');
    headers.delete('Content-Length');
    return new Response(
        html.replace('<head>', '<head><meta name="scanmark-saved-copy" content="1">'),
        { status: 200, headers });
}

// ---------------------------------------------------------------------------
// SCANS THAT COULD NOT BE SENT
// ---------------------------------------------------------------------------

// The server refuses a scanned token older than this, checked when the
// request is PROCESSED. Injected by the /service-worker.js route from the
// server's own QR_CODE_WINDOW so the two can never drift apart.
const QR_WINDOW_SECONDS = self.SCANMARK_QR_WINDOW_SECONDS || 45;
const SYNC_TAG = 'scanmark-scans';

/**
 * The moment the server will stop accepting this token, in epoch ms.
 * Tokens look like "S<session>|<issued-unix-seconds>|<signature>".
 * Returns null when the payload is not a token we can read.
 */
function tokenDeadline(qrData) {
    const parts = String(qrData || '').split('|');
    if (parts.length !== 3) return null;
    const issuedSeconds = Number(parts[1]);
    if (!Number.isFinite(issuedSeconds)) return null;
    return (issuedSeconds + QR_WINDOW_SECONDS) * 1000;
}

/** One stored scan per student per class: a newer code replaces an older. */
function queueKey(data) {
    const session = String(data.qr_data || '').split('|')[0] || 'unknown';
    return `${data.user_marker || 'anonymous'}:${session.replace(/^S/, '')}`;
}

function jsonResponse(body, status) {
    return new Response(JSON.stringify(body), {
        status: status,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
}

/** An answer from ScanMark itself, as opposed to "try again later". */
function isDefinitive(response) {
    const type = response.headers.get('content-type') || '';
    return type.includes('application/json') && response.status !== 429 &&
        response.status < 500;
}

/**
 * Pass every scan straight through; keep a copy only when there was no
 * network to send it on.
 *
 * Every HTTP answer goes back to the page untouched — including 429 and 503,
 * which carry the Retry-After the scanner paces itself by. This used to turn
 * any 5xx into "No connection. This scan is saved…", which hid the server's
 * pacing from the scanner AND stopped it, so a database that was merely
 * busy for two seconds cost students their scan.
 */
async function handleAttendanceRequest(event) {
    const request = event.request;
    const body = await request.clone().text();
    const csrf = request.headers.get('X-CSRFToken') || '';
    let data = null;
    try { data = JSON.parse(body); } catch (_) { /* not ours to store */ }
    try {
        const response = await fetch(request);
        if (data && isDefinitive(response)) {
            event.waitUntil(dropQueued(queueKey(data)));
        }
        return response;
    } catch (_) {
        if (!data) return jsonResponse({ status: 'error', message: 'No connection.' }, 503);
        const deadline = tokenDeadline(data.qr_data);
        const remainingMs = deadline === null ? 0 : deadline - Date.now();
        // Queueing a code the server will already refuse is worse than
        // failing here: it looks like success and silently isn't.
        if (remainingMs <= 0) {
            return jsonResponse({
                status: 'error', outcome: 'offline_expired',
                message: 'No connection, and this code has expired. Reconnect, then scan the new code on screen.'
            }, 400);
        }
        data.queued_at = new Date().toISOString();
        data.expires_at = deadline;
        await storeScan({ key: queueKey(data), data, csrf });
        // Retry from here as well, so the scan still goes if the page is
        // closed: Background Sync where the browser has it (it fires when
        // the network returns, even with no page open), and a short loop
        // inside this event's lifetime everywhere else.
        if (self.registration.sync) {
            self.registration.sync.register(SYNC_TAG).catch(() => {});
        }
        event.waitUntil(drainUntilDeadline(deadline));
        return jsonResponse({
            status: 'queued', outcome: 'queued',
            message: 'No connection yet. Your scan is saved and is being sent ' +
                'automatically — keep this page open until it is confirmed.',
            expires_at: deadline
        }, 202);
    }
}

self.addEventListener('sync', event => {
    if (event.tag === SYNC_TAG) event.waitUntil(drainQueue());
});

self.addEventListener('message', event => {
    if (event.data && event.data.type === 'flush') event.waitUntil(drainQueue());
});

async function drainUntilDeadline(deadline) {
    let delay = 2000;
    while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, delay));
        const remaining = await drainQueue();
        if (!remaining) return;
        delay = Math.min(delay * 2, 8000);
    }
}

let draining = null;

/** Send every stored scan once. Resolves to how many are still waiting. */
function drainQueue() {
    if (!draining) {
        draining = drainOnce().finally(() => { draining = null; });
    }
    return draining;
}

async function drainOnce() {
    const entries = await allQueued();
    let waiting = 0;
    for (const entry of entries) {
        if (Date.now() > Number(entry.data.expires_at)) {
            await dropQueued(entry.key);
            await tell({ key: entry.key, outcome: 'expired',
                         message: 'the code expired before the connection came back' });
            continue;
        }
        let response;
        let payload;
        try {
            ({ response, payload } = await send(entry.data, entry.csrf));
            if (payload && payload.outcome === 'csrf_expired' && payload.csrf_token) {
                entry.csrf = payload.csrf_token;
                ({ response, payload } = await send(entry.data, entry.csrf));
            }
        } catch (_) {
            return entries.length;          // still offline; try later
        }
        if (!isDefinitive(response)) {
            waiting += 1;
            continue;
        }
        await dropQueued(entry.key);
        await tell({
            key: entry.key,
            outcome: payload.outcome || payload.status,
            message: payload.message || '',
            course_code: payload.course_code
        });
    }
    return waiting;
}

async function send(data, csrf) {
    // A request into a dead cell can hang for minutes on TCP retransmits,
    // and while it does the single-flight drain blocks every other try.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
        const response = await fetch('/mark_attendance', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
            body: JSON.stringify(data),
            signal: controller.signal
        });
        const payload = await response.clone().json().catch(() => null);
        return { response, payload };
    } finally {
        clearTimeout(timeout);
    }
}

/** Every open ScanMark page hears how a stored scan ended. */
async function tell(message) {
    const pages = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    pages.forEach(page => page.postMessage(Object.assign({ type: 'scan-sync' }, message)));
}

function openOfflineDatabase() {
    return new Promise((resolve, reject) => {
        // v3: one entry per student per class (`key`), holding the request
        // body and its form token. Earlier versions' entries are useless by
        // now (they expire within QR_WINDOW_SECONDS) and are dropped.
        const request = indexedDB.open('ScanMarkOfflineDB', 3);
        request.onupgradeneeded = event => {
            const database = event.target.result;
            if (database.objectStoreNames.contains('scans')) database.deleteObjectStore('scans');
            database.createObjectStore('scans', { keyPath: 'key' });
        };
        request.onsuccess = event => resolve(event.target.result);
        request.onerror = () => reject(request.error);
    });
}

async function withStore(mode, work) {
    const database = await openOfflineDatabase();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction('scans', mode);
        const result = work(transaction.objectStore('scans'));
        transaction.oncomplete = () => resolve(result && result.result);
        transaction.onerror = () => reject(transaction.error);
    });
}

async function storeScan(entry) {
    // A newer code for the same class replaces an older one, never the
    // other way round: the newest code is the one most likely to still be
    // inside the server's window when the network returns.
    const existing = await withStore('readonly', store => store.get(entry.key));
    if (existing && Number(existing.data.expires_at) > Number(entry.data.expires_at)) return;
    await withStore('readwrite', store => store.put(entry));
}

function allQueued() {
    return withStore('readonly', store => store.getAll()).then(rows => rows || []);
}

function dropQueued(key) {
    return withStore('readwrite', store => store.delete(key)).catch(() => {});
}
