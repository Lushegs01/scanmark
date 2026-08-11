const CACHE_NAME = 'scanmark-cache-v3';
const STATIC_ASSETS = [
    '/static/style.css',
    '/static/logo.png',
    '/static/logo-192.png',
    '/static/manifest.json',
    '/static/scanner.js',
    '/static/vendor/jsQR.min.js'
];

self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)));
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
        )).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (url.pathname === '/mark_attendance' && event.request.method === 'POST') {
        event.respondWith(handleAttendanceRequest(event.request));
        return;
    }
    if (event.request.method === 'GET' && STATIC_ASSETS.includes(url.pathname)) {
        event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request)));
    }
});

// The server refuses a scanned token older than this, checked when the
// request is PROCESSED. Injected by the /service-worker.js route from the
// server's own QR_CODE_WINDOW so the two can never drift apart.
const QR_WINDOW_SECONDS = self.SCANMARK_QR_WINDOW_SECONDS || 45;

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

function jsonResponse(body, status) {
    return new Response(JSON.stringify(body), {
        status: status,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
}

async function handleAttendanceRequest(request) {
    const networkRequest = request.clone();
    const queueRequest = request.clone();
    try {
        const response = await fetch(networkRequest);
        if (response.status < 500) return response;
        throw new Error(`transient HTTP ${response.status}`);
    } catch (_) {
        const data = await queueRequest.json();
        const deadline = tokenDeadline(data.qr_data);
        const remainingMs = deadline === null ? 0 : deadline - Date.now();

        // Queueing a code the server will already refuse is worse than
        // failing here: it looks like success and silently isn't.
        if (remainingMs <= 0) {
            return jsonResponse({
                status: 'error',
                message: 'No connection, and this code has expired. Reconnect, then scan the new code on screen.'
            }, 400);
        }

        data.queued_at = new Date().toISOString();
        data.expires_at = deadline;
        data.dedupe_key = `${data.user_marker || 'anonymous'}:${data.qr_data || 'missing'}`;
        await saveScanOffline(data);

        return jsonResponse({
            status: 'queued',
            message: `No connection. This scan is saved and will be sent automatically, but it only counts if you get back online within ${Math.ceil(remainingMs / 1000)}s. If you see no confirmation, scan again.`
        }, 202);
    }
}

function openOfflineDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('ScanMarkOfflineDB', 2);
        request.onupgradeneeded = event => {
            const database = event.target.result;
            if (database.objectStoreNames.contains('scans')) database.deleteObjectStore('scans');
            database.createObjectStore('scans', { keyPath: 'dedupe_key' });
        };
        request.onsuccess = event => resolve(event.target.result);
        request.onerror = () => reject(request.error);
    });
}

async function saveScanOffline(data) {
    const database = await openOfflineDatabase();
    return new Promise((resolve, reject) => {
        const transaction = database.transaction('scans', 'readwrite');
        transaction.objectStore('scans').put(data);
        transaction.oncomplete = resolve;
        transaction.onerror = () => reject(transaction.error);
    });
}
