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

async function handleAttendanceRequest(request) {
    const networkRequest = request.clone();
    const queueRequest = request.clone();
    try {
        const response = await fetch(networkRequest);
        if (response.status < 500) return response;
        throw new Error(`transient HTTP ${response.status}`);
    } catch (_) {
        const data = await queueRequest.json();
        data.queued_at = new Date().toISOString();
        data.dedupe_key = `${data.user_marker || 'anonymous'}:${data.qr_data || 'missing'}`;
        await saveScanOffline(data);
        return new Response(JSON.stringify({
            status: 'queued',
            message: 'No network. This scan is queued on this phone and will retry after connectivity returns.'
        }), {
            status: 202,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
        });
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
