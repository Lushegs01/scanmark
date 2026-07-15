// v2: the v1 pre-cache list included URLs that don't exist (/base.html,
// /static/script.js) — cache.addAll() rejects if ANY url 404s, so the
// service worker never actually installed and offline mode never worked.
const CACHE_NAME = 'scanmark-cache-v2';
const urlsToCache = [
    '/static/style.css',
    '/static/logo.png',
    '/static/logo-192.png',
    '/static/manifest.json',
];

// 1. Install & Cache Static Files
self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
    );
});

// 2. Clean Up Old Caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
        )
    );
});

// 3. THE UPGRADED FETCH ENGINE
self.addEventListener('fetch', event => {
    // SCENARIO A: The user is trying to submit an attendance scan (POST request)
    if (event.request.url.includes('/mark_attendance') && event.request.method === 'POST') {
        event.respondWith(
            fetch(event.request.clone()).catch(async () => {
                console.log("📶 Network dead. Saving scan to local offline queue...");

                // Read the scan data the student tried to send
                const scanData = await event.request.clone().json();

                // Save it to the phone's local IndexedDB (Offline Storage)
                await saveScanOffline(scanData);

                // Honest message: the sync is attempted later, but the QR
                // token may have expired by then and need a fresh scan.
                return new Response(JSON.stringify({
                    status: "success",
                    message: "📶 No network — scan saved on this phone. It will try to sync automatically; if the class QR has expired by then, please scan again."
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            })
        );
        return; // Stop here so it doesn't run the static cache logic below
    }

    // SCENARIO B: Static assets only — cache-first. Dynamic pages
    // (dashboards, login, APIs) always go to the network: serving them
    // from cache would show stale, per-user content.
    if (event.request.method === 'GET' && urlsToCache.some(u => event.request.url.endsWith(u))) {
        event.respondWith(
            caches.match(event.request).then(response => response || fetch(event.request))
        );
    }
    // Everything else: browser default (no interception).
});

// --- HELPER DATABASE FUNCTION ---
// This creates a mini-database right inside the student's phone browser
function saveScanOffline(data) {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('ScanMarkOfflineDB', 1);

        request.onupgradeneeded = event => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains('scans')) {
                db.createObjectStore('scans', { autoIncrement: true });
            }
        };

        request.onsuccess = event => {
            const db = event.target.result;
            const transaction = db.transaction('scans', 'readwrite');
            const store = transaction.objectStore('scans');

            // Add a timestamp so we know exactly when they scanned it offline
            data.offline_timestamp = new Date().toISOString();
            store.add(data);
            resolve();
        };

        request.onerror = () => reject("Failed to open offline database");
    });
}
