const CACHE_NAME = 'scanmark-cache-v1';
const urlsToCache = [
    '/',
    '/static/style.css',
    '/static/manifest.json'
];

// Install the service worker and cache core assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Opened cache');
                return cache.addAll(urlsToCache);
            })
    );
});

// Intercept network requests
self.addEventListener('fetch', event => {
    event.respondWith(
        // Network-first strategy: Try to get fresh data from the server first
        fetch(event.request).catch(() => {
            // If the network fails (student is offline), load from the cache
            return caches.match(event.request);
        })
    );
});