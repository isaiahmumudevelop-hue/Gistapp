/* GistApp Service Worker */
const CACHE_NAME = 'gistapp-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/manifest.json'
];

// Install — cache shell
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS_TO_CACHE).catch(()=>{}))
  );
});

// Activate — clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Fetch — network first, fall back to cache
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Skip WebSocket, API, uploads, and non-GET
  if (req.method !== 'GET') return;
  if (url.pathname.startsWith('/socket.io')) return;
  if (url.pathname.startsWith('/api/')) return;
  if (url.pathname.startsWith('/uploads/')) return;
  if (url.pathname.startsWith('/wallpapers/')) return;

  event.respondWith(
    fetch(req)
      .then(res => {
        // cache successful GET responses for the shell
        if (res.ok && (url.pathname === '/' || url.pathname === '/index.html')){
          const copy = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req).then(r => r || caches.match('/offline.html').then(o => o || caches.match('/'))))
  );
});
