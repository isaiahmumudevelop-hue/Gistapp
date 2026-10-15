/* GistApp Service Worker */
const CACHE_NAME = 'gistapp-v5';
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


/* ---------- web push ---------- GISTAPP_WEBPUSH_V1 */
self.addEventListener('push', function(event){
  let data = { title: 'GistApp', body: 'New notification', url: '/', tag: 'gistapp' };
  try {
    if (event.data) data = Object.assign(data, event.data.json());
  } catch(_){}
  event.waitUntil(
    self.registration.showNotification(data.title || 'GistApp', {
      body: data.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: data.tag || 'gistapp',
      data: { url: data.url || '/' },
      vibrate: [80, 40, 80],
      renotify: true
    })
  );
});

self.addEventListener('notificationclick', function(event){
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list){
      for (const c of list){
        if (c.url.includes(self.location.origin)){
          c.focus();
          try { c.navigate(url); } catch(_){}
          return;
        }
      }
      return self.clients.openWindow(url);
    })
  );
});
