// Service worker : tout l'application est mise en cache => fonctionne sans Internet
const CACHE = 'hexacore-v1.0.1';
const FILES = ['./', 'index.html', 'manifest.webmanifest', 'css/app.css',
  'js/hexacore.js',
  'lib/qrcode.js', 'lib/jsQR.js',
  'fonts/inter.woff2', 'fonts/michroma.woff2', 'fonts/rajdhani-500.woff2', 'fonts/rajdhani-600.woff2', 'fonts/rajdhani-700.woff2',
  'img/logo-mark.png', 'img/icon-192.png', 'img/icon-512.png', 'img/icon-maskable-512.png'];

self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || fetch(e.request).then((r) => {
    if (r.ok && new URL(e.request.url).origin === location.origin) { const cp = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, cp)); }
    return r;
  }).catch(() => caches.match('index.html'))));
});
