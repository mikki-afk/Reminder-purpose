const CACHE = 'lang-reminder-v2';

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/', '/index.html', '/sw.js'])));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});

// Receive push from Cloudflare Worker and show notification
self.addEventListener('push', e => {
  let data = { title: 'Language Reminder', body: '' };
  try { data = e.data?.json() ?? data; } catch {}

  e.waitUntil(
    self.registration.showNotification(data.title, {
      body:             data.body,
      requireInteraction: false,
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window' }).then(wins => {
      const open = wins.find(w => w.url.startsWith(self.location.origin));
      return open ? open.focus() : clients.openWindow('/');
    })
  );
});
