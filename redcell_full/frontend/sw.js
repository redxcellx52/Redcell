/**
 * sw.js — REDCELL AR-GE Service Worker
 * Web Push bildirimleri alır ve gösterir.
 * /static/sw.js olarak servis edilir.
 */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Push bildirimi geldiğinde
self.addEventListener('push', function(event) {
  let payload = { title: 'REDCELL', body: 'Yeni bildirim', url: '/admin' };

  if (event.data) {
    try { payload = JSON.parse(event.data.text()); } catch {}
  }

  const options = {
    body:    payload.body,
    icon:    '/static/icon-192.png',   // Yoksa tarayıcı varsayılanı kullanır
    badge:   '/static/badge-72.png',
    data:    { url: payload.url || '/admin' },
    actions: payload.actions || [],
    vibrate: [200, 100, 200],
    tag:     'redcell-bildirim',
    renotify: true,
  };

  event.waitUntil(
    self.registration.showNotification(payload.title, options)
  );
});

// Bildirime tıklandığında admin paneline yönlendir
self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const hedefUrl = event.notification.data?.url || '/admin';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // Zaten açık bir REDCELL sekmesi varsa odaklan
      for (const client of list) {
        if (client.url.includes(self.location.origin)) {
          client.focus();
          client.navigate(hedefUrl);
          return;
        }
      }
      // Yoksa yeni sekme aç
      clients.openWindow(hedefUrl);
    })
  );
});
