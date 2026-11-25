/* MALIMI COPY — Service Worker: PWA (offline shell) + Web Push (inafanya kazi hata app ikiwa imefungwa) */
const VERSION = 'v1';
const CACHE = 'malimi-shell-' + VERSION;
const SHELL = [
  '/offline.html',
  '/manifest.webmanifest',
  '/favicon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/badge-96.png',
];
const DEFAULT_ICON = '/icons/icon-192.png';
const DEFAULT_BADGE = '/icons/badge-96.png';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((c) => Promise.all(SHELL.map((u) => c.add(u).catch(() => null))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('malimi-shell-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;           // CDN / fonts: browser handles
  if (url.pathname.startsWith('/api/')) return;              // API: kamwe usi-cache (auth, malipo, coins)
  if (url.pathname === '/sw.js') return;

  // Kurasa: mtandao kwanza; ukikosa, onyesha ukurasa wa offline
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => caches.match('/offline.html'))
    );
    return;
  }

  // Icons / manifest / picha: cache kwanza, sasisha nyuma ya pazia
  if (/^\/(icons\/|favicon|manifest\.webmanifest|offline\.html)/.test(url.pathname) || /\.(png|svg|ico|webp)$/.test(url.pathname)) {
    event.respondWith(
      caches.open(CACHE).then((cache) =>
        cache.match(req).then((hit) => {
          const net = fetch(req).then((res) => {
            if (res && res.ok) cache.put(req, res.clone());
            return res;
          }).catch(() => hit);
          return hit || net;
        })
      )
    );
  }
});

/* ---------------- PUSH ---------------- */
function parsePush(event) {
  let d = {};
  if (event.data) {
    try { d = event.data.json(); } catch (e) { d = { body: event.data.text() }; }
  }
  return d || {};
}

self.addEventListener('push', (event) => {
  const d = parsePush(event);
  const title = String(d.title || 'MALIMI COPY').slice(0, 80);
  const options = {
    body: String(d.body || 'Una ujumbe mpya.').slice(0, 300),
    icon: d.icon || DEFAULT_ICON,
    badge: d.badge || DEFAULT_BADGE,
    tag: d.tag || 'malimi-' + Date.now(),
    renotify: true,
    vibrate: [180, 90, 180],
    timestamp: Date.now(),
    lang: 'sw',
    data: { url: d.url || '/' },
    actions: [{ action: 'open', title: 'Fungua' }],
  };
  if (d.image) options.image = d.image;
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const raw = (event.notification.data && event.notification.data.url) || '/';
  const target = new URL(raw, self.location.origin);
  if (target.origin !== self.location.origin) return;       // usifungue tovuti za nje
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) {
      if (new URL(w.url).origin === self.location.origin) {
        try { await w.focus(); } catch (e) {}
        w.postMessage({ type: 'push-nav', url: target.href });
        return;
      }
    }
    await self.clients.openWindow(target.href);
  })());
});

/* Browser ikibadilisha subscription (inaisha / inazungushwa), jisajili upya kimya kimya */
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil((async () => {
    try {
      const r = await fetch('/api/push/key', { credentials: 'include' });
      const k = await r.json();
      if (!k.publicKey) return;
      const pad = '='.repeat((4 - (k.publicKey.length % 4)) % 4);
      const raw = atob((k.publicKey + pad).replace(/-/g, '+').replace(/_/g, '/'));
      const key = Uint8Array.from(raw, (c) => c.charCodeAt(0));
      const sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      await fetch('/api/push/subscribe', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sub.toJSON()),
      });
    } catch (e) {}
  })());
});
