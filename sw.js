// AAC Platform — Service Worker
// Network-first for the SPA shell so users always get the latest deploy,
// with a cached fallback when offline.

const CACHE_NAME = "aac-cache-v2";
const SHELL = ["/", "/index.html", "/manifest.json", "/aac-icon.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // Only handle GET requests on the same origin.
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) {
    return;
  }

  // Never cache Firebase / API traffic — always go to network.
  if (/firebase|googleapis|gstatic/i.test(req.url)) {
    return;
  }

  // Network-first: fetch fresh, fall back to cache when offline.
  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
        return res;
      })
      .catch(() => caches.match(req).then((hit) => hit || caches.match("/index.html")))
  );
});
