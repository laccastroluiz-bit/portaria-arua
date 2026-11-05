/* Portaria Aruá — cache somente da interface pública, sem dados de visitantes. */
const CACHE_NAME = "portaria-arua-interface-v1";
const CACHE_PREFIX = "portaria-arua-interface-";
const FILES = [
  "./index.html",
  "./1%20-%20controle-acesso-motoristas.html",
  "./manifest.webmanifest",
  "./icon-portaria.svg"
];
const WHITELIST = new Set(FILES.map(file => new URL(file, self.registration.scope).pathname));

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME)
    .then(cache => cache.addAll(FILES))
    .then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys
    .filter(name => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
    .map(name => caches.delete(name))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;
  const target = new URL(event.request.url);
  if (target.origin !== self.location.origin || target.search ||
      !WHITELIST.has(target.pathname)) return;
  event.respondWith(fetch(event.request).then(response => {
    if (response.ok) {
      const copy = response.clone();
      caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy)).catch(() => {});
    }
    return response;
  }).catch(() => caches.match(event.request).then(cached => {
    return cached || Response.error();
  })));
});
