const CACHE_NAME = "controle-portaria-arua-v2";

const ARQUIVOS_CACHE = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./logo-arua.png"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return Promise.all(
        ARQUIVOS_CACHE.map(function (arquivo) {
          return cache.add(arquivo).catch(function () {
            return null;
          });
        })
      );
    })
  );

  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (nomesCaches) {
      return Promise.all(
        nomesCaches.map(function (nomeCache) {
          if (nomeCache !== CACHE_NAME) {
            return caches.delete(nomeCache);
          }

          return null;
        })
      );
    })
  );

  self.clients.claim();
});

self.addEventListener("fetch", function (event) {
  if (event.request.method !== "GET") return;

  event.respondWith(
    caches.match(event.request).then(function (respostaCache) {
      if (respostaCache) {
        return respostaCache;
      }

      return fetch(event.request).then(function (respostaRede) {
        return caches.open(CACHE_NAME).then(function (cache) {
          cache.put(event.request, respostaRede.clone());
          return respostaRede;
        });
      }).catch(function () {
        return caches.match("./index.html");
      });
    })
  );
});
