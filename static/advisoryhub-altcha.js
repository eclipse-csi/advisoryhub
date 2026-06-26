/*
 * ALTCHA proof-of-work worker registration (self-hosted, strict-CSP build).
 *
 * static/altcha/altcha.external.min.js is ALTCHA's "external" build: it ships
 * no inline <style> and no bundled Web Workers, so it loads under the app's
 * strict CSP unchanged. The trade-off is that every PoW algorithm must be
 * registered with a factory that creates the Worker. We register the SHA family
 * (the only algorithms altcha-lib-py emits — default SHA-256) pointing at the
 * vendored same-origin worker, so new Worker(...) is governed by
 * default-src 'self' — no worker-src / blob: exception needed.
 *
 * The worker URL is read from a data attribute so it carries the {% static %}
 * content-hashed path in production.
 */
(function () {
  "use strict";
  var MAX_TRIES = 60; // ~3s at 50ms — the widget module loads well within this

  function register() {
    var altcha = globalThis.$altcha;
    if (!altcha || !altcha.algorithms || typeof altcha.algorithms.set !== "function") {
      return false; // widget script not ready yet — keep polling
    }
    var host = document.querySelector("[data-altcha-worker]");
    if (host) {
      var url = host.getAttribute("data-altcha-worker");
      if (url) {
        var factory = function () {
          return new Worker(url);
        };
        ["SHA-256", "SHA-384", "SHA-512"].forEach(function (algo) {
          altcha.algorithms.set(algo, factory);
        });
      }
    }
    return true;
  }

  if (register()) {
    return;
  }
  var tries = 0;
  var timer = setInterval(function () {
    if (register() || (tries += 1) >= MAX_TRIES) {
      clearInterval(timer);
    }
  }, 50);
})();
