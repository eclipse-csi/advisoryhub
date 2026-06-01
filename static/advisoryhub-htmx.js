/* AdvisoryHub — global HTMX configuration, CSRF, and error surfacing.
 *
 * Loaded once (base.html) after htmx.min.js. Three jobs:
 *  1. Harden the swap surface: disable htmx's eval-based features. We use no
 *     `hx-on`/`hx-vals="js:"`/event filters and no swapped response carries a
 *     <script>, so turning these off shrinks the XSS blast radius (defence in
 *     depth alongside the CSP) with zero behavioural change.
 *  2. Inject the CSRF token on every htmx request from a single <meta> tag,
 *     replacing the per-form `hx-headers='{"X-CSRFToken": ...}'` that used to
 *     be sprayed across ~10 templates (one token surface, not many).
 *  3. Surface request failures: a swap that errors (non-2xx) or never reaches
 *     the server used to be silent. Show a dismissible toast reusing the
 *     `.messages` styling so the user knows the action did not take effect.
 *  4. Surface request *outcomes* to assistive tech: mark the swap target
 *     `aria-busy` while the request is in flight, and announce a quiet,
 *     polite confirmation when a mutation (non-GET) succeeds — so a partial
 *     swap that updates the page in place isn't silent to screen readers.
 */
(function () {
  "use strict";

  if (!window.htmx) return;

  htmx.config.allowEval = false;
  htmx.config.allowScriptTags = false;
  // Don't let htmx inject its indicator <style> into <head>: under the enforced
  // CSP (style-src 'self', no 'unsafe-inline') that inline style is blocked. The
  // equivalent .htmx-indicator rules are shipped in advisoryhub.css instead.
  htmx.config.includeIndicatorStyles = false;

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  document.body.addEventListener("htmx:configRequest", function (event) {
    var token = csrfToken();
    if (token) event.detail.headers["X-CSRFToken"] = token;
  });

  function toast(message) {
    var region = document.getElementById("toast-region");
    if (!region) return;
    var li = document.createElement("li");
    li.className = "error";
    li.setAttribute("role", "alert");

    var text = document.createElement("span");
    text.textContent = message;
    li.appendChild(text);

    var dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "toast__dismiss";
    dismiss.setAttribute("aria-label", "Dismiss");
    dismiss.textContent = "×";
    dismiss.addEventListener("click", function () {
      li.remove();
    });
    li.appendChild(dismiss);

    region.appendChild(li);
    window.setTimeout(function () {
      li.remove();
    }, 8000);
  }

  document.body.addEventListener("htmx:responseError", function () {
    toast("Something went wrong and your change was not saved. Please try again.");
  });
  document.body.addEventListener("htmx:sendError", function () {
    toast("Network error — your change was not saved. Check your connection and try again.");
  });

  // Mark the swap target busy while the request is in flight so assistive tech
  // knows the region is updating. The visible spinner (.htmx-indicator) is a
  // separate, purely visual cue.
  function setBusy(el, busy) {
    if (!el || !el.setAttribute) return;
    if (busy) el.setAttribute("aria-busy", "true");
    else el.removeAttribute("aria-busy");
  }

  // Announce a quiet, polite confirmation that a mutation succeeded. Cleared
  // first so an identical consecutive message is still re-announced.
  function announce(message) {
    var region = document.getElementById("htmx-status");
    if (!region) return;
    region.textContent = "";
    window.setTimeout(function () {
      region.textContent = message;
    }, 30);
  }

  document.body.addEventListener("htmx:beforeRequest", function (event) {
    setBusy(event.detail.target || event.detail.elt, true);
  });
  document.body.addEventListener("htmx:afterRequest", function (event) {
    setBusy(event.detail.target || event.detail.elt, false);
    // Only mutations get a confirmation; GET-driven swaps (timelines, panels
    // loaded on `hx-trigger="load"`) update the page as expected and would
    // otherwise announce on every navigation.
    var cfg = event.detail.requestConfig;
    var verb = cfg && cfg.verb ? String(cfg.verb).toLowerCase() : "get";
    if (event.detail.successful && verb !== "get") announce("Done.");
  });
})();
