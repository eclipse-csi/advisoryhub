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
 */
(function () {
  "use strict";

  if (!window.htmx) return;

  htmx.config.allowEval = false;
  htmx.config.allowScriptTags = false;

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
})();
