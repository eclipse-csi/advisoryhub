/* Click-to-copy for any `[data-copy]` element.
 *
 * CSP-safe progressive enhancement: a single delegated `click` listener (no
 * inline handlers), the async Clipboard API (`navigator.clipboard.writeText`,
 * Baseline-widely-available and fine in the app's secure contexts — https in
 * prod, localhost in dev). On success it shows a brief inline "Copied" state on
 * the activated element and announces through the polite toast region
 * (`advisoryhub:toast`, owned by advisoryhub-toast.js) so screen-reader users
 * get the confirmation too. No off-screen-textarea fallback: that needs an
 * inline `style`, which the `style-src 'self'` CSP forbids; an insecure context
 * just gets the error toast instead.
 *
 * Markup contract:
 *   <button type="button" data-copy="TEXT" aria-label="Copy …">visible</button>
 * The element's text is swapped to "Copied" for REVERT_MS, then restored.
 */
(function () {
  "use strict";

  var REVERT_MS = 1300;

  function toast(level, message) {
    document.dispatchEvent(
      new CustomEvent("advisoryhub:toast", { detail: { level: level, message: message } })
    );
  }

  function flash(el) {
    if (el._copyTimer) {
      clearTimeout(el._copyTimer);
    } else {
      // First flash since the last revert — stash the real label to restore.
      el.dataset.copyOriginal = el.textContent;
    }
    el.classList.add("is-copied");
    el.textContent = "Copied";
    el._copyTimer = setTimeout(function () {
      el.classList.remove("is-copied");
      if (el.dataset.copyOriginal != null) {
        el.textContent = el.dataset.copyOriginal;
        delete el.dataset.copyOriginal;
      }
      el._copyTimer = null;
    }, REVERT_MS);
  }

  function copy(el) {
    var text = el.getAttribute("data-copy");
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () {
          flash(el);
          toast("success", "Copied to clipboard");
        },
        function () {
          toast("error", "Couldn’t copy to clipboard");
        }
      );
    } else {
      toast("error", "Clipboard isn’t available in this browser");
    }
  }

  document.addEventListener("click", function (e) {
    var target = e.target;
    if (!(target instanceof Element)) return;
    var el = target.closest("[data-copy]");
    if (!el) return;
    e.preventDefault();
    copy(el);
  });
})();
