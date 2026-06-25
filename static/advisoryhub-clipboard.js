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
 * The element's text is swapped to "Copied" for REVERT_MS, then restored. When
 * the target carries icons or other markup, wrap the swappable text in a
 * `[data-copy-label]` child — only that child's text is swapped, so the icons
 * survive; without one, the element's own text is swapped (the plain case).
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
    // Swap a dedicated label child when present so copy targets can carry icons
    // (e.g. the clipboard/check affordance) without textContent replacement
    // wiping them; otherwise swap the element's own text (the plain case).
    var label = el.querySelector("[data-copy-label]") || el;
    if (el._copyTimer) {
      clearTimeout(el._copyTimer);
    } else {
      // First flash since the last revert — stash the real label to restore.
      label.dataset.copyOriginal = label.textContent;
    }
    el.classList.add("is-copied");
    label.textContent = "Copied";
    el._copyTimer = setTimeout(function () {
      el.classList.remove("is-copied");
      if (label.dataset.copyOriginal != null) {
        label.textContent = label.dataset.copyOriginal;
        delete label.dataset.copyOriginal;
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
