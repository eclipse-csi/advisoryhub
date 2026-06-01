/* AdvisoryHub — native <dialog> controller (CSP-clean, no inline handlers).
 *
 * Centralises every modal/drawer interaction that used to live in inline
 * `onclick=`/`onclose=`/`hx-on::` attributes and the two per-drawer inline
 * <script> blocks, so a strict Content-Security-Policy (no 'unsafe-inline',
 * no 'unsafe-hashes') can be enforced. The native <dialog>.showModal() engine
 * is unchanged — only the wiring moved here, using event delegation like
 * advisoryhub-row-link.js / advisoryhub-maintenance.js.
 *
 * Markup contract:
 *   - A host element that HTMX swaps dialog markup into carries
 *     `data-dialog-host`. After the swap, the <dialog> inside it is opened;
 *     when it closes, the host is emptied so reopening fetches a fresh partial.
 *   - A button that opens an already-in-page dialog carries
 *     `data-dialog-open="<dialog-id>"`.
 *   - A button that closes its containing dialog carries `data-dialog-close`.
 *   - `dialog.confirm-dialog` forms close their dialog on a SUCCESSFUL htmx
 *     submit. `dialog.drawer` (and any `[data-light-dismiss]`) close on a
 *     backdrop click. These two scopes are deliberate: a drawer's "load older
 *     edits" htmx request must NOT close the drawer, and confirm dialogs keep
 *     their explicit Cancel/Esc affordance.
 */
(function () {
  "use strict";

  function isDialog(el) {
    return typeof HTMLDialogElement !== "undefined" && el instanceof HTMLDialogElement;
  }

  function open(dialog) {
    if (!dialog) return;
    // Light-dismiss for drawers (and anything opting in) — wired once.
    if (!dialog.dataset.ahWired) {
      dialog.dataset.ahWired = "1";
      if (dialog.matches(".drawer, [data-light-dismiss]")) {
        dialog.addEventListener("click", function (event) {
          if (event.target === dialog) dialog.close();
        });
      }
    }
    if (typeof dialog.showModal === "function") {
      if (!dialog.open) dialog.showModal();
    } else {
      dialog.setAttribute("open", "open"); // very old engines: non-modal fallback
    }
  }

  function openInHost(host) {
    if (host) open(host.querySelector("dialog"));
  }

  // Open a dialog that HTMX just swapped into a [data-dialog-host] container.
  // All such hosts use innerHTML swaps, so the swapped element IS the host.
  document.body.addEventListener("htmx:afterSwap", function (event) {
    var host = event.target;
    if (host && host.matches && host.matches("[data-dialog-host]")) openInHost(host);
  });

  // Close a confirm dialog after its form submits successfully. Scoped to
  // .confirm-dialog so in-drawer htmx (e.g. "load older edits") never closes
  // the drawer.
  document.body.addEventListener("htmx:afterRequest", function (event) {
    if (!event.detail || !event.detail.successful) return;
    var src = event.target;
    var dialog = src && src.closest ? src.closest("dialog.confirm-dialog") : null;
    if (dialog && dialog.open) dialog.close();
  });

  // Delegated open/close buttons.
  document.addEventListener("click", function (event) {
    var closer = event.target.closest("[data-dialog-close]");
    if (closer) {
      var owned = closer.closest("dialog");
      if (owned) owned.close();
      return;
    }
    var opener = event.target.closest("[data-dialog-open]");
    if (opener) {
      open(document.getElementById(opener.getAttribute("data-dialog-open")));
    }
  });

  // When any modal dialog closes, clear its host (if it lives in one). The
  // `close` event does not bubble, so listen in the capture phase.
  document.addEventListener(
    "close",
    function (event) {
      if (!isDialog(event.target)) return;
      var host = event.target.closest("[data-dialog-host]");
      if (host) host.innerHTML = "";
      // Native <dialog> restores focus to the opener — but if the opener was
      // swapped out of the DOM (e.g. the CVE-reject form replaces the table row
      // that held its trigger), focus falls back to <body>, stranding keyboard
      // and screen-reader users at the top. Move it to the main landmark
      // (#content is focusable, tabindex=-1) so context isn't lost.
      if (document.activeElement === document.body || document.activeElement === null) {
        var main = document.getElementById("content");
        if (main && typeof main.focus === "function") main.focus();
      }
    },
    true,
  );
})();
