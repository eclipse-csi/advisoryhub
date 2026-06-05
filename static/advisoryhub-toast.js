/* AdvisoryHub — unified user-feedback toasts.
 *
 * The single owner/renderer of the corner notification stack (#toast-region in
 * base.html). One visual system for every kind of feedback, keyed on level:
 *
 *   success / info   → TEMPORARY: announced politely, auto-dismissed after a
 *                      few seconds (also has a manual close button).
 *   warning / error  → PERSISTENT: announced assertively, NO timer — the user
 *                      must dismiss it with the close button.
 *
 * Everything funnels through render(); there are four feeders:
 *   1. `advisoryhub:toast`   — a custom DOM event any module can dispatch
 *                              (detail {message|text, level|type}).
 *   2. `advisoryhub:messages`— the HX-Trigger event emitted by
 *                              common.middleware.HtmxMessagesMiddleware for
 *                              HTMX responses (detail {messages:[{level,message}]}).
 *   3. htmx:responseError / htmx:sendError — transport / non-2xx failures, which
 *                              htmx never routes through HX-Trigger, surfaced as
 *                              PERSISTENT errors (previously an 8s auto-dismiss).
 *   4. The #toast-data JSON island in base.html — Django messages that survived
 *                              a full-page POST→redirect, drained on page load.
 *
 * CSP-clean: no inline handlers, text set via textContent, styling lives in
 * advisoryhub.css. Decoupled via events so load order vs. advisoryhub-htmx.js
 * is irrelevant (every feeder fires after the deferred scripts have run).
 */
(function () {
  "use strict";

  var AUTO_DISMISS_MS = 5000;
  // Slightly longer than the CSS exit transition; a hard failsafe so a toast is
  // always removed even if `transitionend` never fires (reduced-motion, tab
  // backgrounded, etc.).
  var EXIT_MS = 240;

  function region() {
    return document.getElementById("toast-region");
  }

  function normalise(level) {
    if (level === "danger") return "error";
    if (level === "success" || level === "info" || level === "warning" || level === "error") {
      return level;
    }
    return "info";
  }

  // Errors and warnings stay until the user acts; successes/infos are transient.
  function isPersistent(level) {
    return level === "error" || level === "warning";
  }

  function dismiss(li) {
    if (li.dataset.leaving) return;
    li.dataset.leaving = "1";
    li.classList.add("toast--leaving");
    window.setTimeout(function () {
      li.remove();
    }, EXIT_MS);
  }

  function render(message, level) {
    var host = region();
    if (!host || !message) return;
    level = normalise(level);

    var li = document.createElement("li");
    li.className = level;
    // role=alert => assertive (announced at once) for things the user must act
    // on; role=status => polite for transient confirmations.
    li.setAttribute("role", isPersistent(level) ? "alert" : "status");

    var text = document.createElement("span");
    text.textContent = message;
    li.appendChild(text);

    var close = document.createElement("button");
    close.type = "button";
    close.className = "toast__dismiss";
    close.setAttribute("aria-label", "Dismiss");
    close.textContent = "×"; // ×
    close.addEventListener("click", function () {
      dismiss(li);
    });
    li.appendChild(close);

    host.appendChild(li);

    if (!isPersistent(level)) {
      window.setTimeout(function () {
        dismiss(li);
      }, AUTO_DISMISS_MS);
    }
  }

  // 1. Generic seam: any code can `dispatchEvent(new CustomEvent("advisoryhub:toast", …))`.
  document.addEventListener("advisoryhub:toast", function (event) {
    var detail = event.detail || {};
    render(detail.message || detail.text, detail.level || detail.type);
  });

  // 2. Django messages serialised onto HTMX responses (HtmxMessagesMiddleware).
  document.body.addEventListener("advisoryhub:messages", function (event) {
    var detail = event.detail || {};
    var list = detail.messages || [];
    for (var i = 0; i < list.length; i++) {
      render(list[i].message, list[i].level);
    }
  });

  // 3. Transport / HTTP-error responses (htmx skips HX-Trigger on non-2xx).
  document.body.addEventListener("htmx:responseError", function () {
    render("Something went wrong and your change was not saved. Please try again.", "error");
  });
  document.body.addEventListener("htmx:sendError", function () {
    render("Network error — your change was not saved. Check your connection and try again.", "error");
  });

  // 4. Page-load island: Django messages that survived a full-page redirect.
  function drainIsland() {
    var node = document.getElementById("toast-data");
    if (!node) return;
    var list = [];
    try {
      list = JSON.parse(node.textContent || "[]");
    } catch (e) {
      list = [];
    }
    node.remove();
    for (var i = 0; i < list.length; i++) {
      render(list[i].message, list[i].level);
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", drainIsland);
  } else {
    drainIsland();
  }
})();
