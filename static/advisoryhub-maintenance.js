/*
 * Maintenance mode — client-side disabling of write controls.
 *
 * Display-only: the server (common.middleware.MaintenanceModeMiddleware)
 * is what actually refuses writes. This just makes paused users SEE that
 * actions are unavailable instead of clicking buttons that 503.
 *
 * Active only when <body data-maintenance-paused> is present, which the
 * maintenance_mode context processor sets exclusively for paused (non-admin)
 * viewers. Admins never get the attribute, so their buttons stay live.
 *
 * What we disable:
 *   - submit controls inside write forms — either method="post|put|patch|delete"
 *     OR a form carrying hx-post/hx-put/hx-patch/hx-delete (htmx omits method=)
 *   - standalone htmx write triggers (hx-post/put/patch/delete on a button/link)
 *   - fetch()-driven controls that have no form/hx markup: the Access panel's
 *     add/remove/permission controls and its drag-to-reorder rows
 * What we leave alone: navigation links, GET forms/searches, the theme toggle,
 *   hx-get controls, and anything inside [data-maintenance-allow] (e.g. Sign out).
 */
(function () {
  "use strict";

  var TITLE = "Paused for maintenance";
  var WRITE_HX = ["hx-post", "hx-put", "hx-patch", "hx-delete"];
  var WRITE_METHODS = ["post", "put", "patch", "delete"];
  // Submit controls inside a form (a bare <button> defaults to submit).
  var SUBMIT_SEL = "button:not([type=button]), input[type=submit], input[type=image]";
  // Fetch-driven Access-panel controls (static/advisoryhub-access.js) — no
  // form, no hx-*, so they need explicit selectors.
  var FETCH_CTRL_SEL =
    "[data-add-grant],[data-remove-grant],[data-remove-invitation]," +
    "[data-principal-input],[data-add-permission]";

  function paused() {
    return document.body && document.body.hasAttribute("data-maintenance-paused");
  }

  function isAllowed(el) {
    return !!el.closest("[data-maintenance-allow]");
  }

  function disableControl(el) {
    if (isAllowed(el)) return;
    if ("disabled" in el) el.disabled = true;
    // Anchors / draggable rows can't use the disabled property — neutralise
    // them visually and behaviourally too.
    el.classList.add("is-maintenance-disabled");
    el.setAttribute("aria-disabled", "true");
    if (el.tagName === "A" || el.getAttribute("draggable") === "true") {
      el.setAttribute("tabindex", "-1");
      el.setAttribute("draggable", "false");
    }
    if (!el.title) el.title = TITLE;
  }

  function isWriteForm(form) {
    var method = (form.getAttribute("method") || "get").toLowerCase();
    if (WRITE_METHODS.indexOf(method) !== -1) return true;
    return WRITE_HX.some(function (a) {
      return form.hasAttribute(a);
    });
  }

  function apply(root) {
    if (!paused()) return;
    var scope = root && root.querySelectorAll ? root : document;

    // 1) Submit controls inside write forms (regular POST and htmx forms).
    scope.querySelectorAll("form").forEach(function (form) {
      if (!isWriteForm(form) || isAllowed(form)) return;
      form.querySelectorAll(SUBMIT_SEL).forEach(disableControl);
    });

    // 2) Standalone htmx write triggers (a button/link that is NOT a form).
    var hxSel = WRITE_HX.map(function (a) {
      return "[" + a + "]";
    }).join(",");
    scope.querySelectorAll(hxSel).forEach(function (el) {
      if (el.tagName !== "FORM") disableControl(el);
    });

    // 3) Fetch-driven Access-panel controls + its draggable rows.
    scope.querySelectorAll(FETCH_CTRL_SEL).forEach(disableControl);
    scope.querySelectorAll(".access-row[draggable=true]").forEach(disableControl);
  }

  // Belt-and-braces: swallow clicks AND submits that slip through on a paused
  // control (e.g. Enter inside a still-focusable input, or a control we didn't
  // tag). Capture phase so we win before app/htmx handlers run.
  document.addEventListener(
    "click",
    function (e) {
      if (!paused()) return;
      var t = e.target.closest(".is-maintenance-disabled, [aria-disabled=true]");
      if (t && !isAllowed(t)) {
        e.preventDefault();
        e.stopPropagation();
      }
    },
    true
  );
  document.addEventListener(
    "submit",
    function (e) {
      if (!paused()) return;
      var form = e.target;
      if (form && form.tagName === "FORM" && isWriteForm(form) && !isAllowed(form)) {
        e.preventDefault();
        e.stopPropagation();
      }
    },
    true
  );

  function init() {
    apply(document);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Re-apply to htmx-injected fragments (drawers, swapped panels).
  if (document.body) {
    document.body.addEventListener("htmx:afterSettle", function (e) {
      apply(e.target);
    });
  }
})();
