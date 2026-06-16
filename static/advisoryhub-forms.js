/* AdvisoryHub — small delegated form behaviours (CSP-clean, no inline handlers).
 *
 * Currently: conditional-enable. A control marked
 *   data-enabled-by="<radio-name>:<value>"
 * is enabled only while the named radio group has that value selected, and
 * disabled otherwise (so it is excluded from submission). Replaces the inline
 * `onclick="...disabled=..."` handlers on the orphan-CVE reassignment radios.
 *
 * Delegation handles HTMX-swapped fragments (e.g. the reassignment row).
 */
(function () {
  "use strict";

  function sync(target) {
    var spec = target.getAttribute("data-enabled-by");
    if (!spec) return;
    var sep = spec.indexOf(":");
    var name = spec.slice(0, sep);
    var wantValue = spec.slice(sep + 1);
    var form = target.form;
    if (!form) return;
    var checked = form.querySelector('input[name="' + name + '"]:checked');
    target.disabled = !(checked && checked.value === wantValue);
  }

  function syncWithin(root) {
    var nodes = (root || document).querySelectorAll("[data-enabled-by]");
    for (var i = 0; i < nodes.length; i++) sync(nodes[i]);
  }

  document.addEventListener("change", function (event) {
    var el = event.target;
    if (!el.matches || !el.matches('input[type="radio"]')) return;
    if (el.form) syncWithin(el.form);
  });

  // ---- confirm-to-submit gate ------------------------------------------
  // A submit control marked `data-confirm-submit` stays disabled until, within
  // its form, every `[data-confirm-token]` input's trimmed/lowercased value
  // equals its token attribute AND every `[data-confirm-required]` field is
  // non-empty. Gates consequential actions (e.g. GDPR forget-user) behind
  // retyping a confirmation phrase plus a justification — CSP-clean, no inline
  // handlers. The button ships `disabled` in markup so it fails closed when JS
  // is unavailable.
  function syncConfirm(form) {
    if (!form) return;
    var btn = form.querySelector("[data-confirm-submit]");
    if (!btn) return;
    var ok = true,
      i,
      els;
    els = form.querySelectorAll("[data-confirm-token]");
    for (i = 0; i < els.length; i++) {
      var want = (els[i].getAttribute("data-confirm-token") || "").trim().toLowerCase();
      if ((els[i].value || "").trim().toLowerCase() !== want) ok = false;
    }
    els = form.querySelectorAll("[data-confirm-required]");
    for (i = 0; i < els.length; i++) {
      if (!(els[i].value || "").trim()) ok = false;
    }
    btn.disabled = !ok;
  }

  function syncConfirmWithin(root) {
    var btns = (root || document).querySelectorAll("[data-confirm-submit]");
    for (var i = 0; i < btns.length; i++) syncConfirm(btns[i].form);
  }

  document.body.addEventListener("htmx:afterSwap", function (event) {
    syncWithin(event.target);
    syncConfirmWithin(event.target);
  });

  // ---- aria-invalid bridge ---------------------------------------------
  // Mirror the CSS :user-invalid state to aria-invalid so screen readers learn
  // a field is in error — the pseudo-class is invisible to assistive tech.
  // :user-invalid only matches after interaction, so this never fires early.
  function syncAriaInvalid(el) {
    if (!el || !el.matches || !el.matches("input, select, textarea")) return;
    var invalid;
    try {
      invalid = el.matches(":user-invalid");
    } catch (_e) {
      return; // :user-invalid unsupported on this engine — leave markup as-is
    }
    if (invalid) el.setAttribute("aria-invalid", "true");
    else if (el.getAttribute("aria-invalid") === "true") el.removeAttribute("aria-invalid");
  }
  document.addEventListener("blur", function (e) { syncAriaInvalid(e.target); }, true);
  document.addEventListener("input", function (e) {
    syncAriaInvalid(e.target);
    if (e.target && e.target.form) syncConfirm(e.target.form);
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      syncWithin(document);
      syncConfirmWithin(document);
    });
  } else {
    syncWithin(document);
    syncConfirmWithin(document);
  }
})();
