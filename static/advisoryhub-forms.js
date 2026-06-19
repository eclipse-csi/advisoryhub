/* AdvisoryHub — small delegated form behaviours (CSP-clean, no inline handlers).
 *
 * Five behaviours, all delegated on document so they survive HTMX-swapped
 * fragments (e.g. the reassignment row, the comment form):
 *  1. Conditional-enable: a control marked `data-enabled-by="<radio>:<value>"`
 *     is enabled only while the named radio group has that value (replaces the
 *     inline `onclick="...disabled=..."` handlers on the CVE reassignment radios).
 *  2. Confirm-to-submit gate: a `[data-confirm-submit]` button stays disabled
 *     until the form's `[data-confirm-token]` / `[data-confirm-required]` fields
 *     are satisfied (gates consequential actions behind a retyped phrase).
 *  3. aria-invalid bridge: mirror the CSS :user-invalid state to aria-invalid.
 *  4. Ctrl/Cmd+Enter submits the focused form through its default submit button.
 *  5. A subtle "⌘/Ctrl + Enter to submit" hint on textarea forms.
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
    injectHintsWithin(event.target);
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

  // ---- Ctrl/Cmd+Enter to submit ----------------------------------------
  // A keyboard "submit/save" shortcut for every form, so textarea-bearing forms
  // (advisory details, comments, modal reasons) can be submitted without leaving
  // the keyboard — plain Enter inserts a newline there. Single-line inputs
  // already submit on Enter; the shortcut is simply consistent for them.
  //
  // Faithful to native implicit submission AND the gates in this file: resolve
  // the form's default submit button and submit *through* it with
  // requestSubmit(), which fires a cancelable `submit` event — so htmx (hx-post
  // forms), native constraint validation, `data-submit-once`, and the
  // `data-confirm-submit` gate above all still run. A missing or disabled submit
  // control means "no submission" (e.g. the confirm gate disables its button
  // until the phrase is typed), exactly as native Enter behaves.
  function defaultSubmitButton(form) {
    if (!form || !form.querySelectorAll) return null;
    var sel =
      'button[type="submit"], button:not([type]), input[type="submit"], input[type="image"]';
    var inside = form.querySelectorAll(sel);
    for (var i = 0; i < inside.length; i++) {
      if (!inside[i].disabled) return inside[i];
    }
    // Submit controls associated by the form= attribute (the dialog pattern in
    // _confirm_action.html, where the button lives outside its <form>).
    if (form.id) {
      var ext = document.querySelectorAll(
        'button[form][type="submit"], button[form]:not([type]), ' +
          'input[form][type="submit"], input[form][type="image"]',
      );
      for (var j = 0; j < ext.length; j++) {
        if (ext[j].getAttribute("form") === form.id && !ext[j].disabled) return ext[j];
      }
    }
    return null;
  }

  document.addEventListener("keydown", function (event) {
    if (event.defaultPrevented) return;
    if (event.key !== "Enter" || !(event.ctrlKey || event.metaKey)) return;
    // Don't fire mid-IME-composition or on auto-repeat from a held chord.
    if (event.isComposing || event.repeat) return;
    var t = event.target;
    if (!t) return;
    var form = t.form instanceof HTMLFormElement ? t.form : t.closest ? t.closest("form") : null;
    if (!form) return;
    var btn = defaultSubmitButton(form);
    if (!btn) return; // no usable submit control (incl. a disabled confirm gate)
    event.preventDefault();
    // Win over the combobox keydown handlers (mentions/cwe/select) that also act
    // on Enter while their menu is open: this global listener registers before
    // those, so stopping immediate propagation suppresses their commit and the
    // form submits — the predictable, GitHub-style behaviour.
    event.stopImmediatePropagation();
    if (typeof form.requestSubmit === "function") form.requestSubmit(btn);
    else btn.click(); // ancient engines: click still fires submit + validation
  });

  // ---- "⌘/Ctrl + Enter to submit" hint ---------------------------------
  // A subtle, platform-aware hint injected next to the submit button on forms
  // that contain a <textarea> (where the shortcut is genuinely useful). JS-only,
  // so it shows exactly when the shortcut is available; skipped on confirm-gated
  // forms (their button is disabled until a phrase is typed, so the hint would
  // mislead). Re-run after htmx swaps re-render forms (comment form, dialogs).
  function comboKeys() {
    var p =
      (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    return /mac|iphone|ipad|ipod/i.test(p) ? ["⌘", "Enter"] : ["Ctrl", "Enter"];
  }
  function submitLabel() {
    var el = document.getElementById("kbd-hint-i18n");
    if (el) {
      try {
        var v = JSON.parse(el.textContent);
        if (typeof v === "string" && v) return v;
      } catch (_e) {
        /* fall through to the English default */
      }
    }
    return "to submit";
  }
  function buildHint() {
    var span = document.createElement("span");
    span.className = "kbd-hint";
    var keys = comboKeys();
    for (var i = 0; i < keys.length; i++) {
      var k = document.createElement("kbd");
      k.textContent = keys[i];
      span.appendChild(k);
    }
    var label = document.createElement("span");
    label.className = "kbd-hint__label";
    label.textContent = submitLabel();
    span.appendChild(label);
    return span;
  }
  function injectHint(form) {
    if (!form || !form.querySelector) return;
    if (!form.querySelector("textarea")) return;
    if (form.querySelector("[data-confirm-submit]")) return; // gated → no hint
    var btn = defaultSubmitButton(form);
    if (!btn) return;
    var prev = btn.previousElementSibling;
    if (prev && prev.classList && prev.classList.contains("kbd-hint")) return; // already added
    btn.insertAdjacentElement("beforebegin", buildHint());
  }
  function injectHintsWithin(root) {
    if (!root) root = document;
    if (root.matches && root.matches("form")) injectHint(root);
    var forms = root.querySelectorAll ? root.querySelectorAll("form") : [];
    for (var i = 0; i < forms.length; i++) injectHint(forms[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      syncWithin(document);
      syncConfirmWithin(document);
      injectHintsWithin(document);
    });
  } else {
    syncWithin(document);
    syncConfirmWithin(document);
    injectHintsWithin(document);
  }
})();
