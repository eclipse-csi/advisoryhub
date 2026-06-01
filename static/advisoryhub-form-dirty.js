// Two form-protection behaviours, both keyed off a FormData snapshot (sorted
// and CSRF-token-stripped so token rotation doesn't read as a change):
//
//   <form data-dirty-form>     Disable the submit button until something
//                              changes. Used on the notification-preferences
//                              form, which has no native validation constraints
//                              for a disabled submit to gate (so it does not
//                              suppress error feedback — see the forms guide).
//
//   <form data-unsaved-guard>  Warn via `beforeunload` if the user navigates
//                              away with unsaved edits. Used on the advisory
//                              authoring form. Re-baselines on formset add/remove
//                              (advisoryhub-formsets.js dispatches the event) so a
//                              structural change isn't counted as unsaved content.
//
// NOTE: load this AFTER advisoryhub-formsets.js (and cvss/cwe) on a page so the
// unsaved-guard baseline is captured once those scripts have finished their
// on-load DOM/field normalisation — otherwise that normalisation would read as
// an immediate (false) "unsaved change".
(function () {
  "use strict";

  const SKIP_KEYS = new Set(["csrfmiddlewaretoken"]);

  function snapshot(form) {
    const fd = new FormData(form);
    const pairs = [];
    for (const [key, value] of fd.entries()) {
      if (SKIP_KEYS.has(key)) continue;
      pairs.push(key + "=" + value);
    }
    pairs.sort();
    return pairs.join("&");
  }

  function initDirtyDisable(form) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    const initial = snapshot(form);
    const sync = () => {
      button.disabled = snapshot(form) === initial;
    };
    sync();
    form.addEventListener("change", sync);
    form.addEventListener("input", sync);
  }

  function initUnsavedGuard(form) {
    let baseline = snapshot(form);
    let submitting = false;
    form.addEventListener("submit", () => {
      submitting = true;
    });
    document.addEventListener("advisoryhub:formset-changed", () => {
      baseline = snapshot(form);
    });
    window.addEventListener("beforeunload", (e) => {
      if (submitting) return;
      if (snapshot(form) === baseline) return;
      e.preventDefault();
      e.returnValue = ""; // some browsers require this to show the prompt
    });
  }

  function start() {
    document.querySelectorAll("form[data-dirty-form]").forEach(initDirtyDisable);
    document.querySelectorAll("form[data-unsaved-guard]").forEach(initUnsavedGuard);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
