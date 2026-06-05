// Form-edit feedback + submit hygiene, all keyed off a FormData snapshot (sorted
// and CSRF-token-stripped so token rotation doesn't read as a change):
//
//   <span data-unsaved-indicator hidden>  An "unsaved changes" marker placed
//                              inside a form. Shown whenever the form is dirty
//                              (differs from its loaded snapshot), hidden when
//                              pristine. Pure feedback — it NEVER gates submit.
//                              Opt-in is simply the element's presence in a form.
//
//   <form data-submit-once>    After a submit the browser actually lets through
//                              (native validation passed, or the form is
//                              novalidate), disable the submit control so an
//                              impatient double-click can't double-post. We do
//                              NOT disable to *block* submission — the forms guide
//                              (§4) says let users submit and surface errors — only
//                              AFTER a valid click, which is the guide's endorsed
//                              double-post guard.
//
//   <form data-unsaved-guard>  Warn via `beforeunload` if the user navigates
//                              away with unsaved edits. Used on the advisory
//                              authoring form.
//
// The indicator and the unsaved-guard both re-baseline on formset add/remove
// (advisoryhub-formsets.js dispatches `advisoryhub:formset-changed`) so a
// structural row change isn't itself counted as unsaved content.
//
// NOTE: load this AFTER advisoryhub-formsets.js (and cvss/cwe/validate) on a page
// so the baselines are captured once those scripts have finished their on-load
// DOM/field normalisation — otherwise that normalisation would read as an
// immediate (false) "unsaved change".
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

  function initIndicator(form, indicator) {
    let baseline = snapshot(form);
    const sync = () => {
      indicator.hidden = snapshot(form) === baseline;
    };
    sync();
    form.addEventListener("input", sync);
    form.addEventListener("change", sync);
    document.addEventListener("advisoryhub:formset-changed", () => {
      baseline = snapshot(form);
      sync();
    });
  }

  function initSubmitOnce(form) {
    let submitted = false;
    form.addEventListener("submit", (e) => {
      // A second submit gesture while the first is still in flight: drop it.
      if (submitted) {
        e.preventDefault();
        return;
      }
      submitted = true;
      const button = form.querySelector('button[type="submit"], input[type="submit"]');
      if (!button) return;
      // Defer the disable so the control is still serialised into THIS POST (a
      // disabled control is excluded from submission). The `submitted` flag is
      // the actual re-entrancy guard; the disable is the visible cue. A failed
      // server-side validation re-renders a fresh page with the button enabled.
      requestAnimationFrame(() => {
        button.disabled = true;
      });
    });
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
    document.querySelectorAll("[data-unsaved-indicator]").forEach((indicator) => {
      const form = indicator.closest("form");
      if (form) initIndicator(form, indicator);
    });
    document.querySelectorAll("form[data-submit-once]").forEach(initSubmitOnce);
    document.querySelectorAll("form[data-unsaved-guard]").forEach(initUnsavedGuard);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
