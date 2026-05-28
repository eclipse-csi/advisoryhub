// Disable the submit button on a form until the user has actually
// changed something. Activates on any <form data-dirty-form>; finds
// the first <button type="submit"> inside.
//
// Comparison is done via FormData serialization, sorted and stripped of
// the CSRF token so its rotation doesn't read as "dirty". This handles
// checkboxes, radios, selects, and text inputs uniformly.
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

  function init(form) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return;
    const initial = snapshot(form);
    const sync = () => {
      button.disabled = snapshot(form) === initial;
    };
    sync();
    form.addEventListener("change", sync);
    form.addEventListener("input", sync);
    // After a server-rendered swap (e.g. HTMX), the listeners on the
    // *old* form node are gone — but the script doesn't run again. We
    // don't currently target HTMX-swapped forms with dirty-tracking, so
    // this is fine; revisit if that changes.
  }

  function start() {
    document.querySelectorAll("form[data-dirty-form]").forEach(init);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
