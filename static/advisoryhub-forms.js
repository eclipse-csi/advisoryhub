/* AdvisoryHub — small delegated form behaviours (CSP-clean, no inline handlers).
 *
 * Currently: conditional-enable. A control marked
 *   data-enabled-by="<radio-name>:<value>"
 * is enabled only while the named radio group has that value selected, and
 * disabled otherwise (so it is excluded from submission). Replaces the inline
 * `onclick="...disabled=..."` handlers on the orphan-CVE reassignment radios.
 *
 * Delegation handles HTMX-swapped fragments (e.g. the admin reassignment row).
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

  document.body.addEventListener("htmx:afterSwap", function (event) {
    syncWithin(event.target);
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      syncWithin(document);
    });
  } else {
    syncWithin(document);
  }
})();
