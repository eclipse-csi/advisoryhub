/* AdvisoryHub — left navigation rail (CSP-clean, no inline handlers).
 *
 * Two behaviours on the dense advisory rail shown on detail/edit pages:
 *   1. A quick-filter <input data-advisory-rail-filter> hides non-matching
 *      rows (matched against data-rail-text = lowercased id + summary).
 *   2. On load, the active advisory is scrolled into view inside the
 *      (independently scrolling) rail so it isn't hidden below the fold.
 *
 * Delegation is used for the filter so it survives any HTMX-swapped fragment.
 */
(function () {
  "use strict";

  function filterRail(input) {
    var rail = input.closest(".advisory-rail");
    if (!rail) return;
    var q = input.value.trim().toLowerCase();
    var items = rail.querySelectorAll(".advisory-rail__item");
    var shown = 0;
    for (var i = 0; i < items.length; i++) {
      var hay = items[i].getAttribute("data-rail-text") || "";
      var match = q === "" || hay.indexOf(q) !== -1;
      items[i].hidden = !match;
      if (match) shown++;
    }
    var empty = rail.querySelector("[data-advisory-rail-empty]");
    if (empty) empty.hidden = items.length === 0 || shown !== 0;
  }

  document.addEventListener("input", function (event) {
    var target = event.target;
    if (!target || !target.closest) return;
    var input = target.closest("[data-advisory-rail-filter]");
    if (input) filterRail(input);
  });

  function revealActive() {
    var active = document.querySelector(".advisory-rail__item.is-active");
    if (active && typeof active.scrollIntoView === "function") {
      active.scrollIntoView({ block: "nearest" });
    }
  }

  if (document.readyState !== "loading") revealActive();
  else document.addEventListener("DOMContentLoaded", revealActive);
})();
