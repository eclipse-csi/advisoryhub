// Makes <tr data-href="..."> rows clickable anywhere except on nested
// interactive elements (links, buttons, form controls, details/summary, or
// anything marked [data-no-row-click]). Honours modifier keys / middle-click
// for open-in-new-tab.
//
// This is a POINTER convenience only. Keyboard and screen-reader users use the
// real <a> in the row's first cell (the canonical affordance) — the row itself
// is intentionally NOT a focus stop, since a focusable <tr> with no role/name
// is announced as concatenated cell text and duplicates that link.
(function () {
  "use strict";

  var INTERACTIVE = "a, button, input, textarea, select, label, form, summary, details, [data-no-row-click]";

  function rowFor(target) {
    if (!(target instanceof Element)) return null;
    if (target.closest(INTERACTIVE)) return null;
    return target.closest("tr[data-href]");
  }

  function navigate(row, openInNewTab) {
    var href = row.getAttribute("data-href");
    if (!href) return;
    if (openInNewTab) {
      window.open(href, "_blank", "noopener");
    } else {
      window.location.href = href;
    }
  }

  document.addEventListener("click", function (e) {
    if (e.defaultPrevented) return;
    if (e.button !== 0) return;
    var row = rowFor(e.target);
    if (!row) return;
    navigate(row, e.metaKey || e.ctrlKey || e.shiftKey);
  });

  document.addEventListener("auxclick", function (e) {
    if (e.button !== 1) return;
    var row = rowFor(e.target);
    if (!row) return;
    e.preventDefault();
    navigate(row, true);
  });
})();
