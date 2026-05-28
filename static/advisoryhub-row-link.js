// Makes <tr data-href="..."> rows clickable anywhere except on nested
// interactive elements (links, buttons, form controls, details/summary,
// or anything marked [data-no-row-click]). Honours modifier keys for
// open-in-new-tab and supports Enter/Space keyboard activation.
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

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" && e.key !== " ") return;
    if (!(e.target instanceof Element)) return;
    if (e.target.closest(INTERACTIVE)) return;
    var row = e.target.closest("tr[data-href]");
    if (!row || row !== e.target) return;
    e.preventDefault();
    navigate(row, e.metaKey || e.ctrlKey);
  });

  // Make rows focusable so keyboard users can reach them.
  function makeFocusable(root) {
    var rows = (root || document).querySelectorAll("tr[data-href]:not([tabindex])");
    for (var i = 0; i < rows.length; i++) {
      rows[i].setAttribute("tabindex", "0");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { makeFocusable(); });
  } else {
    makeFocusable();
  }

  // Pick up rows swapped in by HTMX.
  document.addEventListener("htmx:afterSwap", function (e) {
    makeFocusable(e.target);
  });
})();
