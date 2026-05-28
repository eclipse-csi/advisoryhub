/* Combobox for the CWE field on the advisory form.
 *
 * Markup contract (form.html):
 *   <script type="application/json" id="cwe-catalog-data">[{id,name,abstraction},…]</script>
 *
 *   <!-- one row per formset entry -->
 *   <input type="hidden" name="cwe_ids-0-value" data-cwe-hidden …>
 *   <input type="text"    data-cwe-input data-cwe-target="cwe_ids-0-value" …>
 *
 * The hidden input is the only one that gets submitted; the server-side
 * validator rejects anything not in the vendored MITRE catalog. The
 * visible input is purely for display and search: it shows
 * "CWE-NN — Name" once a row is committed, and the user can edit it to
 * filter the dropdown (by id or name fragment, case-insensitive).
 *
 * Newly-added formset rows are picked up via a MutationObserver so the
 * combobox lights up without coordination from advisoryhub-formsets.js.
 */
(function () {
  "use strict";

  var MAX_RESULTS = 50;
  var catalog = null;
  var catalogById = null;
  var panel = null;
  var activeInput = null;
  var activeIndex = -1;
  var matches = [];

  function loadCatalog() {
    if (catalog) return catalog;
    var el = document.getElementById("cwe-catalog-data");
    if (!el) { catalog = []; catalogById = {}; return catalog; }
    try {
      var data = JSON.parse(el.textContent);
      catalog = Array.isArray(data) ? data : (data.weaknesses || []);
    } catch (_e) {
      catalog = [];
    }
    catalogById = {};
    for (var i = 0; i < catalog.length; i++) catalogById[catalog[i].id] = catalog[i];
    return catalog;
  }

  function lookup(id) {
    loadCatalog();
    return catalogById[(id || "").toUpperCase()] || null;
  }

  function cssEscape(s) {
    if (window.CSS && window.CSS.escape) return window.CSS.escape(s);
    return String(s).replace(/(["\\])/g, "\\$1");
  }

  function hiddenFor(input) {
    var name = input.getAttribute("data-cwe-target");
    if (!name) return null;
    return document.querySelector('input[name="' + cssEscape(name) + '"]');
  }

  function displayFor(entry) {
    return entry ? entry.id + " — " + entry.name : "";
  }

  // Mark which display inputs we've initialised, so we don't overwrite
  // text the user is in the middle of editing on subsequent renders.
  function initInput(input) {
    if (input.dataset.cweInit === "1") return;
    input.dataset.cweInit = "1";
    var h = hiddenFor(input);
    if (!h) return;
    var id = (h.value || "").trim().toUpperCase();
    if (!id) return;
    var entry = lookup(id);
    if (entry) input.value = displayFor(entry);
  }

  function initExisting() {
    document.querySelectorAll("[data-cwe-input]").forEach(initInput);
  }

  function ensurePanel() {
    if (panel) return panel;
    panel = document.createElement("div");
    panel.className = "cwe-combobox-panel";
    panel.setAttribute("role", "listbox");
    panel.hidden = true;
    document.body.appendChild(panel);
    return panel;
  }

  function positionPanel(input) {
    var rect = input.getBoundingClientRect();
    var p = ensurePanel();
    p.style.position = "absolute";
    p.style.left = (window.scrollX + rect.left) + "px";
    p.style.top = (window.scrollY + rect.bottom + 2) + "px";
    p.style.minWidth = Math.max(rect.width, 280) + "px";
  }

  function filter(query) {
    var data = loadCatalog();
    if (!data.length) return [];
    var q = (query || "").toLowerCase().trim();
    if (!q) return data.slice(0, MAX_RESULTS);

    var numMatch = q.match(/^(?:cwe-)?(\d+)$/);
    var out = [];
    if (numMatch) {
      var prefix = "cwe-" + numMatch[1];
      for (var i = 0; i < data.length && out.length < MAX_RESULTS; i++) {
        var idLow = data[i].id.toLowerCase();
        if (idLow === prefix || idLow.indexOf(prefix) === 0) out.push(data[i]);
      }
      if (out.length) return out;
    }
    for (var j = 0; j < data.length && out.length < MAX_RESULTS; j++) {
      if (data[j].id.toLowerCase().indexOf(q) !== -1 ||
          data[j].name.toLowerCase().indexOf(q) !== -1) {
        out.push(data[j]);
      }
    }
    return out;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function render(input) {
    matches = filter(input.value);
    activeIndex = matches.length ? 0 : -1;
    var p = ensurePanel();
    if (!matches.length) {
      p.innerHTML = '<div class="cwe-combobox-empty">No matching CWE</div>';
    } else {
      var html = "";
      for (var i = 0; i < matches.length; i++) {
        var w = matches[i];
        html +=
          '<div class="cwe-combobox-option' + (i === activeIndex ? " is-active" : "") +
          '" role="option" data-cwe-id="' + w.id + '">' +
          '<strong>' + w.id + '</strong> <span>' + escapeHtml(w.name) + '</span>' +
          '</div>';
      }
      p.innerHTML = html;
    }
    p.hidden = false;
    positionPanel(input);
  }

  function hide() {
    if (panel) panel.hidden = true;
    activeInput = null;
    matches = [];
    activeIndex = -1;
  }

  function commit(input, entry) {
    var h = hiddenFor(input);
    if (h) h.value = entry.id;
    input.value = displayFor(entry);
    hide();
  }

  function clear(input) {
    var h = hiddenFor(input);
    if (h) h.value = "";
    input.value = "";
  }

  function moveActive(delta) {
    if (!matches.length) return;
    activeIndex = (activeIndex + delta + matches.length) % matches.length;
    var nodes = ensurePanel().querySelectorAll(".cwe-combobox-option");
    for (var i = 0; i < nodes.length; i++) {
      var on = i === activeIndex;
      nodes[i].classList.toggle("is-active", on);
      if (on && nodes[i].scrollIntoView) nodes[i].scrollIntoView({ block: "nearest" });
    }
  }

  function resolveOnBlur(input) {
    var v = (input.value || "").trim();
    if (!v) { clear(input); return; }

    // 1. Exact id ("CWE-79", "cwe-79", "79")
    var num = v.match(/^(?:cwe-?)?(\d+)$/i);
    if (num) {
      var entry = lookup("CWE-" + num[1]);
      if (entry) { commit(input, entry); return; }
    }

    // 2. The current display string ("CWE-79 — Name") — typical no-edit blur.
    var idPart = v.match(/^(CWE-\d+)\b/i);
    if (idPart) {
      var byId = lookup(idPart[1]);
      if (byId) { commit(input, byId); return; }
    }

    // 3. Exact name match (case-insensitive)
    var data = loadCatalog();
    var ql = v.toLowerCase();
    for (var i = 0; i < data.length; i++) {
      if (data[i].name.toLowerCase() === ql) { commit(input, data[i]); return; }
    }

    // 4. Couldn't resolve — drop both so the empty formset row is ignored
    // on submit. Free-form text is never accepted.
    clear(input);
  }

  // ---- event wiring -----------------------------------------------------

  document.addEventListener("focusin", function (e) {
    var t = e.target;
    if (t instanceof HTMLInputElement && t.matches("[data-cwe-input]")) {
      initInput(t);
      activeInput = t;
      // Highlight existing text so the next keystroke replaces it; lets
      // users edit a committed row without having to manually clear first.
      try { t.select(); } catch (_e) {}
      render(t);
    }
  });

  document.addEventListener("input", function (e) {
    var t = e.target;
    if (t instanceof HTMLInputElement && t.matches("[data-cwe-input]")) {
      activeInput = t;
      render(t);
    }
  });

  // Commit via mousedown so we can preventDefault and keep focus on the
  // input; this avoids the blur handler firing before the click registers.
  document.addEventListener("mousedown", function (e) {
    if (!panel || panel.hidden) return;
    var opt = e.target.closest && e.target.closest(".cwe-combobox-option");
    if (opt && activeInput) {
      e.preventDefault();
      var entry = lookup(opt.dataset.cweId);
      if (entry) commit(activeInput, entry);
    }
  });

  document.addEventListener("focusout", function (e) {
    var t = e.target;
    if (t instanceof HTMLInputElement && t.matches("[data-cwe-input]")) {
      resolveOnBlur(t);
      setTimeout(hide, 50);
    }
  });

  document.addEventListener("keydown", function (e) {
    if (!activeInput || !panel || panel.hidden) return;
    if (e.key === "ArrowDown") { e.preventDefault(); moveActive(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveActive(-1); }
    else if (e.key === "Enter") {
      if (activeIndex >= 0 && matches[activeIndex]) {
        e.preventDefault();
        commit(activeInput, matches[activeIndex]);
      }
    }
    else if (e.key === "Escape") { e.preventDefault(); hide(); }
  });

  window.addEventListener("scroll", function () {
    if (activeInput && panel && !panel.hidden) positionPanel(activeInput);
  }, true);

  window.addEventListener("resize", function () {
    if (activeInput && panel && !panel.hidden) positionPanel(activeInput);
  });

  // Initialise existing rows on first load and observe future inserts
  // (formset add-row button clones a template without notifying us).
  function initAndObserve() {
    initExisting();
    if (!("MutationObserver" in window)) return;
    var mo = new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var n = added[j];
          if (!(n instanceof Element)) continue;
          if (n.matches && n.matches("[data-cwe-input]")) initInput(n);
          if (n.querySelectorAll) n.querySelectorAll("[data-cwe-input]").forEach(initInput);
        }
      }
    });
    mo.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAndObserve);
  } else {
    initAndObserve();
  }
})();
