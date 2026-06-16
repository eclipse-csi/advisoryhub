/* Smart combobox enhancement for long <select> menus (project & group pickers).
 *
 * Progressive enhancement, opt-in via `data-combobox` on a single <select>:
 *
 *   <select name="project" data-combobox aria-label="Project">…options…</select>
 *
 * On enhancement the native <select> is hidden (but kept in the DOM, named and
 * enabled, so it still submits normally) and a text input + floating listbox
 * take its place. Typing filters the select's own <option>s by substring
 * (label or value, case-insensitive); picking one writes the value back to the
 * <select> and dispatches a native `change` event, so server-side form handling
 * and any HTMX `from:select` triggers behave exactly as before. With JS off the
 * native <select> stays fully usable — nothing here hides it.
 *
 * Same interaction / ARIA model as the CWE and @-mention comboboxes
 * (advisoryhub-cwe.js / -mentions.js); the data source here is the <select>
 * itself rather than a JSON catalog, which is what keeps it generic. CSP: no
 * inline handlers — everything is delegated on document, and selects inserted
 * later (e.g. via an HTMX swap) are picked up by a MutationObserver.
 */
(function () {
  "use strict";

  var MAX_RESULTS = 100;
  var PANEL_ID = "select-combobox-panel";
  var panel = null;
  var activeInput = null;
  var activeIndex = -1;
  var matches = [];
  var truncated = false;

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function isComboInput(t) {
    return t instanceof HTMLInputElement && t.classList.contains("combobox__input") && t._cbSelect;
  }

  // ---- model: read straight from the native <select> --------------------

  function optionsOf(select) {
    var out = [];
    var opts = select.options;
    for (var i = 0; i < opts.length; i++) {
      if (opts[i].disabled) continue;
      // A required select's empty option is a placeholder, not a real choice.
      if (select._cbSkipEmpty && opts[i].value === "") continue;
      out.push({
        value: opts[i].value,
        label: (opts[i].textContent || "").trim(),
        // Optional secondary text (e.g. a project slug) shown on a second line
        // and folded into the match — set per <option> via data-combobox-detail.
        detail: (opts[i].getAttribute("data-combobox-detail") || "").trim(),
      });
    }
    return out;
  }

  function currentLabel(select) {
    var o = select.options[select.selectedIndex];
    if (!o || (select._cbSkipEmpty && o.value === "")) return "";
    return (o.textContent || "").trim();
  }

  function filterOptions(select, query) {
    var data = optionsOf(select);
    var q = (query || "").toLowerCase().trim();
    var out = [];
    truncated = false;
    for (var i = 0; i < data.length; i++) {
      if (
        !q ||
        data[i].label.toLowerCase().indexOf(q) !== -1 ||
        data[i].value.toLowerCase().indexOf(q) !== -1 ||
        (data[i].detail && data[i].detail.toLowerCase().indexOf(q) !== -1)
      ) {
        if (out.length >= MAX_RESULTS) {
          truncated = true;
          break;
        }
        out.push(data[i]);
      }
    }
    return out;
  }

  // ---- floating panel (singleton, body-positioned like the siblings) ----

  function ensurePanel() {
    // Rebuild if a previous host (e.g. a modal dialog the panel was parented
    // into, see panelParent) was torn down and took the panel out of the DOM.
    if (panel && panel.isConnected) return panel;
    panel = document.createElement("div");
    panel.id = PANEL_ID;
    panel.className = "combobox-panel";
    panel.setAttribute("role", "listbox");
    panel.hidden = true;
    // Keep the wheel on the list: translate the delta to scrollTop and
    // preventDefault so it never chains to the page's root scroller (the wanted
    // behaviour for an open dropdown everywhere). Belt-and-braces alongside
    // `overscroll-behavior: contain`. `passive: false` so we may preventDefault.
    // deltaMode: 0=pixels, 1=lines, 2=pages.
    panel.addEventListener(
      "wheel",
      function (e) {
        if (!isOpen()) return;
        var f = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? panel.clientHeight : 1;
        panel.scrollTop += e.deltaY * f;
        e.preventDefault();
      },
      { passive: false }
    );
    document.body.appendChild(panel);
    return panel;
  }

  // Where the panel must live to both paint above its surroundings and receive
  // events from them. A modal <dialog> (showModal()) sits in the top layer and
  // makes the rest of the document (incl. <body>) inert, so a body-level panel
  // is painted *behind* the dialog and can't receive pointer/wheel events.
  // Making the panel a *descendant of the open dialog* fixes both: a positioned
  // child paints above the dialog's own content, and — being inside the
  // (non-inert) dialog subtree — it receives wheel/click directly, exactly like
  // the dialog's own form fields do.
  //
  // We deliberately do NOT promote the panel to the top layer (popover): a
  // top-layer popover nested in a modal dialog has inconsistent wheel/pointer
  // event delivery across engines — fine in Chromium, but the events fall
  // through to the page behind in WebKit/Firefox. A plain positioned descendant
  // is engine-agnostic.
  function panelParent() {
    if (activeInput) {
      var dlg = activeInput.closest("dialog");
      if (dlg && dlg.open) return dlg;
    }
    return document.body;
  }

  // Reparent the panel under the right host (the open dialog, or <body>) and
  // toggle visibility with the ``hidden`` attribute. ``isOpen`` is the single
  // "is the panel visible" predicate.
  function showPanel() {
    var p = ensurePanel();
    var parent = panelParent();
    if (p.parentNode !== parent) parent.appendChild(p);
    p.hidden = false;
  }

  function hidePanel() {
    if (!panel) return;
    panel.hidden = true;
    // Park the singleton back on <body> between sessions so a closing host
    // dialog (whose subtree gets cleared) can't take the panel down with it.
    if (panel.parentNode !== document.body) document.body.appendChild(panel);
  }

  function isOpen() {
    return !!panel && !panel.hidden;
  }

  function optionId(i) {
    return "select-combobox-opt-" + i;
  }

  function positionPanel(input) {
    var rect = input.getBoundingClientRect();
    var p = ensurePanel();
    // Viewport-relative fixed positioning works whether the panel sits on <body>
    // or is reparented inside a modal dialog (no combobox host establishes a
    // transformed containing block, so `fixed` stays viewport-relative). The
    // capture-phase scroll/resize listeners re-run this to follow the input.
    p.style.position = "fixed";
    p.style.left = rect.left + "px";
    p.style.top = rect.bottom + 2 + "px";
    p.style.minWidth = Math.max(rect.width, 240) + "px";
  }

  // `queryOverride` lets focus open the full list (current value highlighted)
  // rather than filtering by the displayed label, which is otherwise selected
  // text waiting to be replaced. Typing (the `input` event) filters normally.
  function render(input, queryOverride) {
    var select = input._cbSelect;
    if (!select) return;
    matches = filterOptions(select, queryOverride != null ? queryOverride : input.value);

    // Land the active row on the currently-selected value when it survives the
    // filter, so opening a long list highlights (and scrolls to) the current
    // choice rather than always jumping to the top.
    activeIndex = matches.length ? 0 : -1;
    for (var k = 0; k < matches.length; k++) {
      if (matches[k].value === select.value) {
        activeIndex = k;
        break;
      }
    }

    var p = ensurePanel();
    if (!matches.length) {
      p.innerHTML = '<div class="combobox-empty">No matches</div>';
    } else {
      var html = "";
      for (var i = 0; i < matches.length; i++) {
        var m = matches[i];
        var on = i === activeIndex;
        var cur = m.value === select.value;
        html +=
          '<div class="combobox-option' +
          (on ? " is-active" : "") +
          (cur ? " is-current" : "") +
          '" id="' +
          optionId(i) +
          '" role="option" aria-selected="' +
          (on ? "true" : "false") +
          '" data-cb-index="' +
          i +
          '"><span class="combobox-option__text"><span class="combobox-option__label">' +
          escapeHtml(m.label || "—") +
          "</span>" +
          (m.detail ? '<span class="combobox-option__detail">' + escapeHtml(m.detail) + "</span>" : "") +
          "</span></div>";
      }
      if (truncated) {
        html += '<div class="combobox-empty">Showing first ' + MAX_RESULTS + " — keep typing to narrow…</div>";
      }
      p.innerHTML = html;
    }
    input.setAttribute("aria-expanded", "true");
    if (activeIndex >= 0) input.setAttribute("aria-activedescendant", optionId(activeIndex));
    else input.removeAttribute("aria-activedescendant");
    // Position the (still-hidden) panel first, then reveal, so it never paints
    // for a frame at a stale position.
    positionPanel(input);
    showPanel();
    // Bring the active row into view so opening a long list lands on the
    // current choice rather than the top.
    if (activeIndex >= 0) {
      var act = p.querySelector(".combobox-option.is-active");
      if (act && act.scrollIntoView) act.scrollIntoView({ block: "nearest" });
    }
  }

  function hide() {
    hidePanel();
    if (activeInput) {
      activeInput.setAttribute("aria-expanded", "false");
      activeInput.removeAttribute("aria-activedescendant");
    }
    activeInput = null;
    matches = [];
    activeIndex = -1;
  }

  function commit(input, opt) {
    var select = input._cbSelect;
    if (!select) return;
    if (select.value !== opt.value) {
      select.value = opt.value;
      // Mirror a real user selection so form handlers / HTMX `from:select` fire.
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    input.value = opt.label;
    hide();
  }

  // On blur, free-form text that didn't resolve to an option is discarded: the
  // input snaps back to the <select>'s current value (a select always has one).
  function revert(input) {
    var select = input._cbSelect;
    if (select) input.value = currentLabel(select);
  }

  function moveActive(delta) {
    if (!matches.length) return;
    activeIndex = (activeIndex + delta + matches.length) % matches.length;
    var nodes = ensurePanel().querySelectorAll(".combobox-option");
    for (var i = 0; i < nodes.length; i++) {
      var on = i === activeIndex;
      nodes[i].classList.toggle("is-active", on);
      nodes[i].setAttribute("aria-selected", on ? "true" : "false");
      if (on && nodes[i].scrollIntoView) nodes[i].scrollIntoView({ block: "nearest" });
    }
    if (activeInput) activeInput.setAttribute("aria-activedescendant", optionId(activeIndex));
  }

  // ---- enhancement -------------------------------------------------------

  function wire(select) {
    if (select.dataset.comboboxReady === "1") return;
    if (select.multiple || select.disabled) return;
    select.dataset.comboboxReady = "1";

    // A required <select> needs an empty first <option> so "nothing chosen" is
    // representable; treat that option as a placeholder (surfaced as the input's
    // placeholder text, never a pickable row), not a selectable value.
    var skipEmpty = select.required;
    select._cbSkipEmpty = skipEmpty;

    var input = document.createElement("input");
    input.type = "text";
    input.className = "combobox__input";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-haspopup", "listbox");
    input.setAttribute("aria-expanded", "false");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-controls", PANEL_ID);

    var ph = select.getAttribute("data-combobox-placeholder");
    if (!ph && skipEmpty) {
      for (var pi = 0; pi < select.options.length; pi++) {
        if (select.options[pi].value === "") {
          ph = (select.options[pi].textContent || "").trim();
          break;
        }
      }
    }
    if (ph) input.placeholder = ph;

    var aria = select.getAttribute("aria-label");
    if (aria) input.setAttribute("aria-label", aria);

    // Inherit the select's id so an existing <label for=…> targets the input
    // instead; the now-hidden select keeps the same name (and a suffixed id) so
    // form submission is unchanged. An implicit wrapping <label> (no `for`)
    // associates with the input automatically once it's the first control.
    if (select.id) {
      var origId = select.id;
      select.id = origId + "-native";
      input.id = origId;
    }

    input._cbSelect = select;
    // Move `required` to the visible input — a hidden <select> that stays
    // `required` is an unfocusable invalid control that silently blocks native
    // submission; enforce it where the user can actually see and fix it.
    if (select.required) {
      input.required = true;
      select.required = false;
    }
    select.hidden = true;
    select.setAttribute("tabindex", "-1");
    select.parentNode.insertBefore(input, select);
    input.value = currentLabel(select);
  }

  function wireAll(root) {
    var scope = root && root.querySelectorAll ? root : document;
    scope.querySelectorAll("select[data-combobox]").forEach(wire);
  }

  // ---- event wiring (all delegated; CSP-safe) ---------------------------

  document.addEventListener("focusin", function (e) {
    if (!isComboInput(e.target)) return;
    activeInput = e.target;
    // Select the shown text so the next keystroke replaces it — lets the user
    // re-filter a committed value without clearing it first (mirrors the CWE box).
    try {
      e.target.select();
    } catch (_e) {}
    render(e.target, ""); // show the full list on focus, not just the current value
  });

  document.addEventListener("input", function (e) {
    if (!isComboInput(e.target)) return;
    activeInput = e.target;
    render(e.target);
  });

  // Commit on mousedown so focus stays on the input and the blur/revert handler
  // doesn't fire before the click registers.
  document.addEventListener("mousedown", function (e) {
    if (!isOpen() || !activeInput) return;
    var opt = e.target.closest && e.target.closest(".combobox-option");
    if (!opt) return;
    e.preventDefault();
    var idx = parseInt(opt.getAttribute("data-cb-index"), 10);
    if (matches[idx]) commit(activeInput, matches[idx]);
  });

  document.addEventListener("keydown", function (e) {
    if (!activeInput || !isOpen()) return;
    if (!isComboInput(e.target)) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      moveActive(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      moveActive(-1);
    } else if (e.key === "Enter") {
      if (activeIndex >= 0 && matches[activeIndex]) {
        e.preventDefault();
        commit(activeInput, matches[activeIndex]);
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      revert(e.target);
      hide();
    }
  });

  document.addEventListener("focusout", function (e) {
    if (!isComboInput(e.target)) return;
    var input = e.target;
    revert(input);
    // Defer so an option mousedown can commit first. Only close if focus didn't
    // jump straight to another combobox (which shares this one panel).
    setTimeout(function () {
      if (activeInput === input || activeInput === null) hide();
    }, 50);
  });

  window.addEventListener(
    "scroll",
    function () {
      if (activeInput && isOpen()) positionPanel(activeInput);
    },
    true
  );

  window.addEventListener("resize", function () {
    if (activeInput && isOpen()) positionPanel(activeInput);
  });

  // Enhance existing selects, then watch for ones inserted later (HTMX swaps,
  // dynamically rendered fragments) — the same pattern advisoryhub-cwe.js uses.
  function initAndObserve() {
    wireAll(document);
    if (!("MutationObserver" in window)) return;
    var mo = new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var n = added[j];
          if (!(n instanceof Element)) continue;
          if (n.matches && n.matches("select[data-combobox]")) wire(n);
          if (n.querySelectorAll) wireAll(n);
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
