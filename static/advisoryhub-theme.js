/* AdvisoryHub theme toggle — light / dark / auto.
 *
 * The early bootstrap script in base.html has already set
 * `<html data-theme="dark">` (or removed it) based on the stored preference,
 * so this file only wires the segmented control and reacts to user clicks
 * and system-theme changes (when "auto" is selected).
 */
(function () {
  "use strict";

  var STORAGE_KEY = "advisoryhub.theme";
  var VALID = ["light", "dark", "auto"];
  var root = document.documentElement;
  var mql = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function readPref() {
    var v;
    try { v = localStorage.getItem(STORAGE_KEY); } catch (_) { v = null; }
    return VALID.indexOf(v) >= 0 ? v : "auto";
  }

  function storePref(v) {
    try { localStorage.setItem(STORAGE_KEY, v); } catch (_) { /* ignore */ }
  }

  function effectiveTheme(pref) {
    if (pref === "dark") return "dark";
    if (pref === "light") return "light";
    return mql && mql.matches ? "dark" : "light";
  }

  function apply(pref) {
    var eff = effectiveTheme(pref);
    if (eff === "dark") {
      root.setAttribute("data-theme", "dark");
    } else {
      root.removeAttribute("data-theme");
    }
    root.setAttribute("data-theme-pref", pref);
    syncButtons(pref);
  }

  function syncButtons(pref) {
    var buttons = document.querySelectorAll("[data-theme-pref-btn]");
    for (var i = 0; i < buttons.length; i++) {
      var b = buttons[i];
      var active = b.getAttribute("data-theme-pref-btn") === pref;
      b.setAttribute("aria-pressed", active ? "true" : "false");
    }
  }

  function onClick(evt) {
    var btn = evt.target.closest("[data-theme-pref-btn]");
    if (!btn) return;
    var pref = btn.getAttribute("data-theme-pref-btn");
    if (VALID.indexOf(pref) < 0) return;
    storePref(pref);
    apply(pref);
  }

  function init() {
    var pref = readPref();
    // The early script set `data-theme` for paint; re-apply so the toggle
    // UI's pressed-state lines up with the stored preference.
    apply(pref);

    var toggle = document.querySelector(".theme-toggle");
    if (toggle) toggle.addEventListener("click", onClick);

    if (mql && typeof mql.addEventListener === "function") {
      mql.addEventListener("change", function () {
        if (readPref() === "auto") apply("auto");
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
