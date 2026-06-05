/* AdvisoryHub theme toggle — two-state: follow system ("auto") ↔ pinned override.
 *
 * The early bootstrap script in base.html has already set `<html data-theme>` and
 * `data-theme-pref` from the stored preference, so this file only wires the single
 * toggle button and reacts to system-theme changes while "auto" is selected.
 *
 * Model (per the dark-mode guidance — two-state, no redundant third state): the
 * control is one toggle. Default is "auto" (track the OS). Activating it PINS the
 * opposite of the current OS scheme (the only override a user would want);
 * activating again returns to "auto". A pinned scheme stays put even if the OS
 * later flips to match it. Stored prefs are unchanged ("light"/"dark"/"auto").
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

  function systemIsDark() {
    return !!(mql && mql.matches);
  }

  function apply(pref) {
    var dark = pref === "dark" || (pref === "auto" && systemIsDark());
    if (dark) {
      root.setAttribute("data-theme", "dark");
    } else {
      root.removeAttribute("data-theme");
    }
    root.setAttribute("data-theme-pref", pref); // drives which icon shows (CSS)
    syncToggle(pref);
  }

  function syncToggle(pref) {
    var btn = document.querySelector("[data-theme-toggle]");
    if (!btn) return;
    // aria-pressed reflects "override active" — i.e. anything other than auto.
    btn.setAttribute("aria-pressed", pref === "auto" ? "false" : "true");
    var label = btn.getAttribute("data-label-" + pref);
    if (label) {
      btn.setAttribute("aria-label", label);
      btn.setAttribute("title", label);
    }
  }

  function onClick() {
    var pref = readPref();
    // From "auto": pin the OPPOSITE of the current OS scheme. From a pinned
    // scheme: return to following the system.
    var next = pref === "auto" ? (systemIsDark() ? "light" : "dark") : "auto";
    storePref(next);
    apply(next);
  }

  function init() {
    // The early script set data-theme for paint; re-apply so aria-pressed and
    // the active label line up with the stored preference.
    apply(readPref());

    var btn = document.querySelector("[data-theme-toggle]");
    if (btn) btn.addEventListener("click", onClick);

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
