/* @-mention completion for comment textareas.
 *
 * Markup contract (advisories/detail.html):
 *   <script type="application/json" id="mention-candidates">
 *     [{"kind":"group"|"user","handle":"…","label":"…"}, …]
 *   </script>
 *   <textarea data-mention-input …></textarea>   (comment create + edit forms)
 *
 * The candidate list is scoped server-side to the advisory's visible groups +
 * members + direct grantees (comments.services.mention_candidates) — never the
 * whole user DB. Picking an entry inserts "@<handle> " at the caret; the server
 * re-resolves and re-checks visibility at send time, so the menu is purely a
 * convenience, never an authority.
 *
 * CSP: no inline handlers — everything is delegated on document. The JSON lives
 * in the stable parent page, so it survives the HTMX swaps that re-render the
 * comment form/edit form, and no per-element init (or MutationObserver) is
 * needed.
 */
(function () {
  "use strict";

  var MAX_RESULTS = 50;
  var PANEL_ID = "mention-combobox-panel";
  // "@" + a run of handle characters at the end of the text before the caret,
  // anchored to a word boundary so e-mail addresses (foo@bar) don't trigger it.
  var TOKEN_RE = /(^|[\s(])@([\w.\-+]*)$/;

  var candidates = null;
  var panel = null;
  var activeInput = null;
  var activeIndex = -1;
  var matches = [];

  function loadCandidates() {
    if (candidates) return candidates;
    var el = document.getElementById("mention-candidates");
    if (!el) return [];
    try {
      var data = JSON.parse(el.textContent);
      candidates = Array.isArray(data) ? data : [];
    } catch (_e) {
      candidates = [];
    }
    return candidates;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function ensurePanel() {
    if (panel) return panel;
    panel = document.createElement("div");
    panel.id = PANEL_ID;
    panel.className = "mention-combobox-panel";
    panel.setAttribute("role", "listbox");
    panel.setAttribute("aria-label", "Mention suggestions");
    panel.hidden = true;
    document.body.appendChild(panel);
    return panel;
  }

  function optionId(i) {
    return "mention-opt-" + i;
  }

  // The partial token being typed (text between "@" and the caret), or null
  // when the caret is not inside a mention.
  function currentToken(input) {
    if (typeof input.selectionStart !== "number") return null;
    var before = input.value.slice(0, input.selectionStart);
    var m = before.match(TOKEN_RE);
    if (!m) return null;
    return { query: m[2], start: m.index + m[1].length, end: input.selectionStart };
  }

  function filter(query) {
    var data = loadCandidates();
    if (!data.length) return [];
    var q = (query || "").toLowerCase();
    var out = [];
    for (var i = 0; i < data.length && out.length < MAX_RESULTS; i++) {
      var c = data[i];
      if (
        !q ||
        c.handle.toLowerCase().indexOf(q) === 0 ||
        c.label.toLowerCase().indexOf(q) !== -1
      ) {
        out.push(c);
      }
    }
    return out;
  }

  function positionPanel(input) {
    var rect = input.getBoundingClientRect();
    var p = ensurePanel();
    p.style.position = "absolute";
    p.style.left = window.scrollX + rect.left + "px";
    p.style.top = window.scrollY + rect.bottom + 2 + "px";
    p.style.minWidth = Math.max(rect.width, 260) + "px";
  }

  function render(input, query) {
    matches = filter(query);
    activeIndex = matches.length ? 0 : -1;
    var p = ensurePanel();
    if (!matches.length) {
      p.innerHTML = '<div class="mention-combobox-empty">No matches</div>';
    } else {
      var html = "";
      for (var i = 0; i < matches.length; i++) {
        var c = matches[i];
        var on = i === activeIndex;
        html +=
          '<div class="mention-combobox-option' +
          (on ? " is-active" : "") +
          '" id="' +
          optionId(i) +
          '" role="option" aria-selected="' +
          (on ? "true" : "false") +
          '" data-mention-index="' +
          i +
          '"><span class="mention-combobox-kind">' +
          (c.kind === "group" ? "group" : "user") +
          "</span> " +
          escapeHtml(c.label) +
          "</div>";
      }
      p.innerHTML = html;
    }
    p.hidden = false;
    input.setAttribute("aria-expanded", "true");
    input.setAttribute("aria-controls", PANEL_ID);
    if (activeIndex >= 0) input.setAttribute("aria-activedescendant", optionId(activeIndex));
    else input.removeAttribute("aria-activedescendant");
    positionPanel(input);
  }

  function hide() {
    if (panel) panel.hidden = true;
    if (activeInput) {
      activeInput.setAttribute("aria-expanded", "false");
      activeInput.removeAttribute("aria-activedescendant");
    }
    matches = [];
    activeIndex = -1;
  }

  function moveActive(delta) {
    if (!matches.length) return;
    activeIndex = (activeIndex + delta + matches.length) % matches.length;
    var nodes = ensurePanel().querySelectorAll(".mention-combobox-option");
    for (var i = 0; i < nodes.length; i++) {
      var on = i === activeIndex;
      nodes[i].classList.toggle("is-active", on);
      nodes[i].setAttribute("aria-selected", on ? "true" : "false");
      if (on && nodes[i].scrollIntoView) nodes[i].scrollIntoView({ block: "nearest" });
    }
    if (activeInput) activeInput.setAttribute("aria-activedescendant", optionId(activeIndex));
  }

  function commit(input, entry) {
    var token = currentToken(input);
    if (!token) {
      hide();
      return;
    }
    var before = input.value.slice(0, token.start) + "@" + entry.handle + " ";
    var caret = before.length;
    input.value = before + input.value.slice(token.end);
    try {
      input.setSelectionRange(caret, caret);
    } catch (_e) {}
    input.focus();
    hide();
  }

  function refresh(input) {
    activeInput = input;
    var token = currentToken(input);
    if (!token) {
      hide();
      return;
    }
    render(input, token.query);
  }

  // ---- event wiring -------------------------------------------------------

  function isMentionInput(t) {
    return t instanceof HTMLTextAreaElement && t.matches("[data-mention-input]");
  }

  document.addEventListener("input", function (e) {
    if (isMentionInput(e.target)) refresh(e.target);
  });

  document.addEventListener("focusin", function (e) {
    if (isMentionInput(e.target)) refresh(e.target);
  });

  // Caret moves via click/arrow keys can change whether we're inside a token.
  document.addEventListener("keyup", function (e) {
    if (!isMentionInput(e.target)) return;
    if (e.key === "ArrowUp" || e.key === "ArrowDown" || e.key === "Enter" || e.key === "Escape") {
      return; // handled in keydown
    }
    refresh(e.target);
  });

  document.addEventListener("click", function (e) {
    if (isMentionInput(e.target)) refresh(e.target);
  });

  // Commit via mousedown so focus stays on the textarea and the blur handler
  // doesn't fire before the click registers.
  document.addEventListener("mousedown", function (e) {
    if (!panel || panel.hidden) return;
    var opt = e.target.closest && e.target.closest(".mention-combobox-option");
    if (opt && activeInput) {
      e.preventDefault();
      var idx = parseInt(opt.getAttribute("data-mention-index"), 10);
      if (matches[idx]) commit(activeInput, matches[idx]);
    }
  });

  document.addEventListener("keydown", function (e) {
    if (!activeInput || !panel || panel.hidden) return;
    if (!isMentionInput(e.target)) return;
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
      hide();
    }
  });

  document.addEventListener("focusout", function (e) {
    if (isMentionInput(e.target)) setTimeout(hide, 80);
  });

  window.addEventListener(
    "scroll",
    function () {
      if (activeInput && panel && !panel.hidden) positionPanel(activeInput);
    },
    true
  );

  window.addEventListener("resize", function () {
    if (activeInput && panel && !panel.hidden) positionPanel(activeInput);
  });
})();
