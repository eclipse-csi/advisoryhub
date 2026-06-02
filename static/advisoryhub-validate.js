/* AdvisoryHub — live client-side field validation (CSP-clean: no inline handlers
 * or styles). One declarative controller; a field opts in with
 *   data-validate="<kind>"
 * and the per-kind rule below mirrors the server-side authority.
 *
 * Mechanism: setCustomValidity() makes the field participate in native validity,
 * so the existing `*:user-invalid` CSS (red border, advisoryhub.css) and the
 * `:user-invalid` -> `aria-invalid` bridge (advisoryhub-forms.js) react on their
 * own — but only AFTER the user has interacted (blur) or attempted submit, never
 * prematurely. The inline message text goes in a sibling `[data-validate-error]`
 * <small>, revealed by the same `:user-invalid` CSS gate.
 *
 * "datalist" kinds read their accepted values from the <datalist> the field's
 * `list=` already points at (single source of truth — no list copied into JS).
 * Delegation on `document` covers formset rows added dynamically and htmx swaps.
 */
(function () {
  "use strict";

  // Per-kind rules. Each mirrors a server-side check (cited):
  var KINDS = {
    // advisories.ecosystems.is_valid_ecosystem (base name, or base:suffix).
    ecosystem: {
      datalist: true,
      suffix: true,
      requiredSibling: "package_name",
      requiredMsg: "Ecosystem is required — choose one from the list (e.g. Maven, npm, PyPI).",
      invalidMsg:
        "Unknown ecosystem — pick one from the list (optionally with a ':' suffix, e.g. Debian:11).",
    },
    // advisories.validators.is_valid_purl (optional; shape check only).
    purl: {
      pattern: /^pkg:[A-Za-z0-9.+-]+\/\S+$/,
      invalidMsg: "Not a valid package URL — expected pkg:type/name, e.g. pkg:maven/org.example/lib.",
    },
    // intake.forms.clean_project_slug (a known project slug, or the __unsorted__
    // sentinel — both are <option>s in the #intake-projects datalist).
    project: {
      datalist: true,
      requiredAlways: true,
      requiredMsg: "Select a project from the list (or the “I do not know” option).",
      invalidMsg: "Unknown project — pick one from the list.",
    },
  };

  var listCache = {};

  function datalistValues(id) {
    if (!id) return null;
    if (listCache[id]) return listCache[id];
    var el = document.getElementById(id);
    if (!el) return null;
    var set = new Set();
    var opts = el.querySelectorAll("option");
    for (var i = 0; i < opts.length; i++) {
      if (opts[i].value) set.add(opts[i].value);
    }
    listCache[id] = set;
    return set;
  }

  function valueValid(input, cfg, value) {
    if (cfg.pattern) return cfg.pattern.test(value);
    var set = datalistValues(input.getAttribute("list"));
    if (!set || !set.size) return true; // can't validate without the catalog
    if (set.has(value)) return true;
    if (cfg.suffix) {
      var i = value.indexOf(":");
      if (i > 0 && i < value.length - 1) return set.has(value.slice(0, i));
    }
    return false;
  }

  function siblingFilled(input, suffix) {
    var row = input.closest(".affected-row");
    var sib = row && row.querySelector('input[name$="-' + suffix + '"]');
    return !!(sib && sib.value.trim());
  }

  function isRequired(input, cfg) {
    if (cfg.requiredAlways) return true;
    if (cfg.requiredSibling) return siblingFilled(input, cfg.requiredSibling);
    return false;
  }

  function errorEl(input) {
    var box = input.closest("p, .field") || input.parentElement;
    return box ? box.querySelector("[data-validate-error]") : null;
  }

  // Drop a server-rendered errorlist for this field once the user takes over, so
  // the live message doesn't stack on top of the POST-time one.
  function dropServerError(input) {
    var box = input.closest("p, .field");
    var list = box && box.querySelector("ul.errorlist");
    if (list) list.remove();
  }

  function validate(input) {
    var cfg = KINDS[input.dataset.validate];
    if (!cfg) return;
    var value = (input.value || "").trim();
    var msg = "";
    if (value === "") {
      if (isRequired(input, cfg)) msg = cfg.requiredMsg;
    } else if (!valueValid(input, cfg, value)) {
      msg = cfg.invalidMsg;
    }
    input.setCustomValidity(msg);
    var el = errorEl(input);
    if (el) el.textContent = msg;
  }

  function validateAll(root) {
    var inputs = (root || document).querySelectorAll("input[data-validate]");
    for (var i = 0; i < inputs.length; i++) validate(inputs[i]);
  }

  // A sibling field (e.g. package_name) flips the "required" state of a
  // data-validate input in the same affected row — re-check that row.
  function revalidateRowFrom(el) {
    var row = el.closest(".affected-row");
    if (!row) return;
    row.querySelectorAll("input[data-validate]").forEach(validate);
  }

  document.addEventListener("input", function (e) {
    var t = e.target;
    if (!(t instanceof Element)) return;
    if (t.matches("input[data-validate]")) {
      dropServerError(t);
      validate(t);
    } else if (t.matches('input[name$="-package_name"]')) {
      revalidateRowFrom(t);
    }
  });

  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!(t instanceof Element)) return;
    if (t.matches("input[data-validate]")) validate(t);
    else if (t.matches('input[name$="-package_name"]')) revalidateRowFrom(t);
  });

  document.addEventListener("focusout", function (e) {
    var t = e.target;
    if (t instanceof Element && t.matches("input[data-validate]")) {
      dropServerError(t);
      validate(t);
    }
  });

  // On a natively-validated form (the public intake form is NOT novalidate) an
  // invalid field blocks submit and the browser focuses it — open any enclosing
  // <details> so it's visible. No-op on the novalidate advisory form.
  document.addEventListener(
    "invalid",
    function (e) {
      var t = e.target;
      if (!(t instanceof Element) || !t.matches("input[data-validate]")) return;
      var details = t.closest("details");
      if (details && !details.open) details.open = true;
    },
    true
  );

  document.body.addEventListener("htmx:afterSwap", function (event) {
    listCache = {}; // a swapped fragment may carry a fresh datalist
    validateAll(event.target);
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      validateAll(document);
    });
  } else {
    validateAll(document);
  }
})();
