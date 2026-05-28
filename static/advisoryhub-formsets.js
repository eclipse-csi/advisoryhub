/* Dynamic add/remove rows for Django formsets on the advisory form.
 *
 * Markup contract (rendered server-side by templates/advisories/form.html):
 *   <div class="formset-rows" data-formset-prefix="X">…rows…</div>
 *   <template class="empty-form-template" data-prefix="X">…one row…</template>
 *   <button class="add-row-btn" data-prefix="X">+ Add</button>
 *
 * Django uses the literal "__prefix__" placeholder in form input names; we
 * substitute it with the current TOTAL_FORMS value when cloning a row.
 *
 * Nested case: the "affected" outer empty-form embeds an inner events
 * empty-form whose own "__prefix__" placeholder must survive the outer
 * substitution. The inner names look like
 *
 *     affected-__prefix__-events-__prefix__-kind
 *
 * where the first `__prefix__` is the outer affected index (and must be
 * replaced when the outer row is cloned) and the second is the inner event
 * index (and must be preserved for later inner cloning). They are
 * distinguishable by the literal text immediately before them — the inner
 * one is always preceded by "events-". The outer-row clone path uses a
 * negative-lookbehind regex to skip inner-index placeholders; every other
 * clone path does a plain global replace.
 */
(function () {
  "use strict";

  var OUTER_AFFECTED_PREFIX = "affected";

  function cssEscape(s) {
    if (window.CSS && window.CSS.escape) return window.CSS.escape(s);
    return String(s).replace(/(["\\])/g, "\\$1");
  }

  function findContainer(prefix) {
    return document.querySelector(
      '.formset-rows[data-formset-prefix="' + cssEscape(prefix) + '"]'
    );
  }

  function findTemplate(prefix) {
    return document.querySelector(
      'template.empty-form-template[data-prefix="' + cssEscape(prefix) + '"]'
    );
  }

  function totalFormsInput(prefix) {
    return document.querySelector(
      'input[name="' + cssEscape(prefix) + '-TOTAL_FORMS"]'
    );
  }

  function substitutePrefix(html, idx, prefix) {
    var s = String(idx);
    if (prefix === OUTER_AFFECTED_PREFIX) {
      // Skip placeholders that are part of the inner events formset's
      // row index (preceded by "events-"). Substitute every other one.
      return html.replace(/(?<!events-)__prefix__/g, s);
    }
    return html.replaceAll("__prefix__", s);
  }

  function addRow(prefix) {
    var container = findContainer(prefix);
    var tpl = findTemplate(prefix);
    var totalInput = totalFormsInput(prefix);
    if (!container || !tpl || !totalInput) return;

    var idx = parseInt(totalInput.value || "0", 10) || 0;
    var html = substitutePrefix(tpl.innerHTML, idx, prefix);
    var fragment = document.createRange().createContextualFragment(html);
    container.appendChild(fragment);
    totalInput.value = String(idx + 1);
    // Newly-added rows need their dynamic widgets reconciled. Sync every
    // row of every kind; cheap and works even when the fragment's nodes
    // have been moved out.
    syncAllSeverityRows();
    syncAllDescribingHints();
    syncAllEventStatuses();
  }

  function removeRow(button) {
    var row = button.closest(".formset-row");
    if (!row) return;
    var del = row.querySelector('input[type="checkbox"][name$="-DELETE"]');
    if (del) del.checked = true;
    row.classList.add("is-deleted");
    var eventFormset = row.closest("[data-event-formset]");
    if (eventFormset) {
      syncEventStatus(eventFormset);
    } else if (row.matches(".affected-row")) {
      // Removing an outer affected row may not change its inner status,
      // but other affected rows' visual state is unaffected.
      syncAllEventStatuses();
    }
  }

  // ---- Severity score widget toggling -------------------------------------
  //
  // SeverityForm renders two score inputs in each row: a free-text CharField
  // for CVSS vectors (data-severity-score="cvss") and a Select for the
  // Ubuntu enum (data-severity-score="ubuntu"). Exactly one is appropriate
  // at any time; the other is hidden and disabled so it doesn't submit.

  function syncSeverityRow(row) {
    var typeSel = row.querySelector("[data-severity-type]");
    if (!typeSel) return;
    var isUbuntu = typeSel.value === "Ubuntu";
    row.querySelectorAll("[data-severity-score]").forEach(function (input) {
      var match =
        (isUbuntu && input.dataset.severityScore === "ubuntu") ||
        (!isUbuntu && input.dataset.severityScore === "cvss");
      input.hidden = !match;
      input.disabled = !match;
    });
    // The CVSS calculator (advisoryhub-cvss.js) only applies to CVSS_*
    // types. For Ubuntu, hide both the calculator and the score badge so the
    // row stays compact; the calculator manages its own internal layout on
    // refresh().
    var calc = row.querySelector("[data-cvss-calculator]");
    var badge = row.querySelector("[data-cvss-score]");
    if (calc) calc.hidden = isUbuntu;
    if (badge) badge.hidden = isUbuntu;
    if (!isUbuntu && window.AdvisoryHubCvss) {
      window.AdvisoryHubCvss.refresh(row);
    }
  }

  function syncAllSeverityRows() {
    document.querySelectorAll("[data-severity-row]").forEach(syncSeverityRow);
  }

  // ---- Self-describing-select contextual hint -----------------------------
  //
  // Selects rendered by DescribingSelect (advisories/forms.py) carry
  // `data-describing` and each <option> has a `title` attribute with the
  // OSV-spec description. A sibling <small data-describing-help> inside an
  // ancestor marked `data-describing-row` mirrors the selected option's
  // title so the description is visible even without hovering the dropdown.

  function syncDescribingRow(row) {
    var sel = row.querySelector("[data-describing]");
    var help = row.querySelector("[data-describing-help]");
    if (!sel || !help) return;
    var opt = sel.options[sel.selectedIndex];
    help.textContent = (opt && opt.title) || "";
  }

  function syncAllDescribingHints() {
    document.querySelectorAll("[data-describing-row]").forEach(syncDescribingRow);
  }

  // ---- OSV per-range event-constraint guidance ----------------------------
  //
  // OSV requires each range to have at least one "introduced" event and
  // forbids both "fixed" and "last_affected" appearing in the same range.
  // Server-side validation in advisories/validators.py and a formset-level
  // BaseEventFormSet.clean() are the source of truth; this provides live
  // hints as the user types so they catch issues before hitting Save.

  function syncEventStatus(eventFormset) {
    var status = eventFormset.querySelector("[data-event-status]");
    if (!status) return;
    var kindSelects = eventFormset.querySelectorAll(
      '.formset-rows select[name$="-kind"]'
    );
    var hasIntroduced = false;
    var hasFixed = false;
    var hasLastAffected = false;
    var eventCount = 0;
    kindSelects.forEach(function (sel) {
      var row = sel.closest(".formset-row");
      if (row && row.classList.contains("is-deleted")) return;
      eventCount += 1;
      if (sel.value === "introduced") hasIntroduced = true;
      else if (sel.value === "fixed") hasFixed = true;
      else if (sel.value === "last_affected") hasLastAffected = true;
    });
    var messages = [];
    if (eventCount > 0 && !hasIntroduced) {
      messages.push("Missing required 'Introduced' event.");
    }
    if (hasFixed && hasLastAffected) {
      messages.push(
        "'Fixed' and 'Last affected' cannot both appear in a single range."
      );
    }
    status.textContent = messages.join(" • ");
    status.classList.toggle("is-invalid", messages.length > 0);
  }

  function syncAllEventStatuses() {
    document.querySelectorAll("[data-event-formset]").forEach(syncEventStatus);
  }

  document.addEventListener("click", function (e) {
    var target = e.target;
    if (!(target instanceof Element)) return;
    var addBtn = target.closest(".add-row-btn");
    if (addBtn) {
      e.preventDefault();
      addRow(addBtn.dataset.prefix);
      return;
    }
    var removeBtn = target.closest(".remove-row-btn");
    if (removeBtn) {
      e.preventDefault();
      removeRow(removeBtn);
    }
  });

  document.addEventListener("change", function (e) {
    var target = e.target;
    if (!(target instanceof Element)) return;
    if (target.matches("[data-severity-type]")) {
      var row = target.closest("[data-severity-row]");
      if (row) syncSeverityRow(row);
    }
    if (target.matches("[data-describing]")) {
      var describingRow = target.closest("[data-describing-row]");
      if (describingRow) syncDescribingRow(describingRow);
    }
    if (target.matches('select[name$="-kind"]')) {
      var eventFormset = target.closest("[data-event-formset]");
      if (eventFormset) syncEventStatus(eventFormset);
    }
  });

  function syncAll() {
    syncAllSeverityRows();
    syncAllDescribingHints();
    syncAllEventStatuses();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", syncAll);
  } else {
    syncAll();
  }
})();
