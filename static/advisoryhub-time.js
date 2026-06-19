/* AdvisoryHub — localize server-rendered UTC timestamps to the viewer's zone.
 *
 * Loaded once (base.html), `defer` so the DOM is parsed when it runs. Progressive
 * enhancement on top of the `{% timestamp %}` tag (common/templatetags): the
 * server ships an always-correct, labelled-UTC baseline inside
 * `<time datetime="<ISO-with-offset>" data-localize>2026-06-05 14:30 UTC</time>`.
 * Here we rewrite the visible text into the viewer's own timezone (e.g.
 * "2026-06-05 16:30 CEST") and park the canonical UTC instant in the `title`
 * tooltip. With JS off — or in email, which never renders this element — the
 * baseline stands on its own.
 *
 * Relative "N ago" ages (marked `data-relative`) keep their zone-agnostic text;
 * we localize only their tooltip to the exact local moment (the server's UTC-only
 * label is the no-JS fallback).
 *
 * Same shape regardless of locale: we assemble "YYYY-MM-DD HH:MM <tz>" from
 * Intl.DateTimeFormat parts (locale "en-CA" + hourCycle h23 give ISO-ish order
 * and 24h) so localized text lines up with the server baseline. Any parse/Intl
 * failure leaves the baseline in place — never worse than UTC.
 */
(function () {
  "use strict";

  function formatterFor(timeZone) {
    var opts = {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hourCycle: "h23",
      timeZoneName: "short",
    };
    if (timeZone) opts.timeZone = timeZone;
    return new Intl.DateTimeFormat("en-CA", opts);
  }

  var localFmt, utcFmt;
  try {
    localFmt = formatterFor(undefined); // the viewer's own timezone
    utcFmt = formatterFor("UTC");
  } catch (e) {
    return; // Intl unavailable — leave every server baseline as-is
  }

  // "2026-06-05 16:30 CEST" — the timeZoneName part already carries the label
  // (UTC formatter yields "… UTC"), so callers never append it themselves.
  function render(fmt, date) {
    var parts = {};
    fmt.formatToParts(date).forEach(function (p) { parts[p.type] = p.value; });
    return parts.year + "-" + parts.month + "-" + parts.day + " " +
      parts.hour + ":" + parts.minute + " " + (parts.timeZoneName || "");
  }

  // "2026-06-05" — just the calendar date, for low-noise metadata fields.
  function renderDate(fmt, date) {
    var parts = {};
    fmt.formatToParts(date).forEach(function (p) { parts[p.type] = p.value; });
    return parts.year + "-" + parts.month + "-" + parts.day;
  }

  function localize(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var nodes = scope.querySelectorAll("time[data-localize]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.dataset.localized) continue; // idempotent across htmx re-settles
      var iso = el.getAttribute("datetime");
      if (!iso) continue;
      var date = new Date(iso);
      if (isNaN(date.getTime())) continue;
      try {
        if (el.hasAttribute("data-relative")) {
          // Visible "N ago" stays; reveal the exact local moment on hover.
          el.title = render(localFmt, date);
        } else if (el.hasAttribute("data-date-only")) {
          // Visible local date; reveal the full local datetime on hover.
          el.textContent = renderDate(localFmt, date);
          el.title = render(localFmt, date);
        } else {
          el.textContent = render(localFmt, date);
          el.title = render(utcFmt, date);
        }
      } catch (e) {
        continue; // keep this node's server baseline
      }
      el.dataset.localized = "1";
    }
  }

  localize(document);

  // Re-run after htmx swaps so newly-inserted timestamps (inbox rows, posted
  // comments, admin partials) are localized too. The dataset guard keeps a
  // whole-document rescan cheap; scanning the document (not the possibly
  // detached swap target) avoids missing outerHTML-replaced nodes.
  if (window.htmx) {
    document.body.addEventListener("htmx:afterSettle", function () {
      localize(document);
    });
  }
})();
