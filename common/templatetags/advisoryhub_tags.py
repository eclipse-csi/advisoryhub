"""Project-wide template helpers.

Registered explicitly in ``TEMPLATES['OPTIONS']['libraries']`` because
``common`` is a helper module, not an installed app (so its ``templatetags``
package is not auto-discovered). Load with ``{% load advisoryhub %}``.
"""

from __future__ import annotations

from datetime import datetime

from django import template
from django.template.loader import render_to_string
from django.utils.safestring import SafeString, mark_safe

register = template.Library()


@register.simple_tag
def timestamp(
    value: datetime | None, relative: bool = False, css_class: str = ""
) -> SafeString | str:
    """Render a datetime as a localizable ``<time>`` with a labelled-UTC baseline.

    The server emits an unambiguous, always-correct baseline — the active
    timezone's wall-clock plus its name (``2026-06-05 14:30 UTC`` under the
    default ``DJANGO_TIME_ZONE=UTC``) — wrapped in a ``<time data-localize>``
    carrying the machine-readable instant (ISO 8601 with offset) in ``datetime``.
    ``advisoryhub-time.js`` then rewrites the visible text into the viewer's own
    timezone and parks the UTC value in the ``title`` tooltip. With JavaScript
    off (and in email, which doesn't call this tag) the baseline stands on its
    own — see ``advisories.templatetags.advisory_display.coarse_timesince`` for
    the relative-age helper the partial reuses (loaded at the template layer, so
    ``common`` keeps no import dependency on ``advisories``).

    ``relative=True`` keeps the scannable "N ago" text (which carries no timezone
    ambiguity) visible — for the list and inbox age columns. The JS localizes only
    its tooltip to the exact local moment; the server seeds a UTC-only ``title`` as
    the no-JS fallback. ``css_class`` is placed on the ``<time>`` for the few sites
    that style it directly. A falsy ``value`` renders nothing.

    Rendered (not an inclusion tag) so the partial's trailing newline can be
    stripped: these ``<time>`` elements sit mid-sentence ("edited {ts})") where a
    stray space before punctuation would show.
    """
    if not value:
        return ""
    html = render_to_string(
        "common/_timestamp.html",
        {"value": value, "relative": relative, "css_class": css_class},
    )
    return mark_safe(html.strip())


@register.filter
def toast_payload(messages) -> list[dict[str, str]]:
    """Serialise ``django.contrib.messages`` into a toast-ready list.

    Pair with the built-in ``json_script`` filter to emit a CSP-safe,
    non-executable ``<script type="application/json">`` island that
    ``advisoryhub-toast.js`` drains on page load — the delivery path for
    messages that survive a full-page POST→redirect::

        {{ messages|toast_payload|json_script:"toast-data" }}

    Iterating the storage here consumes it (the standard messages contract), so
    the message is not also left for a later render. ``level_tag`` is the
    ``success``/``info``/``warning``/``error`` class the renderer keys on.
    """
    return [{"level": message.level_tag, "message": str(message.message)} for message in messages]
