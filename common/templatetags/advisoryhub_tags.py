"""Project-wide template helpers.

Registered explicitly in ``TEMPLATES['OPTIONS']['libraries']`` because
``common`` is a helper module, not an installed app (so its ``templatetags``
package is not auto-discovered). Load with ``{% load advisoryhub %}``.
"""

from __future__ import annotations

from django import template

register = template.Library()


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
