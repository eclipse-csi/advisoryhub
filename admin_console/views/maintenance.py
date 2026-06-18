"""Maintenance mode toggle for the admin console.

GET renders the toggle form; POST flips the switch, sets the banner
message, records an audit entry on a state/message change, and busts the
per-request cache (via ``MaintenanceMode.save``). The actual *enforcement*
of the switch lives in :class:`common.middleware.MaintenanceModeMiddleware`
— this view only edits the state. See ``INV-MAINT-1``.
"""

from __future__ import annotations

from django.contrib import messages
from django.shortcuts import redirect, render
from django.urls import reverse

from accounts.step_up import require_step_up_or_redirect
from audit.models import Action
from audit.services import record_from_request

from ..forms import MaintenanceModeForm
from ..models import MaintenanceMode
from .base import admin_required


@admin_required
def maintenance(request):
    obj = MaintenanceMode.load()
    # Capture prior state *before* the bound form's full_clean() mutates the
    # instance in place (ModelForm._post_clean writes cleaned data onto it).
    was_enabled = obj.is_enabled
    prev_message = obj.message

    if request.method == "POST":
        # Toggling the org-wide write freeze is a break-glass action (INV-MAINT-1);
        # require a fresh OIDC re-auth before mutating. Viewing the page (GET) is open.
        redirect_resp = require_step_up_or_redirect(request, next_url=request.path)
        if redirect_resp is not None:
            return redirect_resp
        form = MaintenanceModeForm(request.POST, instance=obj)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.updated_by = request.user
            obj.save()

            now_enabled = obj.is_enabled
            message_changed = obj.message != prev_message
            if now_enabled and (not was_enabled or message_changed):
                # Either a fresh enable, or a re-announce with a new message.
                record_from_request(
                    request,
                    action=Action.MAINTENANCE_ENABLED,
                    metadata={"message": obj.message},
                )
                messages.success(request, "Maintenance mode is now ON. Regular users are paused.")
            elif was_enabled and not now_enabled:
                # Record the message that was active when the pause was lifted
                # (redacted by record()) for a complete forensic trail.
                record_from_request(
                    request,
                    action=Action.MAINTENANCE_DISABLED,
                    metadata={"previous_message": prev_message},
                )
                messages.success(request, "Maintenance mode is now OFF.")
            elif message_changed:
                # OFF→OFF: the banner text was staged for next time. The row was
                # mutated, so report it honestly rather than claiming "No change".
                messages.success(request, "Maintenance message updated (mode stays OFF).")
            else:
                messages.info(request, "No change.")
            return redirect(reverse("admin_console:maintenance"))
    else:
        form = MaintenanceModeForm(instance=obj)

    return render(
        request,
        "admin_console/maintenance.html",
        {"form": form, "maintenance": obj, "admin_section": "maintenance"},
    )
