from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from accounts.models import NotificationPreference
from advisories import permissions as perms
from advisories.models import Advisory
from audit.models import Action
from audit.services import record_from_request

from . import services
from .forms import AdvisoryNotificationPreferenceForm, NotificationPreferenceForm
from .models import Notification
from .recipients import resolved_comments_level, resolved_lifecycle_flag

_GLOBAL_FIELDS = (
    "on_advisory_created",
    "on_triage_event",
    "on_advisory_submitted_for_review",
    "on_advisory_published",
    "on_publication_export_status",
    "comments_level",
)

_LIFECYCLE_FIELDS = (
    "on_advisory_submitted_for_review",
    "on_advisory_published",
    "on_publication_export_status",
)


def _global_snapshot(pref: NotificationPreference) -> dict:
    return {field: getattr(pref, field) for field in _GLOBAL_FIELDS}


def _override_snapshot(pref) -> dict | None:
    if pref is None:
        return None
    return {
        "on_advisory_submitted_for_review": pref.on_advisory_submitted_for_review,
        "on_advisory_published": pref.on_advisory_published,
        "on_publication_export_status": pref.on_publication_export_status,
        "comments_level": pref.comments_level,
    }


# ---------------------------------------------------------------------------
# Inbox: the notifications a user received by email, with read/unread state
# ---------------------------------------------------------------------------

_INBOX_PER_PAGE = 30


@login_required
@require_http_methods(["GET"])
def inbox(request):
    """List the notifications the current user received, newest first.

    Visibility is re-checked at *display* time (INV-AUTH-1): a notification
    whose advisory the user can no longer see is still listed (the email was
    already delivered) but renders without a link.
    """
    qs = Notification.objects.filter(recipient=request.user).select_related("advisory")
    page = Paginator(qs, _INBOX_PER_PAGE).get_page(request.GET.get("page"))
    visible_ids = set(perms.visible_advisories(request.user).values_list("pk", flat=True))
    for n in page.object_list:
        n.visible = n.advisory_id is None or n.advisory_id in visible_ids
    return render(
        request,
        "notifications/inbox.html",
        {"page": page, "unread_total": services.unread_count(request.user)},
    )


@login_required
@require_http_methods(["POST"])
def mark_read(request, pk: int):
    """Mark one notification read. Scoped to the caller's own rows (a row owned
    by another user 404s). Returns the re-rendered row for an HTMX swap; falls
    back to a redirect for a no-JS POST.
    """
    notification = get_object_or_404(Notification, pk=pk, recipient=request.user)
    if notification.read_at is None:
        notification.read_at = timezone.now()
        notification.save(update_fields=["read_at"])
    if request.htmx:
        adv = notification.advisory
        notification.visible = adv is None or perms.can_view(request.user, adv)
        return render(request, "notifications/_inbox_row.html", {"n": notification})
    return redirect("notifications:inbox")


@login_required
@require_http_methods(["POST"])
def mark_all_read(request):
    """Mark all of the caller's unread notifications read, then reload the inbox
    (a fresh render zeroes the nav badge)."""
    count = services.mark_all_read(request.user)
    if count:
        plural = "" if count == 1 else "s"
        messages.success(request, f"Marked {count} notification{plural} as read.")
    return redirect("notifications:inbox")


@login_required
def preferences(request):
    pref, _ = NotificationPreference.objects.get_or_create(user=request.user)
    if request.method == "POST":
        form = NotificationPreferenceForm(request.POST, instance=pref)
        if form.is_valid():
            previous = _global_snapshot(pref)
            updated = form.save()
            record_from_request(
                request,
                action=Action.NOTIFICATION_PREFS_CHANGED,
                previous_value=previous,
                new_value=_global_snapshot(updated),
            )
            messages.success(request, "Notification preferences saved.")
            return redirect("notifications:preferences")
    else:
        form = NotificationPreferenceForm(instance=pref)
    return render(request, "notifications/preferences.html", {"form": form})


def _render_advisory_panel(request, advisory: Advisory, *, force_preset: str | None = None):
    pref = services.get_advisory_preference(request.user, advisory)
    # Honor the user's explicit preset pick on POST, even when the stored
    # values happen to match a canned preset. Without this, clicking
    # "Custom…" from a state whose values coincidentally match (or whose
    # row was just deleted) would snap the UI back to that other preset.
    active_preset = force_preset or AdvisoryNotificationPreferenceForm.detect_preset(pref)
    form = AdvisoryNotificationPreferenceForm(
        initial={
            "preset": active_preset,
            **AdvisoryNotificationPreferenceForm.initial_from(pref),
        }
    )
    effective_lifecycle = {
        field: resolved_lifecycle_flag(request.user, advisory, field=field)
        for field in _LIFECYCLE_FIELDS
    }
    return render(
        request,
        "notifications/_advisory_panel.html",
        {
            "advisory": advisory,
            "advisory_pref": pref,
            "advisory_pref_form": form,
            "effective_lifecycle": effective_lifecycle,
            "effective_comments_level": resolved_comments_level(request.user, advisory),
            "active_preset": active_preset,
            "preset_options": _PRESET_OPTIONS,
        },
    )


# (value, label, description) tuples — kept here rather than on the form
# because they're presentation, not validation.
_PRESET_OPTIONS = [
    (
        AdvisoryNotificationPreferenceForm.PRESET_DEFAULT,
        "Default",
        "Use the levels from your global notification settings.",
    ),
    (
        AdvisoryNotificationPreferenceForm.PRESET_ALL,
        "All activity",
        "Every lifecycle event and every comment.",
    ),
    (
        AdvisoryNotificationPreferenceForm.PRESET_DIGEST,
        "Key events + mentions",
        "Publication outcomes and comments where you're mentioned.",
    ),
    (
        AdvisoryNotificationPreferenceForm.PRESET_CUSTOM,
        "Custom…",
        "Fine-tune each event type.",
    ),
]


@login_required
@require_http_methods(["GET", "POST"])
def advisory_preferences(request, advisory_id: str):
    """Render and update the per-advisory notification panel.

    GET returns the panel partial (used by HTMX to lazy-load).
    POST writes new values and returns the re-rendered panel — the
    HTMX form on the panel swaps it in place.
    """
    advisory = get_object_or_404(Advisory, advisory_id=advisory_id)
    if not perms.can_view(request.user, advisory):
        raise PermissionDenied("You cannot configure notifications for this advisory.")

    force_preset: str | None = None
    if request.method == "POST":
        form = AdvisoryNotificationPreferenceForm(request.POST)
        if form.is_valid():
            previous = _override_snapshot(services.get_advisory_preference(request.user, advisory))
            services.set_advisory_preference(request.user, advisory, **form.materialize())
            new = _override_snapshot(services.get_advisory_preference(request.user, advisory))
            record_from_request(
                request,
                action=Action.NOTIFICATION_PREFS_CHANGED,
                advisory=advisory,
                previous_value=previous,
                new_value=new,
            )
            if form.cleaned_data.get("preset") == AdvisoryNotificationPreferenceForm.PRESET_CUSTOM:
                force_preset = AdvisoryNotificationPreferenceForm.PRESET_CUSTOM

    return _render_advisory_panel(request, advisory, force_preset=force_preset)
