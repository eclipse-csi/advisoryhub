"""Public vulnerability report intake views.

Only the public submission surface lives here now:

* ``/report/`` — form (GET) + submission handler (POST). Rate-limited
  per-IP for anonymous submitters, per-user for authenticated ones.
  Honeypot trips redirect to the thank-you page and persist a
  :class:`HoneypotSubmission` row (no Advisory created); real submissions
  delegate to :func:`advisories.services.submit_triage_report` which
  creates an ``Advisory(state=TRIAGE)`` + sidecar and (for authenticated
  users) auto-grants viewer access.
* ``/report/projects.json`` — JSON picker, cached, rate-limited.
* ``/report/thank-you/`` — post-submit page.

Triage views moved to :mod:`advisories.views_triage`.
"""

from __future__ import annotations

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods
from django_ratelimit.core import is_ratelimited

from advisories.form_assembly import (
    advanced_form_context,
    build_event_formsets,
    build_formsets,
    validate_all,
)
from common.net import client_ip_key
from common.ratelimit import json_ratelimit, per_user_or_ip
from projects.models import Project

from . import services
from .forms import VulnerabilityReportForm


@require_http_methods(["GET", "POST"])
def report_form(request):
    if settings.INTAKE_DISABLED:
        return render(request, "intake/disabled.html", status=503)

    if request.method == "POST":
        return _handle_post(request)

    form = VulnerabilityReportForm(authenticated=request.user.is_authenticated)
    formsets = build_formsets(request, None)
    event_formsets = build_event_formsets(request, formsets["affected"], None)
    return render(
        request,
        "intake/report.html",
        {
            "form": form,
            "projects": _public_projects(),
            "advanced_open": False,
            **advanced_form_context(formsets, event_formsets),
        },
    )


def _handle_post(request):
    """Apply the rate limit *before* dispatching to the submission handler
    (settings read at request time so tests can override).

    Checking up front — rather than after ``_do_submit`` runs — is what keeps
    the limit from being cosmetic: a throttled request must not create an
    ``Advisory(state=triage)`` or fan out triage emails (INV-RATELIMIT-1).
    """
    if request.user.is_authenticated:
        rate = settings.RATELIMIT_INTAKE_USER
        key_fn = per_user_or_ip
    else:
        rate = settings.RATELIMIT_INTAKE_ANON
        key_fn = client_ip_key
    if is_ratelimited(
        request=request, group="intake:report", key=key_fn, rate=rate, increment=True
    ):
        return HttpResponse(
            "Rate limit exceeded. Try again in a minute.",
            status=429,
            content_type="text/plain",
        )
    return _do_submit(request)


def _do_submit(request):
    form = VulnerabilityReportForm(request.POST, authenticated=request.user.is_authenticated)
    formsets = build_formsets(request, None)
    event_formsets = build_event_formsets(request, formsets["affected"], None)

    # Validate the top-level form first so honeypot detection (which lives
    # in clean_website) runs. If a bot tripped the honeypot we skip
    # everything else and silently succeed — no point validating advanced
    # fields the row will never use.
    form_valid = form.is_valid()
    if form_valid and form.honeypot_triggered:
        kind, obj = services.create_submission(
            form=form, formsets=None, event_formsets=None, request=request
        )
        ref = str(obj.id)
        return redirect(f"{reverse('intake:thank_you')}?ref={ref}")

    # Real submission path — also validate the OSV-shaped formsets the
    # reporter may have filled from the advanced section.
    bundle_valid = form_valid and validate_all(form, formsets, event_formsets)
    if not bundle_valid:
        return _render_form(request, form, formsets, event_formsets, status=400, advanced_open=True)

    kind, obj = services.create_submission(
        form=form, formsets=formsets, event_formsets=event_formsets, request=request
    )
    if kind == "validation_error":
        # ``submit_triage_report`` ran ``full_clean`` and rejected something
        # the per-field formset validators accepted. Re-render with the
        # disclosure open so the reporter sees the inline errors.
        return _render_form(request, form, formsets, event_formsets, status=400, advanced_open=True)
    ref = obj.advisory_id if kind == "advisory" else str(obj.id)
    return redirect(f"{reverse('intake:thank_you')}?ref={ref}")


def _render_form(request, form, formsets, event_formsets, *, status: int, advanced_open: bool):
    return render(
        request,
        "intake/report.html",
        {
            "form": form,
            "projects": _public_projects(),
            "advanced_open": advanced_open,
            **advanced_form_context(formsets, event_formsets),
        },
        status=status,
    )


@require_http_methods(["GET"])
def thank_you(request):
    ref = request.GET.get("ref", "")
    return render(request, "intake/thank_you.html", {"ref": ref})


@cache_control(public=True, max_age=300)
@json_ratelimit(rate="60/m", key=client_ip_key)
@require_http_methods(["GET"])
def project_picker_json(request):
    q = (request.GET.get("q") or "").strip()
    qs = Project.objects.exclude(slug="unsorted").order_by("name")
    if q:
        qs = qs.filter(_search_q(q))
    qs = qs[:200]
    payload = [{"slug": p.slug, "name": p.name} for p in qs]
    return JsonResponse(payload, safe=False)


def _search_q(q: str):
    return Q(slug__icontains=q) | Q(name__icontains=q)


def _public_projects() -> list[dict]:
    """Slim project list for the HTML datalist; same shape as the JSON API.

    Excludes the ``unsorted`` sentinel — that project exists to receive
    unrouted triage advisories, not as a user-pickable destination.
    """
    return [
        {"slug": p.slug, "name": p.name}
        for p in Project.objects.exclude(slug="unsorted").order_by("name")[:500]
    ]
