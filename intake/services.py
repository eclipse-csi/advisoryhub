"""Write-path service for the public intake submission.

Triage actions (promote / dismiss / reassign / flag) live in
:mod:`advisories.services` now. The intake app's only remaining
responsibility is the public POST: fork honeypot vs. real submission and
delegate to the advisories service for real submissions.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction

from advisories.form_assembly import assemble_json
from advisories.services import submit_triage_report
from common.net import client_ip

from .forms import VulnerabilityReportForm
from .models import HoneypotSubmission


def create_submission(
    *,
    form: VulnerabilityReportForm,
    request,
    formsets=None,
    event_formsets=None,
):
    """Persist a submitted report.

    Honeypot trips become :class:`HoneypotSubmission` rows — they never
    produce an :class:`advisories.Advisory`. Real submissions become
    triage-state advisories via :func:`advisories.services.submit_triage_report`.

    Returns ``(kind, obj)`` where ``kind`` is ``"honeypot"``, ``"advisory"``,
    or ``"validation_error"`` and ``obj`` is the persisted row (or, for
    ``"validation_error"``, the bound form which now carries the
    surfaced errors). The view uses ``kind`` to decide its response.
    """
    cleaned = form.cleaned_data

    if form.honeypot_triggered:
        with transaction.atomic():
            row = HoneypotSubmission.objects.create(
                submitted_ip=client_ip(request),
                submitted_user_agent=request.META.get("HTTP_USER_AGENT", "")[:512],
                honeypot_field_value=(request.POST.get("website") or "")[:512],
            )
        return ("honeypot", row)

    osv_payload = (
        assemble_json(formsets, event_formsets)
        if formsets is not None and event_formsets is not None
        else {}
    )

    try:
        advisory = submit_triage_report(
            request=request,
            project=form.resolved_project,
            summary=cleaned["summary"],
            details=cleaned["details"],
            reporter_display_name=cleaned.get("reporter_display_name", ""),
            **osv_payload,
        )
    except ValidationError as exc:
        # Model-level full_clean rejected something the form/formsets
        # accepted (e.g. a structural validator on the advisory's JSON
        # fields). Hand the errors back to the caller via the form.
        for field, errors in (exc.error_dict or {}).items():
            target = field if field in form.fields else None
            for err in errors:
                form.add_error(target, err)
        return ("validation_error", form)

    return ("advisory", advisory)
