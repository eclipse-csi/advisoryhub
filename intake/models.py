"""Public vulnerability report intake — remaining surface.

The legacy :class:`VulnerabilityReport` model has been folded into
``advisories.Advisory`` as a new ``triage`` lifecycle state. This app now
hosts only:

* :class:`HoneypotSubmission` — bot honeypot trips that we *do* persist for
  spam analytics but never produce an Advisory from.

Triage actions (promote / dismiss / reassign / flag) and the curated
intake sidecar live in :mod:`advisories.services` and
:class:`advisories.models.AdvisoryIntakeMetadata` respectively.
"""

from __future__ import annotations

import uuid

from django.db import models


class HoneypotSubmission(models.Model):
    """A public form submission that tripped the honeypot field.

    Honeypots never produce an :class:`advisories.Advisory` row — they are
    captured here so the public POST handler still does one DB write
    (preserving timing indistinguishability with the real-submission branch)
    without polluting the curated advisory table.

    The form-input ``honeypot_field_value`` is kept verbatim (truncated) for
    spam analysis; it's caller-supplied content and never trusted as
    structured data. PII (IP, UA) is subject to the same retention as the
    intake sidecar and is scrubbed by the ``prune_reports`` command and the
    ``forget_user`` retention path.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    submitted_ip = models.GenericIPAddressField(null=True, blank=True)
    submitted_user_agent = models.CharField(max_length=512, blank=True)
    honeypot_field_value = models.CharField(max_length=512, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True, db_index=True)
    pii_cleared_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-submitted_at"]
        indexes = [
            models.Index(fields=["submitted_at"]),
        ]

    def __str__(self) -> str:
        return f"honeypot {self.id} @ {self.submitted_at:%Y-%m-%d %H:%M}"
