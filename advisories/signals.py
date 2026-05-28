"""Signal handlers for the advisories app.

Currently houses a single safety-net handler that backstops the
``AdvisoryVersion`` v1 invariant — every Advisory row must have at least
one version. The view/service creation paths already call
:func:`advisories.services.record_advisory_version` explicitly so they
get an editor-attributed v1; this handler covers everyone else (seed
fixtures, ad-hoc ORM creates, tests that don't go through the service
layer) by inserting a v1 only if no version exists yet for that row.
"""

from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Advisory, AdvisoryVersion


@receiver(post_save, sender=Advisory)
def _ensure_initial_version(sender, instance: Advisory, created: bool, **kwargs) -> None:
    if not created:
        return
    if AdvisoryVersion.objects.filter(advisory=instance).exists():
        return
    AdvisoryVersion.objects.create(
        advisory=instance,
        version=1,
        payload=instance.to_payload(),
        editor=instance.created_by,
    )
