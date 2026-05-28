"""Add AdvisoryVersion and seed v1 for every existing advisory.

This migration introduces the append-only edit-history log for advisories.
After it runs, the invariant "every Advisory has at least an AdvisoryVersion
v=1 whose payload mirrors the live row" holds, so workflows that pin a
version (review submission, publication) can safely reference v1 even for
advisories that were created before the history feature existed.

The v1 backfill uses the live Advisory column values directly — we do not
call ``Advisory.to_payload()`` because RunPython runs against the
historical app registry where instance methods aren't available.
"""

from __future__ import annotations

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def _backfill_v1(apps, schema_editor):
    Advisory = apps.get_model("advisories", "Advisory")
    AdvisoryVersion = apps.get_model("advisories", "AdvisoryVersion")
    rows = []
    for adv in Advisory.objects.select_related("project").iterator():
        payload = {
            "advisory_id": adv.advisory_id,
            "project_slug": adv.project.slug,
            "summary": adv.summary,
            "details": adv.details,
            "aliases": list(adv.aliases or []),
            "assigned_cve_id": adv.assigned_cve_id,
            "references": list(adv.references or []),
            "affected": list(adv.affected or []),
            "severity": list(adv.severity or []),
            "cwe_ids": list(adv.cwe_ids or []),
            "credits": list(adv.credits or []),
            "withdrawn_reason": adv.withdrawn_reason,
            "kind": adv.kind,
            "ghsa_id": adv.ghsa_id,
            "ghsa_owner": adv.ghsa_owner,
            "ghsa_repo": adv.ghsa_repo,
            "ghsa_metadata_synced_at": (
                adv.ghsa_metadata_synced_at.isoformat() if adv.ghsa_metadata_synced_at else None
            ),
        }
        rows.append(
            AdvisoryVersion(
                advisory=adv,
                version=1,
                payload=payload,
                editor_id=adv.created_by_id,
            )
        )
    # bulk_create skips auto_now_add — we accept "v1.created_at == migration
    # run time" for backfilled rows because there's no reliable per-advisory
    # creation timestamp to preserve in a single bulk insert across DBs.
    AdvisoryVersion.objects.bulk_create(rows, batch_size=500)


def _drop_versions(apps, schema_editor):
    AdvisoryVersion = apps.get_model("advisories", "AdvisoryVersion")
    AdvisoryVersion.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("advisories", "0009_alter_advisory_review_status"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AdvisoryVersion",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("version", models.PositiveIntegerField()),
                ("payload", models.JSONField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="versions",
                        to="advisories.advisory",
                    ),
                ),
                (
                    "editor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["advisory", "version"],
                "indexes": [
                    models.Index(
                        fields=["advisory", "version"],
                        name="advisories__advisor_a0d1f8_idx",
                    ),
                ],
                "unique_together": {("advisory", "version")},
            },
        ),
        migrations.RunPython(_backfill_v1, _drop_versions),
    ]
