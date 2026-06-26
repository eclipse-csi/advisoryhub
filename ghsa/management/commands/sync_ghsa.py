"""``manage.py sync_ghsa`` — refresh PMI repos and GHSA-linked advisories.

Useful for ops backstops (a cron'd ``--all`` outside of Celery beat) and
for one-off troubleshooting. The flags mirror the on-demand UI actions
so a script and a click do the same thing.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from advisories.models import Advisory, Kind
from common.rls import rls_system
from ghsa import services
from projects.models import Project


class Command(BaseCommand):
    help = "Sync PMI repo mirror and/or GHSA-linked advisories."

    def add_arguments(self, parser):
        parser.add_argument("--all", action="store_true", help="Sync every project.")
        parser.add_argument("--project", help="Sync a single project by slug.")
        parser.add_argument("--advisory", help="Sync a single GHSA-linked advisory by advisory_id.")
        parser.add_argument(
            "--pmi-only",
            action="store_true",
            help="Only refresh the PMI repo mirror; skip GHSA discovery/refresh.",
        )
        parser.add_argument(
            "--actor",
            help="Email of the user to attribute the run to in the audit log "
            "(otherwise the run is recorded as 'system').",
        )

    def handle(self, *args, **opts):
        # Run as a trusted system principal so the command is not RLS-filtered
        # under the production non-superuser app role (INV-CONF-2).
        with rls_system():
            return self._handle(*args, **opts)

    def _handle(self, *args, **opts):
        actor = self._resolve_actor(opts.get("actor"))
        if opts["all"] and opts["project"]:
            raise CommandError("--all and --project are mutually exclusive.")
        if opts["advisory"] and (opts["all"] or opts["project"] or opts["pmi_only"]):
            raise CommandError("--advisory cannot be combined with --all/--project/--pmi-only.")

        if opts["advisory"]:
            advisory = Advisory.objects.get(advisory_id=opts["advisory"])
            if advisory.kind != Kind.GHSA_LINKED:
                raise CommandError(f"{advisory.advisory_id} is not a GHSA-linked advisory.")
            result = services.sync_single_ghsa(advisory, by=actor)
            self.stdout.write(self.style.SUCCESS(f"sync_single_ghsa: {result}"))
            return

        if opts["project"]:
            project = Project.objects.get(slug=opts["project"])
            services.sync_project_repos_from_pmi(project, by=actor)
            self.stdout.write(self.style.SUCCESS(f"PMI mirror refreshed for {project.slug}"))
            if opts["pmi_only"]:
                return
            run = services.sync_ghsas_for_project(project, by=actor)
            self.stdout.write(
                self.style.SUCCESS(
                    f"GHSA sync for {project.slug}: created {run.advisories_created}, "
                    f"updated {run.advisories_updated}, errors {run.errors_count}"
                )
            )
            return

        if opts["all"]:
            refreshed = 0
            failed = 0
            for project in Project.objects.all():
                try:
                    services.sync_project_repos_from_pmi(project, by=actor)
                    refreshed += 1
                except Exception as exc:  # pragma: no cover — defensive
                    failed += 1
                    self.stderr.write(
                        self.style.WARNING(f"PMI sync failed for {project.slug}: {exc}")
                    )
            self.stdout.write(
                self.style.SUCCESS(f"PMI mirror refreshed: {refreshed} ok, {failed} failed")
            )
            if opts["pmi_only"]:
                return
            run = services.sync_ghsas_for_all_projects(by=actor)
            self.stdout.write(
                self.style.SUCCESS(
                    f"GHSA sync (all): created {run.advisories_created}, "
                    f"updated {run.advisories_updated}, errors {run.errors_count}"
                )
            )
            return

        raise CommandError(
            "Specify one of --advisory <id>, --project <slug>, or --all (optionally with --pmi-only)."
        )

    @staticmethod
    def _resolve_actor(email: str | None):
        if not email:
            return None
        try:
            return get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist as exc:
            raise CommandError(f"No user with email {email!r}.") from exc
