"""``manage.py sync_roster`` — refresh project security-team rosters.

Pre-provisions shadow users from the authenticated Eclipse API so security-team
members are reachable by notification before their first login. Useful as an
ops backstop (a cron'd ``--all`` outside Celery beat) and for one-off
troubleshooting. Mirrors the on-demand Admin Console action.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from projects import services
from projects.models import Project


class Command(BaseCommand):
    help = "Sync project security-team rosters from the authenticated Eclipse API."

    def add_arguments(self, parser):
        parser.add_argument("--all", action="store_true", help="Sync every project.")
        parser.add_argument("--project", help="Sync a single project by slug.")
        parser.add_argument(
            "--actor",
            help="Email of the user to attribute the run to in the audit log "
            "(otherwise the run is recorded as 'system').",
        )

    def handle(self, *args, **opts):
        if not getattr(settings, "PMI_ROSTER_SYNC_ENABLED", False):
            # Refuse rather than silently no-op, so an operator gets a clear
            # signal the feature flag is off.
            raise CommandError(
                "PMI_ROSTER_SYNC_ENABLED is False — enable it (and configure the "
                "ECLIPSE_API_* credentials) before running the roster sync."
            )
        actor = self._resolve_actor(opts.get("actor"))
        if opts["all"] and opts["project"]:
            raise CommandError("--all and --project are mutually exclusive.")

        if opts["project"]:
            try:
                project = Project.objects.get(slug=opts["project"])
            except Project.DoesNotExist as exc:
                raise CommandError(f"No project with slug {opts['project']!r}.") from exc
            active = services.sync_security_team_roster(project, by=actor)
            self.stdout.write(
                self.style.SUCCESS(f"Roster sync for {project.slug}: {active} active member(s).")
            )
            return

        if opts["all"]:
            result = services.sync_all_security_team_rosters(by=actor)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Roster sync (all): {result['refreshed']} ok, {result['failed']} failed."
                )
            )
            return

        raise CommandError("Specify one of --project <slug> or --all.")

    @staticmethod
    def _resolve_actor(email: str | None):
        if not email:
            return None
        try:
            return get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist as exc:
            raise CommandError(f"No user with email {email!r}.") from exc
