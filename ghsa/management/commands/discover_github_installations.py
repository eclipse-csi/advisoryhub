"""``manage.py discover_github_installations`` — rescan the App's installs.

Calls ``GET /app/installations`` with the App JWT and upserts every
returned installation into :class:`ghsa.models.GitHubAppInstallation`.

Use cases:

* **Bootstrap** an environment that doesn't yet have the
  ``GITHUB_APP_INSTALLATION_ID`` env var migrated into the DB.
* **Recover** after losing webhook delivery (e.g. URL was wrong, or the
  receiver was down long enough that GitHub gave up retrying).
* **Audit** against drift — re-running the command surfaces every
  installation that currently exists on GitHub.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from ghsa.client import GitHubApiError
from ghsa.services import discover_installations


class Command(BaseCommand):
    help = "Pull every installation of the AdvisoryHub GitHub App into the DB registry."

    def add_arguments(self, parser):
        parser.add_argument(
            "--actor",
            help="Email of the user to attribute the discover run to in the audit log.",
        )

    def handle(self, *args, **opts):
        actor = self._resolve_actor(opts.get("actor"))
        try:
            rows = discover_installations(by=actor)
        except GitHubApiError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"Discovered {len(rows)} installation(s):"))
        for row in rows:
            self.stdout.write(
                f"  - {row.account_login} (id={row.installation_id}, "
                f"type={row.account_type}, suspended={'yes' if row.suspended_at else 'no'})"
            )

    @staticmethod
    def _resolve_actor(email: str | None):
        if not email:
            return None
        try:
            return get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist as exc:
            raise CommandError(f"No user with email {email!r}.") from exc
