"""Populate the database with realistic demo data.

Usage::

    python manage.py seed_demo                # idempotent re-seed
    python manage.py seed_demo --reset        # wipe + reseed advisories/projects/users
    python manage.py seed_demo --with-publish-repo /tmp/advisoryhub-pub.git

What you get:

* a global admin user (``admin@example.org``) in the configured admin group;
* 20 demo projects (a mix of mature publishers and non-mature) each
  with a security team and 1-2 members;
* ~30 demo users with a stable distribution across teams and outsiders;
* ~30 advisories spread across draft / submitted / changes-requested /
  approved / dismissed states, plus a handful of CVE requests
  and per-advisory access grants;
* one approved + published advisory if a publication repo path is given
  (the command auto-creates a local bare repo for you on demand).

The command is **safe to run multiple times**; without ``--reset`` it
``get_or_create``\\s users/projects/groups and skips advisory generation
if any already exist.
"""

from __future__ import annotations

import random
import subprocess
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.utils import timezone

from access import services as access_services
from access.models import Permission
from accounts.models import User
from advisories.models import (
    Advisory,
    AdvisoryIntakeMetadata,
    State,
    _unsafe_dev_reset_bypass,
    _unsafe_dev_reset_delete_queryset,
)
from comments.services import add_comment
from intake.models import HoneypotSubmission
from projects.models import Project
from publication.models import PublicationTask
from workflows import services as wf
from workflows.models import CveRequestStatus, OrphanCve, ReviewTask

# Fake project catalogue used by the demo seed. The names/slugs are
# deliberately fictional (no real Eclipse project is referenced) — slugs
# and team-group names must stay stable across reseeds because the kanidm
# bootstrap (dev/kanidm/setup.sh) re-asserts alice's/bob's group membership
# on every OIDC login.
# (slug, display_name, mature, team_group_name, default_package, ecosystem)
DEMO_PROJECTS: list[tuple[str, str, bool, str, str, str]] = [
    (
        "demotech.lantern",
        "Demo Lantern",
        True,
        "demo-lantern-security",
        "org.example.lantern:lantern-core",
        "Maven",
    ),
    (
        "demotech.marigold",
        "Demo Marigold",
        False,
        "demo-marigold-security",
        "org.example.marigold:marigold-core",
        "Maven",
    ),
    (
        "demotech.beacon",
        "Demo Beacon",
        True,
        "demo-beacon-security",
        "org.example.beacon:beacon-server",
        "Maven",
    ),
    (
        "demotech.harbor",
        "Demo Harbor",
        True,
        "demo-harbor-security",
        "org.example.harbor:harbor-core",
        "Maven",
    ),
    (
        "demotech.meadow",
        "Demo Meadow",
        True,
        "demo-meadow-security",
        "org.example.meadow:meadow-core",
        "Maven",
    ),
    (
        "demotech.summit",
        "Demo Summit",
        True,
        "demo-summit-security",
        "org.example.summit:summit-core",
        "Maven",
    ),
    (
        "demotech.willow",
        "Demo Willow",
        False,
        "demo-willow-security",
        "org.example.willow:willow-core",
        "Maven",
    ),
    (
        "demotech.cinder-hollow",
        "Demo Cinder Hollow",
        False,
        "demo-cinder-hollow-security",
        "org.example.cinder:cinder-runtime",
        "Maven",
    ),
    (
        "demotech.compass",
        "Demo Compass",
        True,
        "demo-compass-security",
        "org.example.compass:compass-core",
        "Maven",
    ),
    (
        "demotech.thicket",
        "Demo Thicket",
        False,
        "demo-thicket-security",
        "org.example.thicket:thicket-core",
        "Maven",
    ),
    (
        "demotools.otter",
        "Demo Otter",
        True,
        "demo-otter-security",
        "otter",
        "Other",
    ),
    (
        "demotools.quartz",
        "Demo Quartz",
        False,
        "demo-quartz-security",
        "org.example.quartz:quartz-client",
        "Maven",
    ),
    (
        "demotools.saffron",
        "Demo Saffron",
        False,
        "demo-saffron-security",
        "org.example.saffron:saffron-api",
        "Maven",
    ),
    (
        "demotools.harvest",
        "Demo Harvest",
        True,
        "demo-harvest-security",
        "org.example.harvest:harvest-client",
        "Maven",
    ),
    (
        "demotools.ember",
        "Demo Ember",
        False,
        "demo-ember-security",
        "org.example.ember:ember-client",
        "Maven",
    ),
    (
        "demotools.juniper",
        "Demo Juniper",
        True,
        "demo-juniper-security",
        "org.example.juniper:juniper-core",
        "Maven",
    ),
    (
        "demotools.cobalt",
        "Demo Cobalt",
        False,
        "demo-cobalt-security",
        "org.example.cobalt:cobalt-core",
        "Maven",
    ),
    (
        "demotools.pebble-brook",
        "Demo Pebble Brook",
        False,
        "demo-pebble-brook-security",
        "org.example.pebble:pebble-core",
        "Maven",
    ),
    (
        "demotools.tamarind",
        "Demo Tamarind",
        True,
        "demo-tamarind-security",
        "org.example.tamarind:tamarind-core",
        "Maven",
    ),
    ("demotools.thimble", "Demo Thimble", True, "demo-thimble-security", "@demo/thimble", "npm"),
]

# Demo users. The first three (alice/bob/carol) are kept verbatim for
# parity with docs and the OIDC bootstrap script.
# (email, display_name, project_slug_for_team_or_None)
DEMO_USERS: list[tuple[str, str, str | None]] = [
    ("alice@example.org", "Alice Doe", "demotech.lantern"),
    ("bob@example.org", "Bob Smith", "demotech.marigold"),
    ("carol@example.org", "Carol Outsider", None),
    ("dave@example.org", "Dave Patel", "demotech.beacon"),
    ("erin@example.org", "Erin Mueller", "demotech.harbor"),
    ("frank@example.org", "Frank O'Hara", "demotech.meadow"),
    ("gina@example.org", "Gina Rossi", "demotech.summit"),
    ("hans@example.org", "Hans Becker", "demotech.willow"),
    ("ines@example.org", "Ines Lefevre", "demotech.cinder-hollow"),
    ("jules@example.org", "Jules Tremblay", "demotech.compass"),
    ("kira@example.org", "Kira Watanabe", "demotech.thicket"),
    ("liam@example.org", "Liam O'Connor", "demotools.otter"),
    ("mira@example.org", "Mira Sato", "demotools.quartz"),
    ("noah@example.org", "Noah Andersson", "demotools.saffron"),
    ("olga@example.org", "Olga Ivanova", "demotools.harvest"),
    ("pablo@example.org", "Pablo Garcia", "demotools.ember"),
    ("quinn@example.org", "Quinn Park", "demotools.juniper"),
    ("ravi@example.org", "Ravi Kumar", "demotools.cobalt"),
    ("sara@example.org", "Sara Nilsson", "demotools.pebble-brook"),
    ("theo@example.org", "Theo Dubois", "demotools.tamarind"),
    ("uma@example.org", "Uma Krishnan", "demotools.thimble"),
    # Second members for some teams.
    ("vera@example.org", "Vera Petrova", "demotech.lantern"),
    ("walt@example.org", "Walt Robinson", "demotech.beacon"),
    ("xena@example.org", "Xena Marinos", "demotools.harvest"),
    ("yusuf@example.org", "Yusuf Demir", "demotech.summit"),
    ("zoe@example.org", "Zoe Fischer", "demotools.juniper"),
    # External reviewers / collaborators (no team membership).
    ("amir@example.org", "Amir Hassan", None),
    ("bella@example.org", "Bella Costa", None),
    ("chad@example.org", "Chad Wilson", None),
    ("dora@example.org", "Dora Lindberg", None),
    ("evan@example.org", "Evan Murphy", None),
    ("fiona@example.org", "Fiona Walsh", None),
    ("gabe@example.org", "Gabe Reinholt", None),
    ("hina@example.org", "Hina Tanaka", None),
    ("ivo@example.org", "Ivo Novak", None),
    ("jade@example.org", "Jade Dupont", None),
    ("kemal@example.org", "Kemal Yilmaz", None),
    ("lena@example.org", "Lena Holm", None),
    ("milo@example.org", "Milo Beck", None),
]


# Reusable vulnerability templates. Each generates the OSV-aligned content
# blocks for one advisory; the project/package and version range are
# filled in per-instantiation.
ADVISORY_TEMPLATES: list[dict] = [
    {
        "summary": "Path traversal via double-decoded request URI",
        "details": (
            "Double-decoding of percent-encoded path segments can allow "
            "an attacker to escape the configured resource root and read "
            "files outside the served directory.\n\n"
            "Mitigation: upgrade to a fixed version. As a workaround, "
            "disable second-pass URL decoding in the request pipeline."
        ),
        "cwe_ids": ["CWE-22"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "summary": "Deserialization of untrusted data in message codec",
        "details": (
            "Custom message codecs registered without an explicit "
            "allowlist can be tricked into deserializing arbitrary "
            "classes via attacker-controlled message bodies."
        ),
        "cwe_ids": ["CWE-502"],
        "severity": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "summary": "HTTP request smuggling via CRLF in trailer fields",
        "details": (
            "Unvalidated CRLF sequences in HTTP/1.1 trailer fields can "
            "be used to smuggle a second request past intermediaries "
            "that perform header-based routing."
        ),
        "cwe_ids": ["CWE-444"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    {
        "summary": "Denial of service via unbounded XML entity expansion",
        "details": (
            "The default XML parser configuration does not impose entity "
            "expansion limits. A crafted document with nested entities "
            "can exhaust memory and cause a denial of service."
        ),
        "cwe_ids": ["CWE-776"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    },
    {
        "summary": "Server-side request forgery in URL fetcher",
        "details": (
            "The URL fetcher used for remote resource loading does not "
            "validate the host against an allowlist, enabling SSRF "
            "against internal services reachable from the server."
        ),
        "cwe_ids": ["CWE-918"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    },
    {
        "summary": "Reflected XSS in error-page renderer",
        "details": (
            "Query parameters echoed into the default error page are "
            "not HTML-escaped, enabling reflected XSS against users "
            "whose browsers follow attacker-crafted error URLs."
        ),
        "cwe_ids": ["CWE-79"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    {
        "summary": "Improper certificate validation in TLS client",
        "details": (
            "When configured to use a custom trust store, the TLS "
            "client falls back to system trust silently if the custom "
            "store cannot be loaded, weakening certificate pinning."
        ),
        "cwe_ids": ["CWE-295"],
        "severity": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    {
        "summary": "Race condition in session token rotation",
        "details": (
            "Concurrent requests during session rotation can observe a "
            "window where the old and new tokens are simultaneously "
            "valid, allowing token reuse after re-authentication."
        ),
        "cwe_ids": ["CWE-362"],
        "severity": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
    },
    {
        "summary": "Unsafe ZIP extraction (Zip Slip) in archive importer",
        "details": (
            "Archive importer does not normalize entry paths before "
            "writing them to disk. A crafted archive with ../ entries "
            "can write files outside the intended target directory."
        ),
        "cwe_ids": ["CWE-22"],
        "severity": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    },
    {
        "summary": "Hardcoded default credentials in management endpoint",
        "details": (
            "The optional management endpoint ships with hardcoded "
            "default credentials that are only documented in the "
            "advanced configuration guide."
        ),
        "cwe_ids": ["CWE-798"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "summary": "Open redirect via unvalidated next-URL parameter",
        "details": (
            "The post-login redirect uses the `next` parameter without "
            "validating that the target host matches the configured "
            "origin, enabling phishing via attacker-controlled URLs."
        ),
        "cwe_ids": ["CWE-601"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    {
        "summary": "Information exposure in stack-trace responses",
        "details": (
            "Unhandled exceptions surface full stack traces in HTTP "
            "responses, leaking internal class names, file paths, and "
            "configuration values to remote clients."
        ),
        "cwe_ids": ["CWE-209"],
        "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
]


# Distribution of advisory states (in addition to the three hard-coded
# anchor advisories defined in handle()).
ADVISORY_STATE_PLAN: list[str] = (
    ["draft"] * 9
    + ["submitted"] * 5
    + ["changes_requested"] * 5
    + ["approved"] * 4
    + ["dismissed"] * 4
)


@contextmanager
def _audit_set_null_unblocked():
    """Temporarily allow UPDATE on ``audit_auditlogentry`` so that
    ``Advisory``/``User`` deletions in the dev seed reset can fire their
    ``SET_NULL`` FKs (``AuditLogEntry.advisory`` and ``.actor``). Without
    this the Postgres ``audit_log_no_update`` trigger blocks the cascade.

    Scope is intentionally narrow:
    * Only the UPDATE trigger is touched — the DELETE trigger stays on,
      so seed_demo can never actually remove audit history.
    * On error, the surrounding ``transaction.atomic`` rolls back the
      DISABLE (DDL is transactional in Postgres), so the append-only
      guarantee is automatically restored.

    Dev-only escape hatch: ``seed_demo --reset`` is documented as a
    destructive dev convenience; nothing in prod ever runs this.
    """
    with connection.cursor() as cur:
        cur.execute("ALTER TABLE audit_auditlogentry DISABLE TRIGGER audit_log_no_update")
    # On the success path we must re-enable in the SAME transaction.
    # On exception we deliberately don't try — the surrounding atomic()
    # rolls back the DISABLE, and any SQL on the aborted txn would itself
    # raise and mask the original error.
    yield
    with connection.cursor() as cur:
        cur.execute("ALTER TABLE audit_auditlogentry ENABLE TRIGGER audit_log_no_update")


class Command(BaseCommand):
    help = "Seed the database with realistic demo data."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete existing demo data before seeding (advisories, projects, demo users).",
        )
        parser.add_argument(
            "--with-publish-repo",
            metavar="PATH",
            help=(
                "Path to a (bare) publication Git repo. If the directory "
                "doesn't exist, a fresh bare repo is created there and a "
                "publication advisory is queued + run synchronously."
            ),
        )

    @transaction.atomic
    def handle(self, *args, reset: bool, with_publish_repo: str | None, **opts):
        seed_group_names = {p[3] for p in DEMO_PROJECTS} | {settings.OIDC_ADMIN_GROUP}

        if reset:
            self.stdout.write(self.style.WARNING("Wiping demo data..."))
            # Imported inside reset so ``--reset`` works even before the
            # ghsa app has been migrated on very old DBs.
            from ghsa.models import (
                GhsaCvePushTask,
                GhsaSyncRun,
                GitHubAppInstallation,
                WebhookDelivery,
            )
            from projects.models import ProjectGitHubRepository

            with _audit_set_null_unblocked(), _unsafe_dev_reset_bypass():
                # ReviewTask.version and PublicationTask.version PROTECT
                # AdvisoryVersion, which Advisory.delete() cascades into.
                # Django's PROTECT check raises even when the protector is
                # in the same cascade, so clear these first.
                ReviewTask.objects.all().delete()
                PublicationTask.objects.all().delete()
                # OrphanCve.previous_advisory is SET_NULL, so an orphan
                # row survives advisory deletion with a dangling label
                # and surfaces in the dashboard as "(advisory deleted)".
                # Drop them up front so a fresh seed starts clean.
                OrphanCve.objects.all().delete()
                # Phase-2 GHSA tables: clear before Project so the
                # PROTECT FK on ProjectGitHubRepository.project doesn't
                # block deletion of seeded projects.
                GhsaCvePushTask.objects.all().delete()
                GhsaSyncRun.objects.all().delete()
                # Honeypot rows aren't joined to Advisory but live in the
                # intake app; wipe them so reset reflects a clean DB.
                HoneypotSubmission.objects.all().delete()
                # Advisory deletion is guarded at every layer (model,
                # manager, admin, Postgres trigger). _unsafe_dev_reset_bypass
                # disables the trigger for this transaction; the helper
                # below bypasses the manager guard. Dev-only path.
                # The AdvisoryIntakeMetadata sidecars cascade.
                _unsafe_dev_reset_delete_queryset(Advisory.objects.all())
                ProjectGitHubRepository.objects.all().delete()
                Project.objects.all().delete()
                GitHubAppInstallation.objects.all().delete()
                WebhookDelivery.objects.all().delete()
                User.objects.filter(email__endswith="@example.org").delete()
                Group.objects.filter(name__in=seed_group_names).delete()

        admin_group, _ = Group.objects.get_or_create(name=settings.OIDC_ADMIN_GROUP)

        # Ensure the unsorted sentinel project exists for unrouted triage
        # advisories. Normally created by projects.0003 on a fresh DB; this
        # recreates it after a --reset wipe.
        Project.objects.get_or_create(
            slug="unsorted",
            defaults={
                "name": "Unsorted reports",
                "description": (
                    "Sentinel project for triage advisories submitted without "
                    "a project. Admins resolve these during triage."
                ),
                "security_team": admin_group,
                "is_mature_publisher": False,
            },
        )

        admin, _ = User.objects.get_or_create(
            email="admin@example.org",
            defaults={
                "display_name": "Demo Security Admin",
                "is_staff": True,
                "is_superuser": True,
            },
        )
        admin.groups.add(admin_group)

        # Projects + security teams.
        projects: dict[str, Project] = {}
        for slug, name, mature, team_group, _pkg, _eco in DEMO_PROJECTS:
            projects[slug] = self._make_project(
                slug, name, team_group_name=team_group, mature=mature
            )

        # Demo users + project team memberships.
        users: dict[str, User] = {}
        for email, display_name, member_of in DEMO_USERS:
            u = self._make_user(email, display_name)
            users[email] = u
            if member_of:
                u.groups.add(projects[member_of].security_team)

        # Convenient aliases for the original hardcoded users.
        member_lantern = users["alice@example.org"]
        member_marigold = users["bob@example.org"]
        lantern = projects["demotech.lantern"]
        marigold = projects["demotech.marigold"]

        # Seed vulnerability reports independently of advisories so a
        # re-run can backfill them onto an older demo database.
        self._seed_intake_demo(projects, users)

        # Backdated published + intake advisories so the admin Stats page has a
        # realistic spread to show. Backfillable + idempotent like the intake
        # demo above, so it runs even on a re-seed of an older demo DB.
        self._seed_stats_demo(projects, admin)

        if Advisory.objects.exists() and not reset:
            self.stdout.write("Advisories already exist; skipping advisory creation.")
            return

        # --- Anchor advisories (preserved for parity with docs/tests) -----

        # Advisory 1: draft on Demo Lantern
        Advisory.objects.create(
            project=lantern,
            summary="HTTP/2 header smuggling in request multiplexer",
            details=(
                "Specially crafted CONTINUATION frames may smuggle "
                "headers across multiplexed streams when the buffer "
                "boundary is reached at a specific offset.\n\n"
                "Workaround: disable HTTP/2 until 12.0.42."
            ),
            aliases=[],
            cwe_ids=["CWE-444"],
            references=[
                {"type": "ADVISORY", "url": "https://example.org/demo/lantern/security"},
            ],
            affected=[
                {
                    "package": {"ecosystem": "Maven", "name": "org.example.lantern:lantern-core"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "12.0.0"}, {"fixed": "12.0.42"}],
                        }
                    ],
                }
            ],
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
            credits=[{"name": "An anonymous reporter", "type": "REPORTER"}],
            created_by=member_lantern,
        )

        # Advisory 2: submitted for review (Demo Marigold)
        in_review = Advisory.objects.create(
            project=marigold,
            summary="Deserialization of untrusted data in message-bus codec",
            details=(
                "When custom message codecs are registered without "
                "explicit class allowlisting, an attacker controlling "
                "a message-bus payload can trigger reflection-based "
                "deserialization of arbitrary classes."
            ),
            cwe_ids=["CWE-502"],
            references=[
                {"type": "ADVISORY", "url": "https://example.org/demo/marigold/security"},
            ],
            affected=[
                {
                    "package": {"ecosystem": "Maven", "name": "org.example.marigold:marigold-core"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "4.0.0"}, {"fixed": "4.5.18"}],
                        }
                    ],
                }
            ],
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"}],
            created_by=member_marigold,
        )
        wf.submit_for_review(in_review, by=member_marigold)

        # Advisory 3: approved and published (Demo Lantern, mature project)
        published = Advisory.objects.create(
            project=lantern,
            summary="Path traversal via double URL-decoded request URI",
            details="See references for details.",
            aliases=["CVE-2026-12345"],
            cwe_ids=["CWE-22"],
            references=[
                {"type": "ADVISORY", "url": "https://example.org/demo/lantern/security"},
                {"type": "FIX", "url": "https://github.com/demo-org/lantern/commit/deadbeef"},
            ],
            affected=[
                {
                    "package": {"ecosystem": "Maven", "name": "org.example.lantern:lantern-core"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "11.0.0"}, {"fixed": "11.0.42"}],
                        }
                    ],
                }
            ],
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
            credits=[{"name": "Eve Reporter", "type": "REPORTER"}],
            created_by=member_lantern,
        )

        # --- Bulk advisories across all states ---------------------------

        self._make_bulk_advisories(projects, users, admin)

        if with_publish_repo:
            self._run_publish(published, with_publish_repo)
            self.stdout.write(
                self.style.SUCCESS(f"Published {published.advisory_id} to {with_publish_repo}")
            )
        else:
            # Approve it so it shows as ready-to-publish in the dashboard.
            review_task = wf.submit_for_review(published, by=member_lantern)
            wf.approve_review(review_task, by=admin, notes="LGTM")

        # GHSA-linked demo advisories so a developer can click around the
        # full flow (detail panel, refresh, conflict banner) without
        # registering a sandbox GitHub App.
        self._seed_ghsa_demo(projects, admin)

        self.stdout.write(self.style.SUCCESS("Seed complete."))
        self.stdout.write(
            f"  {Project.objects.count()} projects, "
            f"{User.objects.count()} users, "
            f"{Advisory.objects.count()} advisories.\n"
            "Demo users (all email-authenticated, no password set):\n"
            "  admin@example.org   global admin\n"
            "  alice@example.org   demo-lantern security team\n"
            "  bob@example.org     demo-marigold security team\n"
            "  carol@example.org   outsider (no project membership)\n"
            "  ...plus ~28 more @example.org users across teams.\n"
            "Sign in via OIDC with one of these emails after wiring "
            "your IdP to AdvisoryHub."
        )

    # --- bulk advisory generator -----------------------------------------

    # --- Triage advisory intake demo -------------------------------------

    def _seed_intake_demo(self, projects: dict[str, Project], users: dict[str, User]) -> None:
        """Seed a handful of triage advisories + one honeypot row.

        Idempotent: skips if any triage advisory already exists. Rows are
        created directly (not via the public submission service) to keep
        the audit log clean of synthetic events. ``created_at`` is
        backdated via a follow-up ``.update()`` because ``auto_now_add``
        overrides any value passed to ``objects.create``.
        """
        if Advisory.objects.filter(state=State.TRIAGE).exists():
            return

        from datetime import timedelta

        admin = User.objects.get(email="admin@example.org")
        outsider = users.get("carol@example.org")
        lantern = projects["demotech.lantern"]
        marigold = projects["demotech.marigold"]
        beacon = projects["demotech.beacon"]
        harbor = projects["demotech.harbor"]
        unsorted = Project.objects.get(slug="unsorted")
        now = timezone.now()

        # (advisory kwargs, sidecar kwargs, offset). Sidecar kwargs are
        # applied to AdvisoryIntakeMetadata. ``flag_by`` indirection avoids
        # needing the admin reference inside the data declaration.
        specs: list[tuple[dict, dict, timedelta]] = [
            (
                dict(
                    project=lantern,
                    state=State.TRIAGE,
                    summary="Possible XSS in default error page",
                    details=(
                        "The default 500 error page reflects the `Referer` header "
                        "without escaping when `X-Forwarded-Host` is set. I have a "
                        "small PoC but didn't want to share it on a public form."
                    ),
                ),
                dict(
                    reporter_display_name="Sam Reporter",
                    submitted_ip="198.51.100.21",
                    submitted_user_agent="Mozilla/5.0 (firefox/123)",
                ),
                timedelta(hours=4),
            ),
            (
                dict(
                    project=marigold,
                    state=State.TRIAGE,
                    summary="Memory exhaustion via crafted message-bus message",
                    details=(
                        "Sending a chain of self-referential bridged messages can "
                        "exhaust heap on the receiving worker."
                    ),
                ),
                dict(
                    reporter_display_name="J. Anonymous",
                    submitted_ip="203.0.113.55",
                    submitted_user_agent="curl/8.5.0",
                ),
                timedelta(days=1),
            ),
            (
                dict(
                    project=harbor,
                    state=State.TRIAGE,
                    summary="Admin console login bypass with crafted JSESSIONID",
                    details="Will share details by email when contacted.",
                ),
                dict(
                    submitted_ip="203.0.113.99",
                    submitted_user_agent="Mozilla/5.0 (safari/17)",
                    # Demo of the admin-routing flag: the Demo Harbor security
                    # team reviewer suspects this is actually a Demo Beacon issue.
                    # They can't act on it; an admin must reassign.
                    needs_admin_routing=True,
                    admin_routing_note=(
                        "This looks more like a Demo Beacon authentication bug than "
                        "a Demo Harbor issue — please re-route to demotech.beacon."
                    ),
                    flagged_for_routing_at=now - timedelta(hours=1),
                    flagged_for_routing_by=admin,
                ),
                timedelta(hours=2),
            ),
            (
                dict(
                    project=unsorted,
                    state=State.TRIAGE,
                    summary="Something is broken in a demo plugin but I'm not sure which",
                    details=(
                        "I get a crash when opening certain files in the app. "
                        "I don't know which project this belongs to."
                    ),
                ),
                dict(
                    reporter_display_name="Confused User",
                    submitted_ip="198.51.100.77",
                    submitted_user_agent="Mozilla/5.0 (chrome/121)",
                    needs_admin_routing=True,
                ),
                timedelta(days=3),
            ),
            (
                dict(
                    project=lantern,
                    state=State.DISMISSED,
                    summary="Duplicate report — public CVE already filed",
                    details="Same issue as CVE-2024-XXXXX, already coordinated upstream.",
                    dismissed_reason="duplicate of CVE-2024-XXXXX (public)",
                ),
                dict(
                    submitted_ip="203.0.113.10",
                    submitted_user_agent="curl/8",
                ),
                timedelta(days=8),
            ),
        ]

        if outsider is not None:
            specs.append(
                (
                    dict(
                        project=beacon,
                        state=State.TRIAGE,
                        summary="Race condition in Demo Beacon async response handler",
                        details=(
                            "Under load the async resumed-response can race with a "
                            "second resume call, producing a duplicate-response error."
                        ),
                        created_by=outsider,
                    ),
                    dict(
                        reporter_user=outsider,
                        reporter_display_name=outsider.display_name,
                        submitted_ip="192.0.2.7",
                        submitted_user_agent="Mozilla/5.0 (chrome/120)",
                    ),
                    timedelta(days=2),
                )
            )
            specs.append(
                (
                    dict(
                        project=unsorted,
                        state=State.TRIAGE,
                        summary="Cross-project info disclosure — not sure where to file",
                        details=(
                            "I noticed similar patterns across a few demo projects. "
                            "Filing this so the security team can route it."
                        ),
                        created_by=outsider,
                    ),
                    dict(
                        reporter_user=outsider,
                        reporter_display_name=outsider.display_name,
                        submitted_ip="192.0.2.7",
                        submitted_user_agent="Mozilla/5.0 (chrome/120)",
                        needs_admin_routing=True,
                    ),
                    timedelta(days=5),
                )
            )

        created = 0
        for adv_kwargs, intake_kwargs, offset in specs:
            advisory = Advisory.objects.create(**adv_kwargs)
            AdvisoryIntakeMetadata.objects.create(advisory=advisory, **intake_kwargs)
            when = now - offset
            # ``.update`` bypasses ``auto_now_add`` / ``auto_now`` so the
            # backdated timestamps stick.
            Advisory.objects.filter(pk=advisory.pk).update(created_at=when, modified_at=when)
            AdvisoryIntakeMetadata.objects.filter(advisory=advisory).update(submitted_at=when)
            # If the reporter is an existing user, mirror the auto-grant the
            # service does (so the demo dashboard shows the user has access).
            if intake_kwargs.get("reporter_user"):
                from access.services import grant_to_user

                grant_to_user(advisory, intake_kwargs["reporter_user"], Permission.VIEWER, by=None)
            created += 1

        # Honeypot row — not an Advisory, lives in its own table.
        HoneypotSubmission.objects.create(
            submitted_ip="198.51.100.250",
            submitted_user_agent="python-requests/2.31",
            honeypot_field_value="https://buy-cheap-pills.example",
        )

        self.stdout.write(f"  Seeded {created} triage advisories + 1 honeypot submission.")

    def _seed_stats_demo(self, projects: dict[str, Project], admin: User) -> None:
        """Seed backdated advisories so the admin Stats page is demonstrable.

        Creates three families of synthetic rows spread across every reporting
        period (last week → 12 months → all time), with a deliberate long tail
        so percentiles separate and recent windows read faster than older ones:

        * **Published** advisories (time-to-publish): ``created_at`` →
          ``published_at`` latencies.
        * **Intake** reports (time-to-first-response): ``submitted_at`` → a
          first-response audit event (promote / dismiss / flag).
        * **Reverted** reports: promoted to draft and *later* dismissed — they
          feed the reverted tally (anchored on the dismissal) and also yield a
          TTFR sample anchored on the earlier promotion.

        Idempotent: rows carry a ``[stats-demo]`` summary prefix and the method
        no-ops if they already exist. ``auto_now_add`` timestamps are backdated
        with ``.update()``; the append-only audit rows are backdated under
        :func:`audit.retention._audit_trigger_bypass` (plain UPDATE is blocked
        by the ledger trigger). The enclosing ``handle`` is ``@transaction.atomic``
        so the ``SET LOCAL`` in the bypass applies for the whole sweep.
        """
        from datetime import timedelta

        from audit.models import Action, AuditLogEntry
        from audit.retention import _audit_trigger_bypass
        from audit.services import record

        if Advisory.objects.filter(summary__startswith="[stats-demo]").exists():
            return

        now = timezone.now()
        project_cycle = [
            projects["demotech.lantern"],
            projects["demotech.marigold"],
            projects["demotech.beacon"],
            projects["demotech.harbor"],
        ]

        # (a) Time to publish — (published_days_ago, created→published latency h).
        # Anchors span every period incl. > 12 months; the 120/200/300/400 h
        # tail makes p99 ≫ p90 ≫ mean, and recent latencies stay below older
        # ones so the trend chips read "improved".
        ttp_samples = [
            (1, 5),
            (3, 8),
            (5, 30),
            (6, 12),
            (9, 14),
            (12, 40),
            (13, 9),
            (18, 18),
            (22, 60),
            (27, 22),
            (36, 30),
            (45, 120),
            (52, 26),
            (70, 40),
            (85, 200),
            (110, 50),
            (150, 300),
            (170, 35),
            (220, 60),
            (300, 400),
            (350, 45),
            # Fill the mid-range 30-day buckets so the 12-month trend sparkline
            # has a point in every bucket (older = a touch slower).
            (135, 45),
            (195, 55),
            (255, 60),
            (285, 70),
            (420, 90),
            (600, 150),
        ]
        for i, (days_ago, latency_h) in enumerate(ttp_samples):
            published_at = now - timedelta(days=days_ago)
            created_at = published_at - timedelta(hours=latency_h)
            adv = Advisory.objects.create(
                project=project_cycle[i % len(project_cycle)],
                state=State.PUBLISHED,
                summary=f"[stats-demo] Published advisory #{i + 1}",
                details="Synthetic published advisory for the admin Stats demo.",
                created_by=admin,
            )
            Advisory.objects.filter(pk=adv.pk).update(
                created_at=created_at, modified_at=published_at, published_at=published_at
            )

        # (b) Time to first response — (response_days_ago, response h, action,
        # final state). The final state keeps these out of the triage inbox;
        # the audit action is what the metric reads. Recent responses faster.
        promote, dismiss, flag = (
            Action.ADVISORY_TRIAGE_PROMOTED,
            Action.ADVISORY_DISMISSED,
            Action.ADVISORY_FLAGGED_FOR_ROUTING,
        )
        ttfr_samples = [
            (1, 3, promote, State.DRAFT),
            (4, 10, flag, State.DRAFT),
            (6, 5, promote, State.DRAFT),
            (9, 6, promote, State.DRAFT),
            (12, 20, dismiss, State.DISMISSED),
            (18, 8, promote, State.DRAFT),
            (25, 30, promote, State.DRAFT),
            (38, 12, promote, State.DRAFT),
            (50, 48, flag, State.DRAFT),
            (75, 16, promote, State.DRAFT),
            (88, 72, dismiss, State.DISMISSED),
            (120, 20, promote, State.DRAFT),
            (160, 96, promote, State.DRAFT),
            (240, 24, promote, State.DRAFT),
            (320, 120, promote, State.DRAFT),
            # Fill the sparse mid/old 30-day buckets for the trend sparkline.
            (225, 30, promote, State.DRAFT),
            (285, 60, promote, State.DRAFT),
            (345, 48, dismiss, State.DISMISSED),
            (420, 36, promote, State.DRAFT),
            (560, 144, promote, State.DRAFT),
        ]
        # (c) Reverted — (dismissed_days_ago, promote-before-dismissal h).
        reverted_samples = [
            (3, 30),
            (5, 48),
            (10, 24),
            (20, 36),
            (38, 60),
            (52, 30),
            (70, 48),
            (100, 36),
            (140, 72),
            (200, 48),
            (300, 96),
        ]

        audit_backdates: list[tuple[AuditLogEntry, object]] = []

        def _new_intake(summary: str, ip: str, *, state, reason: str = ""):
            adv = Advisory.objects.create(
                project=project_cycle[len(audit_backdates) % len(project_cycle)],
                state=state,
                summary=summary,
                details="Synthetic intake report for the admin Stats demo.",
                created_by=admin,
                dismissed_reason=reason,
            )
            AdvisoryIntakeMetadata.objects.create(
                advisory=adv,
                reporter_display_name="Stats Demo Reporter",
                submitted_ip=ip,
                submitted_user_agent="stats-demo/1.0",
            )
            return adv

        def _audit(adv, action):
            return record(
                action=action,
                actor=admin,
                advisory=adv,
                metadata={"advisory_id": adv.advisory_id, "stats_demo": True},
            )

        for i, (days_ago, resp_h, action, final_state) in enumerate(ttfr_samples):
            response_at = now - timedelta(days=days_ago)
            submitted_at = response_at - timedelta(hours=resp_h)
            reason = "stats-demo dismissal" if final_state == State.DISMISSED else ""
            adv = _new_intake(
                f"[stats-demo] Intake report #{i + 1}",
                "203.0.113.200",
                state=final_state,
                reason=reason,
            )
            Advisory.objects.filter(pk=adv.pk).update(
                created_at=submitted_at, modified_at=response_at
            )
            AdvisoryIntakeMetadata.objects.filter(advisory=adv).update(submitted_at=submitted_at)
            audit_backdates.append((_audit(adv, action), response_at))

        for i, (days_ago, promote_before_h) in enumerate(reverted_samples):
            dismissed_at = now - timedelta(days=days_ago)
            promoted_at = dismissed_at - timedelta(hours=promote_before_h)
            submitted_at = promoted_at - timedelta(hours=8)
            adv = _new_intake(
                f"[stats-demo] Reverted report #{i + 1}",
                "203.0.113.201",
                state=State.DISMISSED,
                reason="stats-demo reverted after promotion",
            )
            Advisory.objects.filter(pk=adv.pk).update(
                created_at=submitted_at, modified_at=dismissed_at
            )
            AdvisoryIntakeMetadata.objects.filter(advisory=adv).update(submitted_at=submitted_at)
            audit_backdates.append((_audit(adv, Action.ADVISORY_TRIAGE_PROMOTED), promoted_at))
            audit_backdates.append((_audit(adv, Action.ADVISORY_DISMISSED), dismissed_at))

        # Backdate the audit rows; the append-only trigger forbids plain UPDATE.
        with _audit_trigger_bypass():
            for entry, when in audit_backdates:
                AuditLogEntry.objects.filter(pk=entry.pk).update(created_at=when)

        self.stdout.write(
            f"  Seeded stats demo: {len(ttp_samples)} published, "
            f"{len(ttfr_samples)} intake, {len(reverted_samples)} reverted advisories."
        )

    # --- GHSA demo seed --------------------------------------------------

    def _seed_ghsa_demo(self, projects: dict[str, Project], admin: User) -> None:
        """Seed an installation, repo mirror entries, and a handful of GHSA-linked advisories.

        Idempotent: each row is ``get_or_create``'d. Fully offline — the
        canned ``ghsa_metadata`` payload is used in place of a live
        GitHub fetch so devs don't need an App installed to see the
        synced metadata rendered.
        """
        from advisories.models import GhsaState, Kind
        from ghsa.models import GitHubAppAccountType, GitHubAppInstallation
        from projects.models import ProjectGitHubRepository

        now = timezone.now()

        # 1) The installation registry needs at least one active row for
        # the client to resolve "demo-org" to a token.
        GitHubAppInstallation.objects.get_or_create(
            installation_id=1,
            defaults={
                "account_login": "demo-org",
                "account_type": GitHubAppAccountType.ORGANIZATION,
                "app_slug": "advisoryhub-demo",
                "last_seen_at": now,
            },
        )

        # 2) PMI mirror entries for a couple of mature projects. We map
        # PMI slugs to plausible GitHub repos.
        demo_repos: list[tuple[str, str, str]] = [
            ("demotech.lantern", "demo-org", "lantern"),
            ("demotech.beacon", "demo-labs", "beacon"),
        ]
        # Add a second installation so demo-labs resolves too — this
        # also lets a dev see the multi-installation UI populated.
        GitHubAppInstallation.objects.get_or_create(
            installation_id=2,
            defaults={
                "account_login": "demo-labs",
                "account_type": GitHubAppAccountType.ORGANIZATION,
                "app_slug": "advisoryhub-demo",
                "last_seen_at": now,
            },
        )
        for slug, owner, name in demo_repos:
            project = projects.get(slug)
            if project is None:
                continue
            ProjectGitHubRepository.objects.get_or_create(
                project=project,
                owner=owner,
                name=name,
                defaults={"last_seen_in_pmi_at": now},
            )
            project.last_pmi_sync_at = now
            project.save(update_fields=["last_pmi_sync_at"])

        # 3) Canned GHSA REST payload — fields the panel template relies
        # on (summary, severity, cwes, vulnerabilities, html_url).
        def _payload(ghsa_id: str, owner: str, repo: str, summary: str) -> dict:
            return {
                "ghsa_id": ghsa_id,
                "html_url": (f"https://github.com/{owner}/{repo}/security/advisories/{ghsa_id}"),
                "state": "published",
                "summary": summary,
                "description": "Demo advisory synced from a (mock) GHSA.",
                "severity": "high",
                "cvss": {
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "score": 7.5,
                },
                "cwes": [{"cwe_id": "CWE-22", "name": "Path Traversal"}],
                "identifiers": [{"type": "GHSA", "value": ghsa_id}],
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "maven", "name": f"org.example:{repo}"},
                        "vulnerable_version_range": ">= 1.0.0, < 1.2.3",
                        "patched_versions": "1.2.3",
                    }
                ],
                "references": [f"https://github.com/{owner}/{repo}/security/advisories/{ghsa_id}"],
            }

        # 4) Three GHSA-linked advisories: two draft, one published with
        # ``republish_required`` so the dashboard signal is visible.
        demo_advisories: list[tuple[str, str, str, str, str, bool]] = [
            (
                "demotech.lantern",
                "demo-org",
                "lantern",
                "GHSA-demo-lntn-aaaa",
                "Path traversal in static file handler",
                False,  # draft
            ),
            (
                "demotech.beacon",
                "demo-labs",
                "beacon",
                "GHSA-demo-bcn-bbbb",
                "XML external entity in REST parser",
                False,  # draft
            ),
            (
                "demotech.lantern",
                "demo-org",
                "lantern",
                "GHSA-demo-lntn2-cccc",
                "HTTP/2 header smuggling regression",
                True,  # published, republish_required
            ),
        ]
        for slug, owner, repo, ghsa_id, summary, published in demo_advisories:
            project = projects.get(slug)
            if project is None:
                continue
            payload = _payload(ghsa_id, owner, repo, summary)
            advisory, created = Advisory.objects.get_or_create(
                ghsa_id=ghsa_id,
                defaults={
                    "project": project,
                    "kind": Kind.GHSA_LINKED,
                    "ghsa_owner": owner,
                    "ghsa_repo": repo,
                    "ghsa_state": GhsaState.PUBLISHED,
                    "ghsa_metadata": payload,
                    "ghsa_metadata_synced_at": now,
                    "summary": summary,
                    "details": payload["description"],
                    "severity": [{"type": "CVSS_V3", "score": payload["cvss"]["vector_string"]}],
                    "cwe_ids": ["CWE-22"],
                    "aliases": [ghsa_id],
                    "references": [
                        {
                            "type": "ADVISORY",
                            "url": payload["html_url"],
                        }
                    ],
                    "affected": [
                        {
                            "package": {"ecosystem": "Maven", "name": f"org.example:{repo}"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "1.0.0"},
                                        {"fixed": "1.2.3"},
                                    ],
                                }
                            ],
                        }
                    ],
                    "credits": [{"name": "demo-reporter", "type": "REPORTER"}],
                    "created_by": admin,
                },
            )
            if created and published:
                advisory.state = State.PUBLISHED
                advisory.published_at = now
                advisory.republish_required = True
                advisory.save(
                    update_fields=[
                        "state",
                        "published_at",
                        "republish_required",
                        "modified_at",
                    ]
                )

    def _make_bulk_advisories(
        self,
        projects: dict[str, Project],
        users: dict[str, User],
        admin: User,
    ) -> None:
        """Generate ~27 advisories across all lifecycle/review states.

        Output is deterministic: a fixed-seed PRNG selects templates,
        projects, and authors so the dashboard always looks the same.
        """
        rng = random.Random(20260514)

        team_members_by_slug: dict[str, list[User]] = {slug: [] for slug in projects}
        for email, _name, member_of in DEMO_USERS:
            if member_of:
                team_members_by_slug[member_of].append(users[email])

        outsiders = [users[email] for email, _name, member_of in DEMO_USERS if member_of is None]

        # Project metadata indexed for affected-package generation.
        project_meta = {p[0]: (p[4], p[5]) for p in DEMO_PROJECTS}

        # Each project gets at least one advisory; round-robin afterwards.
        project_slugs = list(projects.keys())
        rng.shuffle(project_slugs)
        plan = list(ADVISORY_STATE_PLAN)
        rng.shuffle(plan)

        for idx, state_target in enumerate(plan):
            slug = project_slugs[idx % len(project_slugs)]
            project = projects[slug]
            template = ADVISORY_TEMPLATES[idx % len(ADVISORY_TEMPLATES)]
            pkg, ecosystem = project_meta[slug]

            # Author is a team member when available, otherwise an outsider
            # (which still works because Advisory.created_by has no perm
            # check at the model layer — perms are enforced at the view).
            team = team_members_by_slug[slug]
            author = team[0] if team else outsiders[idx % len(outsiders)]

            major = (idx % 5) + 1
            minor = (idx * 3) % 7
            patch = (idx * 7) % 11
            introduced = f"{major}.{minor}.0"
            fixed = f"{major}.{minor}.{patch + 1}"

            advisory = Advisory.objects.create(
                project=project,
                summary=template["summary"],
                details=template["details"],
                cwe_ids=template["cwe_ids"],
                references=[
                    {
                        "type": "ADVISORY",
                        "url": f"https://example.org/security/advisories/{slug}",
                    },
                ],
                affected=[
                    {
                        "package": {"ecosystem": ecosystem, "name": pkg},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": introduced}, {"fixed": fixed}],
                            }
                        ],
                    }
                ],
                severity=[{"type": "CVSS_V3", "score": template["severity"]}],
                created_by=author,
            )

            self._advance_to_state(advisory, state_target, author=author, admin=admin)

            # Add some flavour: comments, access grants, CVE requests.
            self._sprinkle_extras(
                advisory,
                idx=idx,
                author=author,
                outsiders=outsiders,
                admin=admin,
                rng=rng,
            )

    def _advance_to_state(
        self,
        advisory: Advisory,
        target: str,
        *,
        author: User,
        admin: User,
    ) -> None:
        """Drive a fresh draft advisory into the requested review/lifecycle state."""
        if target == "draft":
            return

        if target == "dismissed":
            advisory.state = State.DISMISSED
            advisory.dismissed_reason = (
                "Reporter retracted — root cause turned out to be a "
                "misconfiguration on the reporter's side, not a product flaw."
            )
            advisory.save(update_fields=["state", "dismissed_reason", "modified_at"])
            return

        review_task = wf.submit_for_review(advisory, by=author)
        if target == "submitted":
            return
        if target == "approved":
            wf.approve_review(review_task, by=admin, notes="Ready to publish.")
            return
        if target == "changes_requested":
            wf.request_changes(
                review_task,
                by=admin,
                notes="Please add the upstream patch URL and refresh the affected ranges.",
            )
            return

    def _sprinkle_extras(
        self,
        advisory: Advisory,
        *,
        idx: int,
        author: User,
        outsiders: list[User],
        admin: User,
        rng: random.Random,
    ) -> None:
        # Comment thread on every third advisory.
        if idx % 3 == 0:
            try:
                add_comment(
                    advisory,
                    author=author,
                    body=(
                        "Initial triage notes: confirmed reproducer attached. "
                        "Severity and affected range estimated from local testing."
                    ),
                )
            except Exception:
                pass

        # Access grants on every second advisory: one collaborator, one viewer.
        if idx % 2 == 0 and outsiders:
            collaborator = outsiders[idx % len(outsiders)]
            viewer = outsiders[(idx + 1) % len(outsiders)]
            try:
                access_services.grant_to_user(
                    advisory, collaborator, Permission.COLLABORATOR, by=author
                )
                access_services.grant_to_user(advisory, viewer, Permission.VIEWER, by=author)
            except Exception:
                pass

        # A handful of CVE requests in the queue (draft advisories only —
        # the workflow rejects requests on dismissed advisories, and
        # advisories already past review usually have their CVE story
        # settled).
        if idx % 7 == 0 and advisory.state == State.DRAFT and advisory.review_status == "none":
            try:
                wf.request_cve(advisory, by=author)
            except Exception:
                pass

        # Reserve one CVE so the dashboard shows a CVE-tagged advisory.
        if idx == 14:
            queued = advisory.cve_requests.filter(status=CveRequestStatus.QUEUED).first()
            if queued is None:
                try:
                    queued = wf.request_cve(advisory, by=author)
                except Exception:
                    queued = None
            if queued is not None:
                try:
                    wf.transition_cve_request(
                        queued,
                        by=admin,
                        new_status=CveRequestStatus.RESERVED,
                        cve_id=f"CVE-2026-{20000 + idx}",
                    )
                except Exception:
                    pass

    # --- helpers ---------------------------------------------------------

    def _make_project(self, slug: str, name: str, *, team_group_name: str, mature: bool) -> Project:
        team, _ = Group.objects.get_or_create(name=team_group_name)
        project, created = Project.objects.get_or_create(
            slug=slug,
            defaults={
                "name": name,
                "security_team": team,
                "is_mature_publisher": mature,
            },
        )
        if not created and project.is_mature_publisher != mature:
            project.is_mature_publisher = mature
            project.save(update_fields=["is_mature_publisher"])
        return project

    def _make_user(self, email: str, display_name: str) -> User:
        user, _ = User.objects.get_or_create(email=email, defaults={"display_name": display_name})
        return user

    def _run_publish(self, advisory: Advisory, repo_path: str) -> None:
        from publication import services as pub_services
        from publication import tasks as pub_tasks

        path = Path(repo_path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "init", "--bare", "--initial-branch=main", str(path)],
                check=True,
                capture_output=True,
            )
            # The bare repo needs an initial commit on `main` for clone to pick up the branch.
            seed = path.with_suffix(".seed")
            seed.mkdir(exist_ok=True)
            subprocess.run(
                ["git", "init", "--initial-branch=main", str(seed)], check=True, capture_output=True
            )
            subprocess.run(
                ["git", "-C", str(seed), "config", "user.email", "seed@example.org"], check=True
            )
            subprocess.run(["git", "-C", str(seed), "config", "user.name", "Seed"], check=True)
            subprocess.run(
                ["git", "-C", str(seed), "config", "commit.gpgsign", "false"], check=True
            )
            (seed / "README.md").write_text("Demo security advisories — generated.\n")
            subprocess.run(["git", "-C", str(seed), "add", "README.md"], check=True)
            subprocess.run(
                ["git", "-C", str(seed), "commit", "-m", "init"], check=True, capture_output=True
            )
            subprocess.run(
                ["git", "-C", str(seed), "remote", "add", "origin", str(path)], check=True
            )
            subprocess.run(
                ["git", "-C", str(seed), "push", "origin", "main"], check=True, capture_output=True
            )

        # Override the configured repo for this seed run only.
        settings.PUB_REPO_URL = str(path)
        settings.PUB_REPO_BRANCH = "main"
        settings.PUB_REPO_AUTH = "none"

        admin = User.objects.get(email="admin@example.org")
        task = pub_services.publish(advisory, by=admin)
        pub_tasks.run_publication(task.pk)
