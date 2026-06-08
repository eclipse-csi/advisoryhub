"""Anonymize a user across audit, comments, and invitations.

Usage::

    python manage.py forget_user alice@example.org
    python manage.py forget_user alice@example.org --pseudo=ex-alice@invalid

Anonymization scrubs the user's email/display_name from every audit
log JSON field, redacts every comment they authored, drops every
pending invitation they created, and finally blanks the user row
itself. The user row is *kept* (not deleted) so existing FKs that were
``SET_NULL`` already keep their structural meaning. Pass ``--also-delete``
to delete the row at the end.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from audit.retention import forget_user


class Command(BaseCommand):
    help = "Anonymize a user across the system (GDPR right-to-be-forgotten)."

    def add_arguments(self, parser):
        parser.add_argument("email", help="Email of the user to forget.")
        parser.add_argument(
            "--pseudo",
            default=None,
            help="Pseudonymous email to use in place of the original.",
        )
        parser.add_argument(
            "--reason",
            default="",
            help="Justification recorded on the USER_FORGOTTEN audit entry.",
        )
        parser.add_argument(
            "--also-delete",
            action="store_true",
            help="After scrubbing, delete the user row too.",
        )

    def handle(self, *args, email: str, pseudo: str | None, reason: str, also_delete: bool, **opts):
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist as exc:
            raise CommandError(f"No user found with email {email!r}.") from exc

        counters = forget_user(user, reason=reason, anonymized_email=pseudo)
        self.stdout.write(self.style.SUCCESS(f"Forgot user pk={user.pk}: {counters}"))

        if also_delete:
            user.delete()
            self.stdout.write(self.style.SUCCESS("User row deleted."))
