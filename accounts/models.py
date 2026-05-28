"""User model for AdvisoryHub.

We use an email-as-username custom user. Group membership is mirrored from
OIDC claims at login time (see ``accounts.auth``); the ``groups`` M2M on
``AbstractUser`` is the authoritative store *for the current session* and is
fully replaced on each login. Forms must never trust client-supplied groups.
"""

from __future__ import annotations

from typing import ClassVar

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager["User"]):
    use_in_migrations = True

    def _create_user(self, email: str | None, password: str | None, **extra):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_user(self, email: str | None, password: str | None = None, **extra):
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra)

    def create_superuser(self, email: str | None, password: str | None = None, **extra):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        return self._create_user(email, password, **extra)


class User(AbstractUser):
    username = None  # type: ignore[assignment]  # email is the unique identifier
    email = models.EmailField("email address", unique=True)
    display_name = models.CharField(max_length=200, blank=True)
    oidc_subject = models.CharField(max_length=255, blank=True, db_index=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    # django-stubs types AbstractUser.objects as its own UserManager[User]; our
    # email-only manager is a deliberate BaseUserManager subclass that can't match
    # that signature. The ClassVar annotation silences the class-variable override;
    # the type:ignore covers the unavoidable manager-class mismatch.
    objects: ClassVar[UserManager] = UserManager()  # type: ignore[assignment]

    def __str__(self) -> str:
        return self.email

    def display_label(self, *, fallback: str = "—") -> str:
        """Best human label for this user: display_name, then email, then fallback.

        Whitespace-only ``display_name`` falls through to ``email`` so a user
        whose OIDC ``name`` claim got stripped to spaces still gets a usable
        label rather than the fallback.
        """
        return (self.display_name or "").strip() or (self.email or "").strip() or fallback

    @property
    def is_global_admin(self) -> bool:
        """Member of the configurable global admin/security group."""
        from django.conf import settings

        return self.groups.filter(name=settings.OIDC_ADMIN_GROUP).exists()


class CommentLevel(models.TextChoices):
    """Notification level for comments.

    ``MENTIONED`` is the floor — there is intentionally no ``NONE`` /
    ``OFF`` choice. Users cannot fully unsubscribe from comments;
    mentions are still always delivered.
    """

    ALL = "all", "Every comment"
    MENTIONED = "mentioned", "Only when mentioned"


class NotificationPreference(models.Model):
    """Per-user *global* notification settings.

    Applies as the default for every advisory the user has access to.
    Per-advisory overrides live in
    :class:`notifications.models.AdvisoryNotificationPreference`.

    Recipient filtering happens at *send* time via ``permissions.can_view``,
    so a revoked user will not receive private content even if their
    preferences are on.

    Lifecycle events (submitted-for-review, published, publication export
    status) are honest booleans because there is no "mention" concept for
    them — the floor / "no Never" rule applies in aggregate via mention
    delivery on comments, not by silently relabelling "off" as
    "mentioned-only" for events that nobody is ever mentioned in.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="notification_preferences"
    )
    on_advisory_created = models.BooleanField(
        default=True,
        help_text=(
            "When an advisory is created in (or reassigned to) a project where you're on "
            "the security team. Global only — no per-advisory override."
        ),
    )
    on_advisory_submitted_for_review = models.BooleanField(
        default=True,
        help_text="When an advisory you have access to is submitted for review.",
    )
    on_advisory_published = models.BooleanField(
        default=True,
        help_text="When an advisory you have access to is published to the public repo.",
    )
    on_publication_export_status = models.BooleanField(
        default=True,
        help_text=(
            "When the publication export succeeds or fails — useful for security-team "
            "members responsible for the publication pipeline."
        ),
    )
    comments_level = models.CharField(
        max_length=16,
        choices=CommentLevel.choices,
        default=CommentLevel.MENTIONED,
        help_text="Mentions are always delivered. Pick whether non-mention comments also notify you.",
    )

    def __str__(self) -> str:
        return f"prefs for {self.user.email}"
