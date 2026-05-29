"""Admin-console operational state.

Currently a single model: :class:`MaintenanceMode`, the site-wide pause
switch an admin flips from ``/admin/maintenance/``. It is a *singleton*
(one row, ``pk=1``) read on every request, so the hot path goes through a
short-lived cache rather than the database — see :meth:`MaintenanceMode.current`.

Enforcement of the switch lives in
:class:`common.middleware.MaintenanceModeMiddleware` (server-side; the
banner and disabled buttons are display-only). See ``INV-MAINT-1``.
"""

from __future__ import annotations

from typing import TypedDict

from django.conf import settings
from django.core.cache import cache
from django.db import models

# Bumped if the cached snapshot shape ever changes, so a rolling deploy
# never reads a stale-shaped value written by the previous version.
_CACHE_KEY = "advisoryhub:maintenance-mode:v1"
# Safety net for cross-process staleness (e.g. LocMem in dev where each
# worker has its own cache and ``save`` only busts the local one). Short
# enough that a toggle propagates quickly; long enough to absorb traffic.
_CACHE_TTL_SECONDS = 30


class MaintenanceSnapshot(TypedDict):
    is_enabled: bool
    message: str


class MaintenanceMode(models.Model):
    """Singleton site-wide maintenance switch.

    When ``is_enabled`` is True, every non-admin request that would mutate
    state is refused by the maintenance middleware and a banner carrying
    ``message`` is shown to impacted (non-admin) users. Members of
    ``settings.OIDC_ADMIN_GROUP`` are never paused.
    """

    SINGLETON_PK = 1

    is_enabled = models.BooleanField(default=False)
    message = models.TextField(
        blank=True,
        help_text=(
            "Shown to paused users in the maintenance banner. Optional — a "
            "generic message is shown when left blank."
        ),
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        verbose_name = "maintenance mode"
        verbose_name_plural = "maintenance mode"

    def __str__(self) -> str:
        return f"maintenance mode: {'ON' if self.is_enabled else 'off'}"

    def save(self, *args, **kwargs):
        # Pin the singleton row and invalidate the per-request cache so a
        # toggle takes effect on the very next request in this process.
        self.pk = self.SINGLETON_PK
        super().save(*args, **kwargs)
        cache.delete(_CACHE_KEY)

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        cache.delete(_CACHE_KEY)

    @classmethod
    def load(cls) -> MaintenanceMode:
        """Return the singleton row, creating it lazily.

        Use this for *editing* (the admin form binds to it). Per-request
        *reads* should use :meth:`current`, which is cached and never writes.
        """
        obj, _ = cls.objects.get_or_create(pk=cls.SINGLETON_PK)
        return obj

    @classmethod
    def current(cls) -> MaintenanceSnapshot:
        """Cheap, cached read of the current state for the *display* path.

        Used by the banner / context processor on every page render. Returns
        a plain dict (safe to cache cross-process) and never writes a row —
        an absent singleton simply reads as *off*. The cache is a 30s
        snapshot, so on a multi-process deployment without a shared cache the
        banner can lag a toggle by up to the TTL. That is cosmetic: the
        *enforcement* read (:meth:`is_paused`) is uncached and authoritative.
        """
        cached: MaintenanceSnapshot | None = cache.get(_CACHE_KEY)
        if cached is not None:
            return cached
        obj = cls.objects.filter(pk=cls.SINGLETON_PK).first()
        snapshot: MaintenanceSnapshot = {
            "is_enabled": bool(obj and obj.is_enabled),
            "message": (obj.message if obj else "") or "",
        }
        cache.set(_CACHE_KEY, snapshot, _CACHE_TTL_SECONDS)
        return snapshot

    @classmethod
    def is_paused(cls) -> bool:
        """Authoritative, uncached read for the *enforcement* path.

        The maintenance pause is an authorization decision (``INV-MAINT-1``),
        so it must not depend on a per-process cache that a sibling worker
        hasn't busted yet. This is a single indexed ``pk=1`` lookup and only
        runs on unsafe-method (write) requests, which are comparatively rare —
        cheap enough to read straight from the database every time and stay
        coherent across workers regardless of the cache backend.
        """
        return cls.objects.filter(pk=cls.SINGLETON_PK, is_enabled=True).exists()
