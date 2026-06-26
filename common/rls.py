"""Row-level-security principal plumbing (INV-CONF-2).

The advisory RLS policy (``advisories/migrations/0010_advisory_rls.py``) filters
``advisories_advisory`` — and its content child tables — to the rows the
*current principal* may see, keyed on two Postgres session GUCs:

* ``advisoryhub.user_id`` — the authenticated user's PK (unset/empty ⇒ no rows).
* ``advisoryhub.is_admin`` — ``'on'`` for a global admin or a trusted system
  context, which bypasses the row predicate.

RLS is enforced only for a **non-superuser** database role; the dev/CI bootstrap
role is a superuser (RLS-exempt), so this is dormant there and live under the
production non-superuser app role (running-in-production §7). This module is what
makes the app *function* when RLS is live: it sets the principal for every web
request (``RowLevelSecurityMiddleware``), Celery task, and management command,
and resets it — fail-closed — afterwards.

Mechanism: a per-connection **session** GUC via ``set_config(..., is_local =>
false)`` — so it needs no surrounding transaction and does not change request
transaction semantics. Django connections are thread-local and (by default)
closed per request, so a value cannot leak across concurrent requests; the
middleware and context managers also reset in a ``finally`` to cover persistent
connections (``CONN_MAX_AGE > 0``). The reset value is the fail-closed
empty/`'off'` principal, never an admin one.
"""

from __future__ import annotations

from contextlib import contextmanager

from django.db import connection

_USER_GUC = "advisoryhub.user_id"
_ADMIN_GUC = "advisoryhub.is_admin"


def set_principal(*, user_id: int | None = None, is_admin: bool = False) -> None:
    """Set the RLS principal on the current DB connection (session-scoped).

    ``user_id=None`` writes an empty string; the policy's
    ``NULLIF(current_setting(...), '')`` turns that into a NULL principal that
    matches no rows — so an unset principal is fail-closed.
    """
    with connection.cursor() as cur:
        # GUC names are module constants (never user input); values are bound.
        cur.execute(
            "SELECT set_config(%s, %s, false)",
            [_USER_GUC, "" if user_id is None else str(user_id)],
        )
        cur.execute(
            "SELECT set_config(%s, %s, false)",
            [_ADMIN_GUC, "on" if is_admin else "off"],
        )


def set_principal_for_user(user) -> None:
    """Set the RLS principal from a (possibly anonymous) request user."""
    from advisories.permissions import is_global_admin

    authed = bool(getattr(user, "is_authenticated", False))
    set_principal(
        user_id=getattr(user, "pk", None) if authed else None,
        is_admin=is_global_admin(user),
    )


def clear_principal() -> None:
    """Reset the principal to the fail-closed (empty / non-admin) value."""
    set_principal(user_id=None, is_admin=False)


@contextmanager
def rls_principal(user):
    """Run a block with the RLS principal set to ``user`` (admins bypass)."""
    set_principal_for_user(user)
    try:
        yield
    finally:
        clear_principal()


@contextmanager
def rls_system():
    """Run a block as a trusted system principal (RLS-exempt).

    For Celery tasks and management commands. Server-side authorization and
    notification-recipient re-checks (``INV-AUTH-1``, ``INV-PRIVACY-2``) still
    run in application code; RLS backstops the *user-facing request path*, so
    trusted background work runs admin-equivalent rather than threading a
    per-row principal through every task.
    """
    set_principal(user_id=None, is_admin=True)
    try:
        yield
    finally:
        clear_principal()
