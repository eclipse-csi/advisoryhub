"""Tests for site-wide maintenance mode (INV-MAINT-1).

Covers the singleton model + cache, the admin toggle view + audit trail,
the middleware enforcement (the actual authority), and the display layer
(banner + body hook).
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from admin_console.models import MaintenanceMode
from audit.models import Action, AuditLogEntry

ADMIN_GROUP = "advisoryhub-security"


@pytest.fixture
def actors(make_user, settings):
    settings.OIDC_ADMIN_GROUP = ADMIN_GROUP
    return {
        "admin": make_user(email="admin@example.org", groups=[ADMIN_GROUP]),
        "member": make_user(email="member@example.org"),
    }


def _enable(message: str = "") -> MaintenanceMode:
    return MaintenanceMode.objects.create(is_enabled=True, message=message)


# --------------------------------------------------------------------------- model


@pytest.mark.django_db
def test_current_reads_off_with_no_row():
    snap = MaintenanceMode.current()
    assert snap == {"is_enabled": False, "message": ""}


@pytest.mark.django_db
def test_load_is_singleton_pk1_and_idempotent():
    a = MaintenanceMode.load()
    b = MaintenanceMode.load()
    assert a.pk == MaintenanceMode.SINGLETON_PK == 1
    assert b.pk == 1
    assert MaintenanceMode.objects.count() == 1


@pytest.mark.django_db
def test_save_pins_singleton_even_when_constructed_fresh():
    MaintenanceMode(is_enabled=True, message="x").save()
    MaintenanceMode(is_enabled=False, message="y").save()
    assert MaintenanceMode.objects.count() == 1
    assert MaintenanceMode.objects.get().pk == 1


@pytest.mark.django_db
def test_save_busts_the_cache():
    assert MaintenanceMode.current()["is_enabled"] is False  # primes cache as "off"
    _enable("down for upgrade")
    snap = MaintenanceMode.current()
    assert snap["is_enabled"] is True
    assert snap["message"] == "down for upgrade"


# ----------------------------------------------------------------------- toggle view


@pytest.mark.django_db
def test_toggle_page_requires_admin(client, actors):
    url = reverse("admin_console:maintenance")
    client.force_login(actors["member"])
    assert client.get(url).status_code == 403


@pytest.mark.django_db
def test_toggle_page_renders_for_admin(client, actors):
    client.force_login(actors["admin"])
    resp = client.get(reverse("admin_console:maintenance"))
    assert resp.status_code == 200
    assert b"Maintenance mode" in resp.content


@pytest.mark.django_db
def test_admin_enables_with_message_records_audit(client, actors):
    client.force_login(actors["admin"])
    resp = client.post(
        reverse("admin_console:maintenance"),
        {"is_enabled": "on", "message": "Back at 14:00 UTC"},
        follow=True,
    )
    assert resp.status_code == 200
    obj = MaintenanceMode.objects.get()
    assert obj.is_enabled is True
    assert obj.message == "Back at 14:00 UTC"
    assert obj.updated_by_id == actors["admin"].pk
    entry = AuditLogEntry.objects.get(action=Action.MAINTENANCE_ENABLED)
    assert entry.metadata["message"] == "Back at 14:00 UTC"
    assert entry.actor_id == actors["admin"].pk


@pytest.mark.django_db
def test_admin_disables_records_audit(client, actors):
    _enable("earlier message")
    client.force_login(actors["admin"])
    resp = client.post(
        reverse("admin_console:maintenance"),
        {"is_enabled": "", "message": "earlier message"},
        follow=True,
    )
    assert resp.status_code == 200
    assert MaintenanceMode.objects.get().is_enabled is False
    entry = AuditLogEntry.objects.get(action=Action.MAINTENANCE_DISABLED)
    # The message active when the pause was lifted is recorded for forensics.
    assert entry.metadata["previous_message"] == "earlier message"


@pytest.mark.django_db
def test_message_only_change_while_on_reannounces(client, actors):
    _enable("old")
    client.force_login(actors["admin"])
    client.post(
        reverse("admin_console:maintenance"),
        {"is_enabled": "on", "message": "new message"},
    )
    assert MaintenanceMode.objects.get().message == "new message"
    # A changed message while already on re-emits an ENABLED entry.
    assert AuditLogEntry.objects.filter(action=Action.MAINTENANCE_ENABLED).count() == 1


@pytest.mark.django_db
def test_noop_resubmit_records_nothing(client, actors):
    _enable("steady")
    client.force_login(actors["admin"])
    client.post(
        reverse("admin_console:maintenance"),
        {"is_enabled": "on", "message": "steady"},
    )
    assert (
        AuditLogEntry.objects.filter(
            action__in=[Action.MAINTENANCE_ENABLED, Action.MAINTENANCE_DISABLED]
        ).count()
        == 0
    )


@pytest.mark.django_db
def test_audit_message_is_redacted(client, actors):
    client.force_login(actors["admin"])
    client.post(
        reverse("admin_console:maintenance"),
        {"is_enabled": "on", "message": "secret ghp_abcdefghijklmnopqrstuvwx token"},
    )
    entry = AuditLogEntry.objects.get(action=Action.MAINTENANCE_ENABLED)
    assert "ghp_" not in entry.metadata["message"]
    assert "***" in entry.metadata["message"]


# ----------------------------------------------------------------- middleware (enforce)


@pytest.mark.django_db
def test_non_admin_write_blocked_when_on(client, actors):
    _enable("paused")
    # Anonymous public report POST is a write on a non-exempt, non-api path.
    resp = client.post(reverse("intake:report"), {})
    assert resp.status_code == 503
    assert b"Maintenance in progress" in resp.content


@pytest.mark.django_db
def test_non_admin_write_allowed_when_off(client, actors):
    resp = client.post(reverse("intake:report"), {})
    assert resp.status_code != 503


@pytest.mark.django_db
def test_non_admin_read_allowed_when_on(client, actors):
    _enable("paused")
    client.force_login(actors["member"])
    assert client.get(reverse("advisories:list")).status_code == 200


@pytest.mark.django_db
def test_admin_write_not_blocked_when_on(client, actors):
    _enable("paused")
    client.force_login(actors["admin"])
    # The toggle POST is itself a write; the admin must still be able to make it.
    resp = client.post(
        reverse("admin_console:maintenance"),
        {"is_enabled": "", "message": ""},
    )
    assert resp.status_code != 503
    assert MaintenanceMode.objects.get().is_enabled is False


@pytest.mark.django_db
def test_api_write_blocked_with_json(client, actors):
    _enable("paused")
    resp = client.post("/api/advisories/")
    assert resp.status_code == 503
    assert resp["Content-Type"].startswith("application/json")
    assert "maintenance" in resp.json()["detail"].lower()


@pytest.mark.django_db
def test_oidc_paths_exempt_when_on(client, actors):
    _enable("paused")
    # Logout is a POST under /oidc/ — paused users must still be able to leave.
    resp = client.post(reverse("oidc_logout"))
    assert resp.status_code != 503


@pytest.mark.django_db
def test_htmx_write_gets_refresh_header(client, actors):
    _enable("paused")
    resp = client.post(reverse("intake:report"), {}, HTTP_HX_REQUEST="true")
    assert resp.status_code == 503
    assert resp["HX-Refresh"] == "true"


@pytest.mark.django_db
def test_blocked_response_sets_retry_after(client, actors):
    _enable("paused")
    resp = client.post(reverse("intake:report"), {})
    assert resp["Retry-After"] == "3600"


# ------------------------------------------------------------------- banner / display


@pytest.mark.django_db
def test_paused_user_sees_banner_and_body_hook(client, actors):
    _enable("Scheduled upgrade")
    body = client.get(reverse("intake:report")).content.decode()
    assert "data-maintenance-paused" in body
    assert "Maintenance in progress" in body
    assert "Scheduled upgrade" in body


@pytest.mark.django_db
def test_admin_sees_admin_banner_without_pause_hook(client, actors):
    _enable("Scheduled upgrade")
    client.force_login(actors["admin"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert "Maintenance mode is ON" in body
    assert "data-maintenance-paused" not in body
    assert reverse("admin_console:maintenance") in body


@pytest.mark.django_db
def test_no_banner_when_off(client, actors):
    client.force_login(actors["member"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert "maintenance-banner" not in body
    assert "data-maintenance-paused" not in body


@pytest.mark.django_db
def test_banner_message_is_redacted_for_display(client, actors):
    # A token accidentally pasted into the message must not surface verbatim
    # in the banner shown to every visitor (mirrors the audit redaction).
    _enable("contact ghp_abcdefghijklmnopqrstuvwx now")
    body = client.get(reverse("intake:report")).content.decode()
    assert "ghp_" not in body
    assert "***" in body


# --------------------------------------------------- middleware: extra coverage (review)


@pytest.mark.django_db
def test_authenticated_non_admin_write_blocked_when_on(client, actors):
    # The headline INV-MAINT-1 scenario: a logged-in member with normal write
    # access is paused. Exercises the is_global_admin group-lookup branch.
    _enable("paused")
    client.force_login(actors["member"])
    resp = client.post(reverse("advisories:create"), {})
    assert resp.status_code == 503


@pytest.mark.django_db
def test_django_admin_not_exempt_from_pause(client, actors):
    # /django-admin/ is governed by the same is_global_admin gate as everything
    # else — a non-admin write there is paused (no stale-is_staff bypass).
    _enable("paused")
    client.force_login(actors["member"])
    resp = client.post("/django-admin/")
    assert resp.status_code == 503


@pytest.mark.django_db
def test_ghsa_webhook_exempt_when_on(client, actors):
    # Inbound GitHub webhook is machine traffic, not a user action — it must
    # still be received (the view does its own HMAC check) rather than 503'd.
    _enable("paused")
    resp = client.post("/ghsa/webhook/", data="{}", content_type="application/json")
    assert resp.status_code != 503


@pytest.mark.django_db
def test_team_member_can_read_write_view_but_not_write(client, actors, make_project):
    # A member with real write access still gets the GET (read) of a
    # write-capable view, while the POST (write) is paused.
    make_project("p", team_members=[actors["member"]])
    _enable("paused")
    client.force_login(actors["member"])
    assert client.get(reverse("advisories:create")).status_code == 200
    assert client.post(reverse("advisories:create"), {}).status_code == 503


@pytest.mark.django_db
def test_single_enable_records_one_entry(client, actors):
    client.force_login(actors["admin"])
    client.post(reverse("admin_console:maintenance"), {"is_enabled": "on", "message": "x"})
    assert AuditLogEntry.objects.filter(action=Action.MAINTENANCE_ENABLED).count() == 1


@pytest.mark.django_db
def test_message_edit_while_off_persists_without_toggle_audit(client, actors):
    # OFF→OFF message edit stages the banner text; the row is mutated but no
    # enable/disable audit is emitted (no state transition).
    client.force_login(actors["admin"])
    client.post(reverse("admin_console:maintenance"), {"is_enabled": "", "message": "staged"})
    assert MaintenanceMode.objects.get().message == "staged"
    assert MaintenanceMode.objects.get().is_enabled is False
    assert (
        AuditLogEntry.objects.filter(
            action__in=[Action.MAINTENANCE_ENABLED, Action.MAINTENANCE_DISABLED]
        ).count()
        == 0
    )
