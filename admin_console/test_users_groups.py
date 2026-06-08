"""Tests for the read-only Users & Groups admin console pages."""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group
from django.urls import reverse

from access.models import (
    AdvisoryAccessGrant,
    PendingInvitation,
    Permission,
    PrincipalType,
)
from accounts.models import NotificationPreference
from advisories.models import Advisory
from notifications.models import AdvisoryNotificationPreference


@pytest.fixture
def base(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="m@example.org")
    project = make_project("alpha", team_members=[member])
    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"admin": admin, "member": member, "project": project, "advisory": advisory}


URL_NAMES = ["user_list", "group_list"]


# ----- Auth gate ----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("name", URL_NAMES)
def test_list_pages_403_for_non_admin(client, base, name):
    client.force_login(base["member"])
    response = client.get(reverse(f"admin_console:{name}"))
    assert response.status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize("name", URL_NAMES)
def test_list_pages_200_for_admin(client, base, name):
    client.force_login(base["admin"])
    response = client.get(reverse(f"admin_console:{name}"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_user_detail_403_for_non_admin(client, base):
    client.force_login(base["member"])
    response = client.get(reverse("admin_console:user_detail", args=[base["admin"].pk]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_group_detail_403_for_non_admin(client, base):
    group = Group.objects.get(name="advisoryhub-security")
    client.force_login(base["member"])
    response = client.get(reverse("admin_console:group_detail", args=[group.pk]))
    assert response.status_code == 403


@pytest.mark.django_db
def test_list_pages_redirect_anonymous(client, base):
    response = client.get(reverse("admin_console:user_list"))
    assert response.status_code in (301, 302)


# ----- Sidebar nav --------------------------------------------------------


@pytest.mark.django_db
def test_sidebar_marks_users_section_active(client, base):
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_list")).content.decode()
    users_idx = body.find(f'href="{reverse("admin_console:user_list")}"')
    assert users_idx != -1
    # Window around the sidebar link should contain aria-current
    window = body[users_idx : users_idx + 200]
    assert 'aria-current="page"' in window


@pytest.mark.django_db
def test_sidebar_marks_groups_section_active_on_group_pages(client, base):
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:group_list")).content.decode()

    def open_tag(url: str) -> str:
        # Slice just the opening <a …> tag so the aria-current of an adjacent
        # nav entry can't leak into the window (the inactive links are short).
        idx = body.find(f'href="{url}"')
        assert idx != -1, url
        return body[idx : body.find(">", idx)]

    # Groups is now its own top-level nav entry and lights up on group pages…
    assert 'aria-current="page"' in open_tag(reverse("admin_console:group_list"))
    # …and Users is no longer marked active on group pages.
    assert 'aria-current="page"' not in open_tag(reverse("admin_console:user_list"))


# ----- User list ---------------------------------------------------------


@pytest.mark.django_db
def test_user_list_paginates(client, base, make_user):
    for i in range(55):
        make_user(email=f"u{i:02d}@example.org")
    client.force_login(base["admin"])
    page1 = client.get(reverse("admin_console:user_list"))
    assert page1.status_code == 200
    assert page1.context["page"].paginator.num_pages >= 2
    page2 = client.get(reverse("admin_console:user_list") + "?page=2")
    assert page2.status_code == 200
    assert "Previous" in page2.content.decode()


@pytest.mark.django_db
def test_user_list_search_by_email_substring(client, base, make_user):
    make_user(email="alice.smith@example.org")
    make_user(email="bob@example.org")
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_list") + "?q=alice").content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "alice.smith@example.org" in table
    assert "bob@example.org" not in table


@pytest.mark.django_db
def test_user_list_search_by_display_name(client, base, make_user):
    other = make_user(email="x@example.org")
    other.display_name = "Bob Vance"
    other.save()
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_list") + "?q=Vance").content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "x@example.org" in table
    assert "admin@example.org" not in table


@pytest.mark.django_db
def test_user_list_filter_by_group(client, base, make_user):
    g, _ = Group.objects.get_or_create(name="researchers")
    inside = make_user(email="in@example.org")
    inside.groups.add(g)
    make_user(email="out@example.org")
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_list") + f"?group={g.pk}").content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "in@example.org" in table
    assert "out@example.org" not in table


@pytest.mark.django_db
def test_user_list_invalid_group_filter_ignored(client, base):
    client.force_login(base["admin"])
    response = client.get(reverse("admin_console:user_list") + "?group=99999")
    assert response.status_code == 200
    # Filter silently dropped — admin user still listed.
    body = response.content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "admin@example.org" in table


@pytest.mark.django_db
def test_user_list_clear_link_when_filter_active(client, base):
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_list") + "?q=alice").content.decode()
    assert reverse("admin_console:user_list") in body
    assert "Clear" in body


# ----- User detail -------------------------------------------------------


@pytest.fixture
def rich_user(base, make_user, make_project):
    """A user with grants/invitations/notif overrides covering every section."""
    other_group, _ = Group.objects.get_or_create(name="research-team")
    user = make_user(email="alice@example.org", groups=["research-team"])

    # Project security team membership via group
    secured_project = make_project("bravo", team_members=[user])

    # Direct grant on base advisory
    AdvisoryAccessGrant.objects.create(
        advisory=base["advisory"],
        principal_type=PrincipalType.USER,
        principal_id=user.pk,
        permission=Permission.COLLABORATOR,
    )

    # Group-inherited grant (research-team)
    extra_advisory = Advisory.objects.create(
        project=base["project"], summary="extra", created_by=base["member"]
    )
    AdvisoryAccessGrant.objects.create(
        advisory=extra_advisory,
        principal_type=PrincipalType.GROUP,
        principal_id=other_group.pk,
        permission=Permission.VIEWER,
    )

    # Pending invitation with mixed-case email to verify iexact match
    pending_advisory = Advisory.objects.create(
        project=base["project"], summary="pending", created_by=base["member"]
    )
    PendingInvitation.objects.create(
        advisory=pending_advisory,
        email="ALICE@example.org",
        permission=Permission.VIEWER,
    )

    # Notification preferences: global + 2 per-advisory overrides
    NotificationPreference.objects.create(user=user)
    AdvisoryNotificationPreference.objects.create(
        user=user, advisory=base["advisory"], on_advisory_published=False
    )
    AdvisoryNotificationPreference.objects.create(
        user=user, advisory=extra_advisory, on_advisory_published=True
    )

    return {
        "user": user,
        "group": other_group,
        "secured_project": secured_project,
        "extra_advisory": extra_advisory,
        "pending_advisory": pending_advisory,
    }


@pytest.mark.django_db
def test_user_detail_renders_all_sections(client, base, rich_user):
    client.force_login(base["admin"])
    response = client.get(reverse("admin_console:user_detail", args=[rich_user["user"].pk]))
    assert response.status_code == 200
    body = response.content.decode()
    # Header
    assert "alice@example.org" in body
    # Groups
    assert "research-team" in body
    # Project security teams (via group)
    assert rich_user["secured_project"].slug in body
    # Direct grant
    assert base["advisory"].advisory_id in body
    assert "collaborator" in body
    # Group-inherited grant
    assert rich_user["extra_advisory"].advisory_id in body
    assert "Via group research-team" in body
    # Pending invitation (iexact match against ALICE@example.org)
    assert rich_user["pending_advisory"].advisory_id in body
    # Notification preferences section
    assert "Per-advisory overrides" in body
    assert "2 advisories have overrides" in body
    # Non-admin → no admin banner
    assert "Global admin." not in body


@pytest.mark.django_db
def test_user_detail_admin_banner_when_admin(client, base, rich_user, settings):
    rich_user["user"].groups.add(Group.objects.get(name=settings.OIDC_ADMIN_GROUP))
    client.force_login(base["admin"])
    body = client.get(
        reverse("admin_console:user_detail", args=[rich_user["user"].pk])
    ).content.decode()
    assert "Global admin." in body


@pytest.mark.django_db
def test_user_detail_pending_invitation_iexact_match(client, base, make_user):
    user = make_user(email="case@example.org")
    PendingInvitation.objects.create(
        advisory=base["advisory"],
        email="CASE@EXAMPLE.ORG",
        permission=Permission.VIEWER,
    )
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_detail", args=[user.pk])).content.decode()
    # Section header is present...
    assert "Pending invitations" in body
    # ...and the advisory id from the mixed-case invitation appears
    assert base["advisory"].advisory_id in body


@pytest.mark.django_db
def test_user_detail_pending_invitation_excludes_redeemed(client, base, make_user):
    user = make_user(email="redeemed@example.org")
    from django.utils import timezone

    PendingInvitation.objects.create(
        advisory=base["advisory"],
        email="redeemed@example.org",
        permission=Permission.VIEWER,
        redeemed_at=timezone.now(),
        redeemed_by=user,
    )
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_detail", args=[user.pk])).content.decode()
    assert "No pending invitations." in body


@pytest.mark.django_db
def test_user_detail_empty_sections_render(client, base, make_user):
    lonely = make_user(email="lonely@example.org")
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:user_detail", args=[lonely.pk])).content.decode()
    assert "No direct grants." in body
    assert "No group-inherited grants." in body
    assert "No pending invitations." in body
    assert "Not on any project security team." in body
    assert "Not a member of any group." in body


# ----- Group list & detail ----------------------------------------------


@pytest.mark.django_db
def test_group_list_search_by_name(client, base):
    Group.objects.get_or_create(name="researchers")
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:group_list") + "?q=research").content.decode()
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "researchers" in table
    assert "advisoryhub-security" not in table


@pytest.mark.django_db
def test_group_list_shows_admin_badge(client, base):
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:group_list")).content.decode()
    # Admin group row should carry the admin badge ("yes" inside a <strong>).
    # Scope the search to the table body — the navbar's user chip popover
    # also mentions the admin's group memberships.
    table = body.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    admin_row_start = table.find("advisoryhub-security")
    assert admin_row_start != -1
    window = table[admin_row_start : admin_row_start + 600]
    assert "<strong>" in window and "yes" in window


@pytest.mark.django_db
def test_group_list_counts_members_and_projects(client, base, make_user):
    g, _ = Group.objects.get_or_create(name="researchers")
    make_user(email="a@example.org", groups=["researchers"])
    make_user(email="b@example.org", groups=["researchers"])
    client.force_login(base["admin"])
    response = client.get(reverse("admin_console:group_list") + "?q=researchers")
    assert response.status_code == 200
    rows = [g for g in response.context["page"].object_list if g.name == "researchers"]
    assert len(rows) == 1
    assert rows[0].member_count == 2
    assert rows[0].projects_secured_count == 0


@pytest.mark.django_db
def test_group_detail_lists_members_projects_and_grants(client, base, make_user):
    g, _ = Group.objects.get_or_create(name="research-team")
    user_a = make_user(email="ga@example.org", groups=["research-team"])
    make_user(email="gb@example.org", groups=["research-team"])
    AdvisoryAccessGrant.objects.create(
        advisory=base["advisory"],
        principal_type=PrincipalType.GROUP,
        principal_id=g.pk,
        permission=Permission.VIEWER,
    )
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:group_detail", args=[g.pk])).content.decode()
    # Members
    assert "ga@example.org" in body
    assert "gb@example.org" in body
    # Grant
    assert base["advisory"].advisory_id in body
    assert "viewer" in body
    # User detail link present
    assert reverse("admin_console:user_detail", args=[user_a.pk]) in body


@pytest.mark.django_db
def test_group_detail_admin_banner_for_admin_group(client, base, settings):
    g = Group.objects.get(name=settings.OIDC_ADMIN_GROUP)
    client.force_login(base["admin"])
    body = client.get(reverse("admin_console:group_detail", args=[g.pk])).content.decode()
    assert "Global admin group." in body


@pytest.mark.django_db
def test_group_detail_shows_secured_projects(client, base):
    # `alpha-security` is created by make_project("alpha"); the base fixture
    # places `member` on its security_team. Verify the project surfaces.
    secured_group = Group.objects.get(name="alpha-security")
    client.force_login(base["admin"])
    body = client.get(
        reverse("admin_console:group_detail", args=[secured_group.pk])
    ).content.decode()
    assert "alpha" in body  # slug
    assert "m@example.org" in body  # member


# ----- Read-only sentinel ------------------------------------------------


@pytest.mark.django_db
def test_pages_contain_no_mutation_forms(client, base, rich_user):
    """Sentinel against *accidental* mutation surfaces on these directory pages.

    The global layout includes a sign-out form (POST to /oidc/logout/); we
    assert no POST form *targets an /admin/users/ or /admin/groups/ URL* — with
    the sole exception of the deliberate ban/unban controls (INV-AUTH-8,
    ``admin_console/test_ban.py``) and the GDPR forget control
    (``admin_console/test_forget.py``) on the user-detail page.
    """
    import re

    client.force_login(base["admin"])
    pages = [
        reverse("admin_console:user_list"),
        reverse("admin_console:user_detail", args=[rich_user["user"].pk]),
        reverse("admin_console:group_list"),
        reverse("admin_console:group_detail", args=[rich_user["group"].pk]),
    ]
    pattern = re.compile(
        r'<form\b[^>]*\bmethod\s*=\s*"post"[^>]*\baction\s*=\s*"(/admin/(?:users|groups)/[^"]*)"',
        re.IGNORECASE,
    )
    allowed = re.compile(r"/admin/users/\d+/(?:ban|unban|forget)/$")
    for url in pages:
        body = client.get(url).content.decode()
        offenders = [m for m in pattern.findall(body) if not allowed.match(m)]
        assert not offenders, f"{url} should have no POST form targeting itself; found {offenders}"
