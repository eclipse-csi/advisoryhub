"""Tests for the ``{% user_chip %}`` template tag and ``User.display_label``.

Covers:
- the model helper falls back from display_name to email to "—"
- the chip renders the display name as the visible label
- the chip falls back to email when display_name is empty
- the chip falls back to the ``fallback`` argument when both are empty
- a ``None`` user renders only the fallback (no popover)
- the popover lists every group the user belongs to
- the popover groups section is absent when the user has no groups
- the chip ``user.groups`` access doesn't N+1 when callers prefetch
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from django.contrib.auth.models import Group
from django.db import connection
from django.template import Context, Template
from django.test.utils import CaptureQueriesContext

from accounts.models import User


def _render(
    user,
    fallback: str = "—",
    *,
    can_see_emails: bool = True,
    request_user=None,
) -> str:
    """Render a chip. ``can_see_emails`` sets the ``viewer_can_see_emails`` flag
    the view would normally compute (default ``True`` — owner's-eye view, which
    is what the popover/groups tests below exercise). ``request_user`` simulates
    the logged-in viewer so the self-email exception can be tested."""
    tpl = Template("{% load user_display %}{% user_chip user fallback=fallback %}")
    ctx = {"user": user, "fallback": fallback, "viewer_can_see_emails": can_see_emails}
    if request_user is not None:
        ctx["request"] = SimpleNamespace(user=request_user)
    return tpl.render(Context(ctx))


@pytest.mark.django_db
class TestDisplayLabel:
    def test_prefers_display_name(self):
        u = User.objects.create_user(email="alice@example.org")
        u.display_name = "Alice Cooper"
        u.save()
        assert u.display_label() == "Alice Cooper"

    def test_falls_back_to_email(self):
        u = User.objects.create_user(email="alice@example.org")
        assert u.display_label() == "alice@example.org"

    def test_falls_back_to_dash_when_both_empty(self):
        # Pathological case: a User row with no email is not creatable
        # through ``create_user``, so construct in-memory.
        u = User(email="", display_name="")
        assert u.display_label() == "—"

    def test_custom_fallback(self):
        u = User(email="", display_name="")
        assert u.display_label(fallback="system") == "system"

    def test_whitespace_only_treated_as_empty(self):
        u = User(email="alice@example.org", display_name="   ")
        # display_name whitespace falls through, email survives because the
        # final strip preserves it.
        assert u.display_label() == "alice@example.org"


@pytest.mark.django_db
class TestUserChipTag:
    def test_renders_display_name(self):
        u = User.objects.create_user(email="alice@example.org")
        u.display_name = "Alice Cooper"
        u.save()
        html = _render(u)
        assert "Alice Cooper" in html
        assert 'class="user-chip"' in html

    def test_falls_back_to_email_when_no_display_name(self):
        u = User.objects.create_user(email="bob@example.org")
        html = _render(u)
        # The visible name is the email (which also appears in the popover);
        # both occurrences are expected.
        assert html.count("bob@example.org") >= 1
        assert "user-chip__name" in html

    def test_renders_fallback_for_none_user(self):
        html = _render(None, fallback="system")
        assert "system" in html
        assert "user-chip--missing" in html
        # No popover for missing users.
        assert "user-chip__pop" not in html

    def test_popover_lists_groups(self):
        u = User.objects.create_user(email="g@example.org")
        u.display_name = "Grace"
        u.save()
        sec, _ = Group.objects.get_or_create(name="advisoryhub-security")
        proj, _ = Group.objects.get_or_create(name="eclipse-jetty-security")
        u.groups.add(sec, proj)
        html = _render(u)
        assert "user-chip__groups-label" in html
        assert "advisoryhub-security" in html
        assert "eclipse-jetty-security" in html

    def test_popover_shows_friendly_name_for_admin_group(self, settings):
        """The admin group renders with its friendly name *and* raw slug; a
        per-project security-team group keeps only its slug."""
        from common.constants import SECURITY_TEAM_DISPLAY_NAME

        u = User.objects.create_user(email="g@example.org")
        u.display_name = "Grace"
        u.save()
        u.groups.add(
            Group.objects.get_or_create(name=settings.OIDC_ADMIN_GROUP)[0],
            Group.objects.get_or_create(name="eclipse-jetty-security")[0],
        )
        html = _render(u)
        # Scope to the popover groups list — the seal's aria-label/title also
        # carry the friendly name, so assert against the <ul> alone.
        groups = html.split('user-chip__groups">', 1)[1].split("</ul>", 1)[0]
        assert SECURITY_TEAM_DISPLAY_NAME in groups  # friendly name for admin group
        assert settings.OIDC_ADMIN_GROUP in groups  # raw slug retained
        assert "eclipse-jetty-security" in groups  # project group present
        assert groups.count(SECURITY_TEAM_DISPLAY_NAME) == 1  # only the admin group

    def test_popover_omits_groups_section_when_empty(self):
        u = User.objects.create_user(email="loner@example.org")
        u.display_name = "Loner"
        u.save()
        html = _render(u)
        assert "Loner" in html
        assert "user-chip__groups-label" not in html
        assert "user-chip__groups" not in html

    def test_popover_includes_email(self):
        u = User.objects.create_user(email="alice@example.org")
        u.display_name = "Alice Cooper"
        u.save()
        html = _render(u)
        assert 'class="user-chip__email"' in html
        assert "alice@example.org" in html


@pytest.mark.django_db
class TestUserChipEmailGating:
    """Non-owners never see another user's email — popover hidden, name masked
    where no display name exists (INV-PRIVACY-4)."""

    def test_non_owner_no_display_name_shows_masked_name_no_popover(self):
        u = User.objects.create_user(email="bob@example.org")
        html = _render(u, can_see_emails=False)
        assert "bob@example.org" not in html
        assert "b•••@example.org" in html  # masked surface label
        assert "user-chip__pop" not in html  # no popover at all
        assert "user-chip--plain" in html

    def test_non_owner_with_display_name_hides_email_and_groups(self):
        u = User.objects.create_user(email="alice@example.org")
        u.display_name = "Alice Cooper"
        u.save()
        u.groups.add(Group.objects.get_or_create(name="advisoryhub-security")[0])
        html = _render(u, can_see_emails=False)
        assert "Alice Cooper" in html  # name still shown
        assert "alice@example.org" not in html  # email hidden
        assert "user-chip__pop" not in html  # whole popover (incl. groups) gone
        assert "advisoryhub-security" not in html

    def test_user_always_sees_own_email(self):
        """The self-exception: a non-owner viewing their own chip still sees it."""
        u = User.objects.create_user(email="self@example.org")
        html = _render(u, can_see_emails=False, request_user=u)
        assert "self@example.org" in html
        assert "user-chip__pop" in html

    def test_other_users_email_still_hidden_when_viewing_self_context(self):
        """A non-owner whose own request is set still can't see *other* people."""
        me = User.objects.create_user(email="me@example.org")
        other = User.objects.create_user(email="other@example.org")
        html = _render(other, can_see_emails=False, request_user=me)
        assert "other@example.org" not in html
        assert "o•••@example.org" in html
        assert "user-chip__pop" not in html


@pytest.mark.django_db
class TestUserChipSecurityTeamMarker:
    """A shield marker flags global security-team / admin members (members of
    ``OIDC_ADMIN_GROUP``) wherever they're named. Per-project security teams are
    a different concept and must not be marked."""

    SEAL = "user-chip__seal"
    LABEL = "Eclipse Foundation Security Team"

    def test_marker_present_for_global_admin(self):
        u = User.objects.create_user(email="admin@example.org")
        u.display_name = "Adam Admin"
        u.save()
        u.groups.add(Group.objects.get_or_create(name="advisoryhub-security")[0])
        html = _render(u)
        assert self.SEAL in html
        assert self.LABEL in html

    def test_marker_absent_for_non_admin(self):
        u = User.objects.create_user(email="nobody@example.org")
        u.display_name = "Nora Nobody"
        u.save()
        html = _render(u)
        assert self.SEAL not in html
        assert self.LABEL not in html

    def test_marker_absent_for_project_security_team_only(self):
        """Membership in a *project* security-team group is not the global team."""
        u = User.objects.create_user(email="proj@example.org")
        u.display_name = "Pat Project"
        u.save()
        u.groups.add(Group.objects.get_or_create(name="eclipse-jetty-security")[0])
        html = _render(u)
        assert self.SEAL not in html

    def test_marker_present_even_when_email_gated(self):
        """A non-owner viewing an admin's plain chip (no popover) still sees the
        marker — identifying the security team must not depend on email visibility."""
        u = User.objects.create_user(email="admin@example.org")
        u.display_name = "Adam Admin"
        u.save()
        u.groups.add(Group.objects.get_or_create(name="advisoryhub-security")[0])
        html = _render(u, can_see_emails=False)
        assert "user-chip--plain" in html
        assert "user-chip__pop" not in html  # popover suppressed
        assert self.SEAL in html  # marker survives

    def test_marker_absent_for_none_user(self):
        html = _render(None, fallback="system")
        assert self.SEAL not in html


@pytest.mark.django_db
class TestUserChipNoNPlusOne:
    def test_groups_prefetched_avoids_n_plus_one(self):
        """When callers prefetch ``groups`` on the User queryset, rendering
        N chips should not trigger N additional queries for groups."""
        g1, _ = Group.objects.get_or_create(name="g1")
        g2, _ = Group.objects.get_or_create(name="g2")
        for i in range(5):
            u = User.objects.create_user(email=f"u{i}@example.org")
            u.display_name = f"User {i}"
            u.save()
            u.groups.add(g1, g2)

        # Without prefetch: one query per user's .groups.all()
        with CaptureQueriesContext(connection) as ctx_no_prefetch:
            users = list(User.objects.all())
            for u in users:
                _render(u)
        # Five users => five group queries (one per user) without prefetch.
        baseline = len(ctx_no_prefetch.captured_queries)

        with CaptureQueriesContext(connection) as ctx_prefetch:
            users = list(User.objects.prefetch_related("groups").all())
            for u in users:
                _render(u)
        prefetched = len(ctx_prefetch.captured_queries)

        # Prefetched: one query for users + one for the groups M2M,
        # regardless of N. Loose check: prefetched run does strictly fewer
        # queries than the un-prefetched run.
        assert prefetched < baseline
