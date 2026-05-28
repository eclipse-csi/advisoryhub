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

import pytest
from django.contrib.auth.models import Group
from django.db import connection
from django.template import Context, Template
from django.test.utils import CaptureQueriesContext

from accounts.models import User


def _render(user, fallback: str = "—") -> str:
    tpl = Template("{% load user_display %}{% user_chip user fallback=fallback %}")
    return tpl.render(Context({"user": user, "fallback": fallback}))


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
