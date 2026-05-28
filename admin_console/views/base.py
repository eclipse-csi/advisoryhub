"""Shared helpers for admin console views.

The console is visible only to members of the configured admin/security
group. Every action endpoint re-checks ``perms.can_review`` so URL
leakage doesn't expand authority.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied

from advisories import permissions as perms


def admin_required(view_func):
    @login_required
    def wrapper(request, *args, **kwargs):
        if not perms.can_review(request.user):
            raise PermissionDenied("Admin/security team access only.")
        return view_func(request, *args, **kwargs)

    wrapper.__name__ = view_func.__name__
    return wrapper
