from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render


def home(request: HttpRequest) -> HttpResponse:
    """Root route (``/``).

    Authenticated users go straight to their advisory list — the working
    surface. Anonymous visitors get a small AdvisoryHub-branded sign-in landing
    instead of an immediate, unexplained bounce to the IdP, so the first screen
    is recognisably this app. No private data lives here: just the sign-in
    button and the public "report a vulnerability" entry point (which already
    exists, anonymously, at ``/report/``).
    """
    if request.user.is_authenticated:
        return redirect("advisories:list")
    return render(request, "landing.html")
