from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def profile_view(request):
    return render(request, "accounts/profile.html", {"user": request.user})


def signed_out_view(request):
    """Anonymous landing page after sign-out.

    Must NOT require authentication — it's the post-logout redirect target,
    so triggering @login_required here would bounce the user straight back
    through OIDC and silently re-authenticate them.
    """
    return render(request, "accounts/signed_out.html")
