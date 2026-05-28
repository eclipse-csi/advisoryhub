"""Public vulnerability report intake form.

The form is intentionally minimal:

* No ``reporter_email`` / no ``reporter_pgp_key`` fields. Reporter email
  is *only* derived from the authenticated user's OIDC-verified profile;
  there is no path for free-text email to enter the system. Anonymous
  reporters may set ``reporter_display_name`` for crediting purposes only
  — it is not used for authorization or contact.
* Project resolution by slug (not pk). The form value ``__unsorted__``
  means "I don't know which project" and routes the resulting advisory
  to the ``unsorted`` sentinel project for admin triage.
* Anti-abuse: honeypot field for anonymous users (silently dropped via a
  separate ``HoneypotSubmission`` table by the view); optional hCaptcha
  when site/secret keys are configured.

The honeypot rule is **never raise** when triggered — the view still
returns the success page so bots learn nothing.
"""

from __future__ import annotations

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxLengthValidator

from projects.models import PMI_ID_VALIDATOR, Project

UNSORTED_SENTINEL = "__unsorted__"


class VulnerabilityReportForm(forms.Form):
    """Public-facing report submission form."""

    project_slug = forms.CharField(
        required=True,
        max_length=100,
        help_text=(
            f"PMI project id (e.g. 'technology.jetty') or '{UNSORTED_SENTINEL}' if you do not know."
        ),
    )
    summary = forms.CharField(max_length=300, required=True)
    details = forms.CharField(
        widget=forms.Textarea,
        required=True,
        validators=[MaxLengthValidator(16384)],
        help_text="Markdown is supported.",
    )
    reporter_display_name = forms.CharField(
        max_length=200,
        required=False,
        help_text=("Optional. Used only for crediting on the resulting advisory."),
    )

    # Honeypot. Real users won't see or fill this; bots will. Layout +
    # aria-hidden go on the rendered widget in the template.
    website = forms.CharField(required=False, widget=forms.HiddenInput, label="")

    def __init__(self, *args, authenticated: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.authenticated = authenticated
        self._honeypot_triggered = False
        # Resolved project after clean_project_slug. ``None`` only happens
        # when the form was invalid; the service layer expects a Project.
        self._resolved_project: Project | None = None

        if authenticated:
            # Authenticated users get neither anti-abuse field.
            self.fields.pop("website", None)
        else:
            self._add_hcaptcha_if_configured()

    def _add_hcaptcha_if_configured(self) -> None:
        site_key = getattr(settings, "HCAPTCHA_SITE_KEY", "")
        secret_key = getattr(settings, "HCAPTCHA_SECRET_KEY", "")
        if not (site_key and secret_key):
            return
        try:
            from hcaptcha.fields import hCaptchaField
        except ImportError:  # pragma: no cover — captcha unconfigured fallback
            return
        self.fields["hcaptcha"] = hCaptchaField()

    # ------------------------------------------------------------------
    # Field cleaners
    # ------------------------------------------------------------------

    def clean_project_slug(self) -> str:
        raw = (self.cleaned_data.get("project_slug") or "").strip()
        if raw == UNSORTED_SENTINEL:
            self._resolved_project = Project.objects.get(slug="unsorted")
            return raw
        PMI_ID_VALIDATOR(raw)
        try:
            project = Project.objects.get(slug=raw)
        except Project.DoesNotExist as exc:
            raise ValidationError("Unknown project.") from exc
        if project.slug == "unsorted":
            # Internal sentinel — pickable only via the explicit __unsorted__
            # form value, never by typing its slug directly.
            raise ValidationError("Unknown project.")
        self._resolved_project = project
        return raw

    def clean_website(self) -> str:
        """Honeypot — record the trip but never raise."""
        value = (self.cleaned_data.get("website") or "").strip()
        if value:
            self._honeypot_triggered = True
        return ""

    @property
    def resolved_project(self) -> Project | None:
        return self._resolved_project

    @property
    def honeypot_triggered(self) -> bool:
        return self._honeypot_triggered
