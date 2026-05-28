"""Public intake URL surface.

Triage URLs moved to :mod:`advisories.urls` under ``/advisories/triage/...``.
This app now hosts only the public POST endpoint, the JSON project
picker, and the thank-you page.
"""

from django.urls import path

from . import views

app_name = "intake"

urlpatterns = [
    path("", views.report_form, name="report"),
    path("projects.json", views.project_picker_json, name="projects_json"),
    path("thank-you/", views.thank_you, name="thank_you"),
]
