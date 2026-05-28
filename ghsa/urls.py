from django.urls import path

from . import views, webhooks

app_name = "ghsa"

urlpatterns = [
    path("connect/", views.connect_github_app, name="connect"),
    path(
        "projects/<uuid:project_id>/sync-repos/",
        views.sync_project_repos,
        name="sync-project-repos",
    ),
    path(
        "projects/<uuid:project_id>/sync-ghsas/",
        views.sync_project_ghsas,
        name="sync-project-ghsas",
    ),
    path("sync-all/", views.sync_all_ghsas, name="sync-all"),
    path("rescan-installations/", views.rescan_installations, name="rescan-installations"),
    path(
        "advisories/<advid:advisory_id>/refresh/",
        views.refresh_advisory_ghsa,
        name="refresh-advisory",
    ),
    path("cve-push/<int:task_id>/retry/", views.retry_cve_push, name="retry-cve-push"),
    path("webhook/", webhooks.webhook, name="webhook"),
]
