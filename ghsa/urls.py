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
    path("sync-all-pmi/", views.sync_all_pmi_repos, name="sync-all-pmi"),
    path("reconcile/", views.reconcile_now, name="reconcile"),
    path("discover/", views.discover_now, name="discover"),
    path("catch-up-webhooks/", views.catch_up_webhooks, name="catch-up-webhooks"),
    path("rescan-installations/", views.rescan_installations, name="rescan-installations"),
    path(
        "advisories/<advid:advisory_id>/refresh/",
        views.refresh_advisory_ghsa,
        name="refresh-advisory",
    ),
    path("cve-push/<int:task_id>/retry/", views.retry_cve_push, name="retry-cve-push"),
    path("cve-push/retry-all/", views.retry_all_cve_pushes, name="retry-all-cve-pushes"),
    path("webhook/", webhooks.webhook, name="webhook"),
]
