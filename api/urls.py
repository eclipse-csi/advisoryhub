from django.urls import path

from . import (
    views_access,
    views_advisories,
    views_comments,
    views_dashboard,
    views_publication,
)

app_name = "api"

urlpatterns = [
    # Advisories
    path("advisories/", views_advisories.advisory_list, name="advisory_list"),
    path(
        "advisories/<advid:advisory_id>/",
        views_advisories.advisory_detail,
        name="advisory_detail",
    ),
    # Comments
    path(
        "advisories/<advid:advisory_id>/comments/",
        views_comments.comments_collection,
        name="comments",
    ),
    # Access grants
    path(
        "advisories/<advid:advisory_id>/grants/",
        views_access.grants_collection,
        name="grants",
    ),
    path(
        "advisories/<advid:advisory_id>/grants/<int:grant_id>/",
        views_access.grant_detail,
        name="grant_detail",
    ),
    # Publication
    path(
        "advisories/<advid:advisory_id>/publication/",
        views_publication.publication_status,
        name="publication_status",
    ),
    path(
        "advisories/<advid:advisory_id>/publish/",
        views_publication.publish,
        name="publish",
    ),
    path(
        "publication/tasks/<int:task_id>/retry/",
        views_publication.retry_task,
        name="publication_retry",
    ),
    path(
        "publication/tasks/<int:task_id>/artifact/<str:kind>/",
        views_publication.artifact_preview,
        name="publication_artifact",
    ),
    # Dashboard / admin tasks
    path(
        "dashboard/cve/<int:task_id>/transition/",
        views_dashboard.cve_transition,
        name="cve_transition",
    ),
    path(
        "dashboard/review/<int:task_id>/decide/",
        views_dashboard.review_decide,
        name="review_decide",
    ),
]
