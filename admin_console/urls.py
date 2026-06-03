from django.urls import path

from . import views

app_name = "admin_console"

urlpatterns = [
    path("", views.inbox, name="index"),
    path("cves/", views.cves, name="cves"),
    path("publications/", views.publications, name="publications"),
    path("audit/", views.audit, name="audit"),
    path("access-log/", views.access_log, name="access_log"),
    path("cve/<int:task_id>/transition/", views.cve_transition, name="cve_transition"),
    path(
        "cve/<int:task_id>/reject-modal/",
        views.cve_reject_modal,
        name="cve_reject_modal",
    ),
    path(
        "orphans/<int:orphan_id>/mark-rejected/",
        views.orphan_mark_rejected,
        name="orphan_mark_rejected",
    ),
    path(
        "orphans/reassignment/<int:task_id>/resolve/",
        views.orphan_reassignment_resolve,
        name="orphan_reassignment_resolve",
    ),
    path("projects/", views.project_list, name="project_list"),
    path("projects/new/", views.project_create, name="project_create"),
    path("projects/<uuid:project_id>/edit/", views.project_edit, name="project_edit"),
    path(
        "projects/<uuid:project_id>/sync-roster/",
        views.project_sync_roster,
        name="project_sync_roster",
    ),
    path("users/", views.user_list, name="user_list"),
    path("users/<int:user_id>/", views.user_detail, name="user_detail"),
    path("groups/", views.group_list, name="group_list"),
    path("groups/<int:group_id>/", views.group_detail, name="group_detail"),
    path("maintenance/", views.maintenance, name="maintenance"),
]
