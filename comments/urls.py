from django.urls import path

from . import views

app_name = "comments"

urlpatterns = [
    path("<advid:advisory_id>/comments/", views.comment_thread, name="thread"),
    path("<advid:advisory_id>/timeline/", views.timeline, name="timeline"),
    path("<advid:advisory_id>/comments/new/", views.comment_create, name="create"),
    path(
        "<advid:advisory_id>/comments/<int:comment_id>/edit/",
        views.comment_edit,
        name="edit",
    ),
    path(
        "<advid:advisory_id>/comments/<int:comment_id>/history/",
        views.comment_history,
        name="history",
    ),
    path(
        "<advid:advisory_id>/comments/<int:comment_id>/redact/",
        views.comment_redact,
        name="redact",
    ),
]
