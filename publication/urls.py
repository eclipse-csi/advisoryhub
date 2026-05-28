from django.urls import path

from . import views

app_name = "publication"

urlpatterns = [
    path("<advid:advisory_id>/publish/", views.publish, name="publish"),
    path("tasks/<int:task_id>/retry/", views.retry, name="retry"),
    path(
        "tasks/<int:task_id>/artifact/<str:kind>/",
        views.artifact_preview,
        name="artifact",
    ),
    path(
        "tasks/<int:task_id>/artifact/<str:kind>/download/",
        views.artifact_download,
        name="artifact_download",
    ),
]
