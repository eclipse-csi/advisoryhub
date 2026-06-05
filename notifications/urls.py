from django.urls import path

from . import views

app_name = "notifications"

urlpatterns = [
    path("inbox/", views.inbox, name="inbox"),
    path("inbox/<int:pk>/read/", views.mark_read, name="mark_read"),
    path("inbox/read-all/", views.mark_all_read, name="mark_all_read"),
    path("preferences/", views.preferences, name="preferences"),
    path(
        "advisory/<advid:advisory_id>/preferences/",
        views.advisory_preferences,
        name="advisory_preferences",
    ),
]
