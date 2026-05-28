from django.urls import path

from . import views

app_name = "notifications"

urlpatterns = [
    path("preferences/", views.preferences, name="preferences"),
    path(
        "advisory/<advid:advisory_id>/preferences/",
        views.advisory_preferences,
        name="advisory_preferences",
    ),
]
