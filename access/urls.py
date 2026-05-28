from django.urls import path

from . import views

app_name = "access"

urlpatterns = [
    path("<advid:advisory_id>/access/", views.access_panel, name="panel"),
    path("<advid:advisory_id>/access/save/", views.batch_save, name="batch_save"),
]
