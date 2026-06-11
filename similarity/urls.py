from django.urls import path

from . import views

app_name = "similarity"

urlpatterns = [
    path("<advid:advisory_id>/similarity/", views.similarity_panel, name="panel"),
    path("<advid:advisory_id>/similarity/run/", views.similarity_run, name="run"),
]
