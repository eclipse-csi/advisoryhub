from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("me/", views.profile_view, name="profile"),
    path("signed-out/", views.signed_out_view, name="signed_out"),
]
