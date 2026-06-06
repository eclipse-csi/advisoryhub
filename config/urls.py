from django.contrib import admin
from django.urls import include, path, register_converter

from accounts.auth import AdvisoryHubOIDCCallbackView
from accounts.step_up import StepUpAuthRequestView
from advisories.path_converters import AdvisoryIdConverter
from common.health import healthz, readyz
from common.views import home

register_converter(AdvisoryIdConverter, "advid")

urlpatterns = [
    path("", home, name="home"),
    path("healthz", healthz, name="healthz"),
    path("readyz", readyz, name="readyz"),
    # Prometheus /metrics. Authentication is intentionally left to the
    # deployment (network policy or a sidecar/reverse-proxy auth header) —
    # the metrics endpoint is fine on a private port; do NOT expose it
    # on the public ingress.
    path("", include("django_prometheus.urls")),
    path("django-admin/", admin.site.urls),
    # Step-up flow and the failed-login-auditing callback override MUST be
    # declared before the mozilla_django_oidc include so they win URL
    # resolution. The callback reuses the library's own URL name, so the path
    # (and the registered redirect_uri) is unchanged.
    path("oidc/step-up/", StepUpAuthRequestView.as_view(), name="step_up_initiate"),
    path(
        "oidc/callback/",
        AdvisoryHubOIDCCallbackView.as_view(),
        name="oidc_authentication_callback",
    ),
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("advisories/", include("advisories.urls")),
    path("advisories/", include("comments.urls")),
    path("advisories/", include("access.urls")),
    path("accounts/", include("accounts.urls")),
    path("notifications/", include("notifications.urls")),
    path("admin/", include("admin_console.urls")),
    path("publication/", include("publication.urls")),
    path("ghsa/", include("ghsa.urls")),
    path("api/", include("api.urls")),
    path("report/", include("intake.urls")),
]
