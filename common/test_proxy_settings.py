"""Tests for the reverse-proxy / edge-TLS settings knobs.

Behind a TLS-terminating proxy (OpenShift Route, Ingress) the app receives
plain HTTP. ``USE_X_FORWARDED_PROTO`` wires ``SECURE_PROXY_SSL_HEADER`` so
``request.is_secure()`` reflects the original scheme, and
``SECURE_REDIRECT_EXEMPT`` keeps probe/scrape endpoints answering with their
real status instead of a 301 (kubelet counts 3xx as probe success, which
would silently disable readiness checking).
"""

from __future__ import annotations

from django.conf import settings
from django.http import HttpResponse
from django.middleware.security import SecurityMiddleware
from django.test import RequestFactory, override_settings

_rf = RequestFactory()


def test_proxy_header_off_by_default():
    # USE_X_FORWARDED_PROTO is unset in test settings → the header must not
    # be trusted (a client could forge it when no proxy strips it).
    assert getattr(settings, "SECURE_PROXY_SSL_HEADER", None) is None
    req = _rf.get("/", HTTP_X_FORWARDED_PROTO="https")
    assert req.is_secure() is False


@override_settings(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"))
def test_forwarded_proto_header_marks_request_secure():
    assert _rf.get("/", HTTP_X_FORWARDED_PROTO="https").is_secure() is True
    # Without the header the request stays insecure (no blanket trust).
    assert _rf.get("/").is_secure() is False


def _ssl_redirect_middleware() -> SecurityMiddleware:
    # SecurityMiddleware snapshots settings in __init__ — build it inside the
    # override so SECURE_SSL_REDIRECT/SECURE_REDIRECT_EXEMPT take effect.
    return SecurityMiddleware(lambda request: HttpResponse("ok"))


@override_settings(SECURE_SSL_REDIRECT=True)
def test_probe_and_metrics_paths_exempt_from_ssl_redirect():
    mw = _ssl_redirect_middleware()
    for path in ("/healthz", "/readyz", "/metrics"):
        response = mw(_rf.get(path))
        assert response.status_code == 200, path


@override_settings(SECURE_SSL_REDIRECT=True)
def test_other_paths_still_redirect_to_https():
    response = _ssl_redirect_middleware()(_rf.get("/advisories/"))
    assert response.status_code == 301
    assert response["Location"].startswith("https://")
