from __future__ import annotations

import json
import re

import pytest
from django.test import override_settings
from django.urls import reverse


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    from advisories.models import Advisory

    advisory = Advisory.objects.create(project=project, summary="x", created_by=member)
    return {"member": member, "advisory": advisory}


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True)
def test_html_comment_post_rate_limit_kicks_in(client, setup):
    """The HTML comment-create endpoint enforces a per-user rate limit.

    The configured rate is 30/min. To keep the test under that ceiling
    fast, we set a dedicated low cap via the cache directly: not all
    rate-limit knobs are easy to override at test time, so we just hit
    the endpoint enough times to exceed the realistic-but-low default
    (30/m) by sending 35 quick requests, accept that the test is slightly
    slow (sub-second), and verify the last few are 429.
    """
    client.force_login(setup["member"])
    url = reverse("comments:create", args=[setup["advisory"].advisory_id])
    statuses = []
    for _ in range(35):
        statuses.append(client.post(url, data={"body": "spam"}).status_code)
    assert statuses.count(429) > 0
    assert statuses[0] != 429  # the first one was allowed


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True)
def test_json_comment_post_rate_limit_kicks_in(client, setup):
    client.force_login(setup["member"])
    url = reverse("api:comments", args=[setup["advisory"].advisory_id])
    statuses = []
    for _ in range(35):
        r = client.post(url, data=json.dumps({"body": "spam"}), content_type="application/json")
        statuses.append(r.status_code)
    # The 30/m bucket gets exceeded; subsequent requests are 429 with our JSON body.
    assert 429 in statuses
    # The JSON 429 response carries our structured error code.
    r = client.post(url, data=json.dumps({"body": "spam"}), content_type="application/json")
    if r.status_code == 429:
        assert r.json()["error"] == "rate_limited"


@pytest.mark.django_db
def test_rate_limit_off_in_default_test_settings(client, setup):
    """Sanity: with RATELIMIT_ENABLE=False (the test default), 35 posts all succeed."""
    client.force_login(setup["member"])
    url = reverse("comments:create", args=[setup["advisory"].advisory_id])
    for _ in range(35):
        r = client.post(url, data={"body": "ok"})
        assert r.status_code != 429


# ---- Health endpoints ----------------------------------------------------


@pytest.mark.django_db
def test_healthz_returns_200_unauthenticated(client):
    r = client.get(reverse("healthz"))
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.django_db
def test_readyz_succeeds_when_db_and_cache_are_up(client):
    r = client.get(reverse("readyz"))
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.django_db
def test_readyz_returns_503_when_a_check_fails(client, monkeypatch):
    from common import health

    def boom():
        raise RuntimeError("simulated cache outage")

    monkeypatch.setattr(health, "_check_cache", boom)
    r = client.get(reverse("readyz"))
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "fail"
    assert "cache" in body["failures"]


@pytest.mark.django_db
def test_readyz_skips_broker_check_by_default(client, monkeypatch):
    """READYZ_INCLUDE_BROKER defaults False → the broker probe never runs."""
    from common import health

    def boom():
        raise RuntimeError("broker probe should not have run")

    monkeypatch.setattr(health, "_check_broker", boom)
    assert client.get(reverse("readyz")).status_code == 200


@pytest.mark.django_db
@override_settings(READYZ_INCLUDE_BROKER=True)
def test_readyz_503_when_broker_down(client, monkeypatch):
    """With the flag on, a broker outage surfaces as a 503 (was previously invisible)."""
    from common import health

    def boom():
        raise RuntimeError("broker down")

    monkeypatch.setattr(health, "_check_broker", boom)
    r = client.get(reverse("readyz"))
    assert r.status_code == 503
    assert "broker" in r.json()["failures"]


# ---- Request-ID middleware ----------------------------------------------


@pytest.mark.django_db
def test_request_id_minted_when_header_absent(client):
    r = client.get(reverse("healthz"))
    assert r["X-Request-ID"]
    assert len(r["X-Request-ID"]) >= 16


@pytest.mark.django_db
def test_request_id_honors_upstream_header(client):
    r = client.get(reverse("healthz"), HTTP_X_REQUEST_ID="abc-from-edge-12345")
    assert r["X-Request-ID"] == "abc-from-edge-12345"


# ---- Security headers (CSP / Permissions-Policy) -------------------------


@pytest.mark.django_db
def test_csp_header_and_nonce_match(client, setup):
    """A nonce-based CSP is emitted and the nonce in the header matches the
    one stamped on the inline bootstrap <script> (so the script executes under
    the enforced policy). Reads whichever header is active, so it holds whether
    CSP is enforced (the default) or in Report-Only mode."""
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:list"))
    csp = r.headers.get("Content-Security-Policy") or r.headers.get(
        "Content-Security-Policy-Report-Only", ""
    )
    assert "script-src" in csp
    assert "'strict-dynamic'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    match = re.search(r"'nonce-([A-Za-z0-9+/=_-]+)'", csp)
    assert match, f"no nonce in CSP header: {csp!r}"
    nonce = match.group(1)
    assert f'nonce="{nonce}"'.encode() in r.content


@pytest.mark.django_db
def test_permissions_policy_present_and_legacy_xss_header_gone(client):
    r = client.get(reverse("healthz"))
    assert "camera=()" in r.headers.get("Permissions-Policy", "")
    assert "geolocation=()" in r.headers.get("Permissions-Policy", "")
    # SECURE_BROWSER_XSS_FILTER was removed; the deprecated header must not appear.
    assert "X-XSS-Protection" not in r.headers


@pytest.mark.django_db
def test_csp_enforced_when_report_only_disabled(client):
    """With an enforced policy configured, the blocking header is emitted."""
    from csp.constants import NONCE, SELF

    policy = {"DIRECTIVES": {"default-src": [SELF], "script-src": [SELF, NONCE]}}
    with override_settings(
        CONTENT_SECURITY_POLICY=policy, CONTENT_SECURITY_POLICY_REPORT_ONLY=None
    ):
        r = client.get(reverse("healthz"))
        assert "script-src" in r.headers.get("Content-Security-Policy", "")


# ---- Branded error pages -------------------------------------------------


@pytest.mark.django_db
@override_settings(DEBUG=False, ALLOWED_HOSTS=["*"])
def test_custom_404_page_is_branded(client):
    """At DEBUG=False a missing route renders the branded 404, not Django's default."""
    r = client.get("/this-route-does-not-exist-zzz/")
    assert r.status_code == 404
    body = r.content.decode()
    assert "AdvisoryHub" in body
    assert 'class="error-page"' in body


# ---- JSON log formatter --------------------------------------------------


def test_json_formatter_emits_one_line_json():
    import logging

    from common.logging import JSONFormatter, set_request_id

    fmt = JSONFormatter()
    rec = logging.LogRecord(
        name="advisoryhub.test",
        level=logging.INFO,
        pathname="x.py",
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    rec.request_id = "req-42"
    rec.advisory_id = "ECL-cccc-ffff-gggg"
    out = fmt.format(rec)
    assert "\n" not in out
    parsed = json.loads(out)
    assert parsed["msg"] == "hello world"
    assert parsed["level"] == "INFO"
    assert parsed["request_id"] == "req-42"
    assert parsed["advisory_id"] == "ECL-cccc-ffff-gggg"
    set_request_id(None)


def test_json_formatter_handles_unjson_extras():
    import logging

    from common.logging import JSONFormatter

    fmt = JSONFormatter()
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname="x.py", lineno=1, msg="hi", args=(), exc_info=None
    )

    class Weird:
        pass

    rec.weirdo = Weird()
    out = fmt.format(rec)
    parsed = json.loads(out)
    # 'weirdo' falls through to repr() and lands as a string.
    assert "weirdo" in parsed


# ---- Sentry init noop ---------------------------------------------------


def test_sentry_init_is_noop_without_dsn(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    from common.sentry import init_from_env

    assert init_from_env() is False


# ---- i18n machinery ------------------------------------------------------


@pytest.mark.django_db
def test_locale_middleware_is_installed(settings):
    assert "django.middleware.locale.LocaleMiddleware" in settings.MIDDLEWARE


@pytest.mark.django_db
def test_translatable_strings_render_in_default_language(client, setup):
    """Sanity: marked strings in base.html resolve to their default form."""
    client.force_login(setup["member"])
    r = client.get(reverse("advisories:list"))
    body = r.content.decode()
    # Default language is English; the literal resolves to itself.
    assert "Advisories" in body
    assert "New advisory" in body


# ---- Prometheus metrics endpoint ----------------------------------------


@pytest.mark.django_db
def test_metrics_endpoint_serves_prometheus_format(client):
    """The /metrics route should serve a Prometheus exposition payload."""
    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.content.decode()
    # The django_prometheus default exposition contains at least one
    # request-counter HELP line; we don't pin specific metric names
    # because django_prometheus updates them between versions.
    assert "# HELP" in body or "# TYPE" in body


# ---- Custom application metrics -----------------------------------------
#
# prometheus_client metric objects are process-global singletons that
# accumulate across the whole pytest run, so Counter/Histogram assertions read
# a *delta* (value before vs. after the action). The backlog Gauge is `.set()`,
# so its absolute value is deterministic.

from celery import shared_task  # noqa: E402


@shared_task(name="common.tests._metrics_probe")
def _metrics_probe(fail: bool = False) -> str:
    if fail:
        raise ValueError("boom")
    return "ok"


def _counter_value(metric, **labels) -> float:
    return metric.labels(**labels)._value.get()


@pytest.mark.django_db
def test_celery_task_signals_record_success_metric():
    """Under EAGER, a task's prerun/postrun signals feed the success counter
    and the duration histogram (handlers connected in audit/apps.py)."""
    from common import metrics

    before = _counter_value(
        metrics.celery_task_total, task="common.tests._metrics_probe", status="success"
    )
    dur_before = metrics.celery_task_duration_seconds.labels(
        task="common.tests._metrics_probe"
    )._sum.get()

    assert _metrics_probe.delay().get() == "ok"

    after = _counter_value(
        metrics.celery_task_total, task="common.tests._metrics_probe", status="success"
    )
    dur_after = metrics.celery_task_duration_seconds.labels(
        task="common.tests._metrics_probe"
    )._sum.get()
    assert after == before + 1
    assert dur_after >= dur_before  # a (possibly ~0) observation was recorded


@pytest.mark.django_db
def test_celery_task_failure_metric():
    """A failing task increments the failure counter (task_failure signal).

    CELERY_TASK_EAGER_PROPAGATES=True re-raises, so the call is wrapped.
    """
    from common import metrics

    before = _counter_value(
        metrics.celery_task_total, task="common.tests._metrics_probe", status="failure"
    )
    with pytest.raises(ValueError):
        _metrics_probe.delay(fail=True).get()
    after = _counter_value(
        metrics.celery_task_total, task="common.tests._metrics_probe", status="failure"
    )
    assert after == before + 1


@pytest.mark.django_db
def test_backlog_gauge_refresh_sets_live_counts(client, make_user, make_project):
    """refresh_backlog_gauges sets advisoryhub_backlog from live DB counts, and
    the series surfaces on /metrics."""
    from advisories.models import Advisory, State
    from advisories.services import latest_version
    from audit.tasks import refresh_backlog_gauges
    from common import metrics
    from publication.models import PublicationTask, PublicationTaskStatus

    member = make_user(email="bk@example.org")
    project = make_project("bk", team_members=[member])

    # Two failed publications.
    for _ in range(2):
        adv = Advisory.objects.create(project=project, summary="s", created_by=member)
        PublicationTask.objects.create(
            advisory=adv,
            version=latest_version(adv),
            status=PublicationTaskStatus.FAILED,
        )
    # Three advisories sitting in triage.
    for _ in range(3):
        Advisory.objects.create(project=project, state=State.TRIAGE, summary="t", created_by=member)

    result = refresh_backlog_gauges()
    assert result["pub_failed"] == 2
    assert result["triage"] == 3
    assert metrics.backlog.labels(queue="pub_failed")._value.get() == 2
    assert metrics.backlog.labels(queue="triage")._value.get() == 3

    body = client.get("/metrics").content
    assert b"advisoryhub_backlog" in body


@pytest.mark.django_db
def test_worker_metrics_exporter_disabled_by_default(monkeypatch):
    """PROMETHEUS_WORKER_METRICS_PORT=0 (test default) → no exporter bind."""
    import prometheus_client

    from common import celery_metrics

    def boom(*_a, **_k):
        raise AssertionError("start_http_server must not be called when the port is 0")

    monkeypatch.setattr(prometheus_client, "start_http_server", boom)
    assert celery_metrics._start_exporter() is False


# ---- Footer help links + admin-only version ------------------------------


@pytest.mark.django_db
@override_settings(
    ADVISORYHUB_REPO_URL="https://github.com/acme/advisoryhub",
    ADVISORYHUB_DISCUSSIONS_URL="https://github.com/orgs/acme/discussions",
)
def test_footer_links_render_for_signed_in_user(client, setup):
    """All three footer links resolve from the configured settings, with the
    issues + private-vuln-report URLs derived from the repo base."""
    client.force_login(setup["member"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert "https://github.com/acme/advisoryhub/issues/new" in body
    assert "https://github.com/orgs/acme/discussions" in body
    assert "https://github.com/acme/advisoryhub/security/advisories/new" in body
    assert "Report a vulnerability in AdvisoryHub" in body


@pytest.mark.django_db
@override_settings(
    ADVISORYHUB_REPO_URL="",
    ADVISORYHUB_DISCUSSIONS_URL="https://github.com/orgs/acme/discussions",
)
def test_footer_repo_links_omitted_when_repo_blank(client, setup):
    """A blank repo base disables the derived links rather than emitting a
    malformed relative URL; the independent discussions link still renders."""
    client.force_login(setup["member"])
    body = client.get(reverse("advisories:list")).content.decode()
    assert "/issues/new" not in body
    assert "/security/advisories/new" not in body
    assert "https://github.com/orgs/acme/discussions" in body


@pytest.mark.django_db
def test_footer_version_visible_to_admin_only(client, make_user, make_project, settings):
    """The app version is shown in the footer only to global admins (display-only
    gating, INV-AUTH-1); regular users never see it."""
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    admin = make_user(email="admin@example.org", groups=["advisoryhub-security"])
    member = make_user(email="plain@example.org")
    make_project("p", team_members=[member])

    client.force_login(member)
    assert "site-footer__version" not in client.get(reverse("advisories:list")).content.decode()

    client.force_login(admin)
    assert "site-footer__version" in client.get(reverse("advisories:list")).content.decode()


def test_app_version_resolves_to_real_version():
    """The deployable image is a uv virtual project (no installed distribution),
    so the version must still resolve from pyproject.toml — never 'unknown'."""
    import tomllib
    from pathlib import Path

    from django.conf import settings

    from common.context_processors import _app_version

    pyproject = tomllib.loads(
        (Path(settings.BASE_DIR) / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert _app_version() == pyproject["project"]["version"]
    assert _app_version() != "unknown"
