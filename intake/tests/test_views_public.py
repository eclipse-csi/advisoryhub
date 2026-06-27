"""Tests for the public intake POST endpoint at ``/report/``."""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.urls import reverse

from advisories.models import Advisory, AdvisoryIntakeMetadata, State
from intake.models import HoneypotSubmission
from projects.models import Project


@pytest.fixture
def unsorted_project(db, admin_group):
    """The ``unsorted`` sentinel project. Created by the projects.0003 migration
    on a fresh DB; this fixture is idempotent for unit tests that wipe the DB
    via the migration teardown."""
    project, _ = Project.objects.get_or_create(
        slug="unsorted",
        defaults={
            "name": "Unsorted reports",
            "security_team": admin_group,
            "is_mature_publisher": False,
        },
    )
    return project


def _empty_formset_management_data() -> dict:
    """Management-form payload for all six OSV formsets, zero rows each.

    The browser sends these as hidden inputs rendered by Django's
    ``{{ formset.management_form }}`` tag; tests posting directly need to
    mirror them.
    """
    data: dict[str, str] = {}
    for prefix in ("aliases", "cwe_ids", "references", "severity", "credits", "affected"):
        data[f"{prefix}-TOTAL_FORMS"] = "0"
        data[f"{prefix}-INITIAL_FORMS"] = "0"
        data[f"{prefix}-MIN_NUM_FORMS"] = "0"
        data[f"{prefix}-MAX_NUM_FORMS"] = "1000"
    return data


def _post(client, **overrides):
    data = {
        "project_slug": "__unsorted__",
        "summary": "Possible buffer overrun",
        "details": "I noticed an unusual response when posting an overlong header.",
        "reporter_display_name": "",
        "website": "",
    }
    data.update(_empty_formset_management_data())
    data.update(overrides)
    return client.post(reverse("intake:report"), data=data, follow=False)


def test_report_form_renders_ecosystem_live_validation(db, client, unsorted_project):
    resp = client.get(reverse("intake:report"))
    assert resp.status_code == 200
    body = resp.content.decode()
    # The shared affected-package partial wires the live ecosystem validation:
    # the controller, the input hook, the message slot, and the datalist it reads.
    assert "advisoryhub-validate.js" in body
    assert 'data-validate="ecosystem"' in body
    assert "data-validate-error" in body
    assert '<datalist id="osv-ecosystems">' in body


def test_report_form_wires_save_feedback(db, client, unsorted_project):
    """The public report form shows an "Unsaved changes" marker and guards a
    double-submit (data-submit-once), but — per the forms guide and to avoid a
    reporter abandoning the form — never disables "Submit report" to gate state
    (no server-side ``disabled`` attribute, so it works even without JS)."""
    body = client.get(reverse("intake:report")).content.decode()
    assert "data-unsaved-indicator" in body
    assert "Unsaved changes" in body
    assert "data-submit-once" in body
    assert "advisoryhub-form-dirty.js" in body
    assert '<button type="submit">Submit report</button>' in body


def test_report_form_project_is_smart_select(db, client, unsorted_project, make_project):
    """The project picker is a smart <select> combobox (advisoryhub-select.js),
    matching the authoring forms — constrained to known projects + the
    "I don't know" (__unsorted__) option, so there's no free-text slug to
    client-validate anymore. Each project option also carries its slug on
    data-combobox-detail (shown as a second line and matched while typing)."""
    make_project("zlib")  # slug "zlib"
    body = client.get(reverse("intake:report")).content.decode()
    assert 'data-validate="project"' not in body
    assert 'name="project_slug"' in body
    assert "data-combobox" in body
    assert 'value="__unsorted__"' in body
    assert 'data-combobox-detail="zlib"' in body


def test_anonymous_submission_creates_triage_advisory(db, client, unsorted_project):
    resp = _post(client, reporter_display_name="Anon Researcher")
    assert resp.status_code == 302
    assert reverse("intake:thank_you") in resp.url

    adv = Advisory.objects.get(state=State.TRIAGE)
    assert adv.project == unsorted_project
    assert adv.created_by is None  # anonymous
    assert adv.summary == "Possible buffer overrun"
    intake = AdvisoryIntakeMetadata.objects.get(advisory=adv)
    assert intake.reporter_user is None
    assert intake.reporter_display_name == "Anon Researcher"
    assert intake.needs_admin_routing  # unsorted → admin routing
    # No advisory access grants — anonymous can't be retroactively granted access.
    assert adv.access_grants.count() == 0
    # No honeypot row.
    assert not HoneypotSubmission.objects.exists()


def test_authenticated_submission_grants_viewer(
    db, client, make_user, make_project, unsorted_project
):
    user = make_user(email="alice@example.org", display_name="Alice")
    project = make_project("zlib")
    client.force_login(user)

    resp = _post(client, project_slug=project.slug, summary="Heap overflow in zlib")
    assert resp.status_code == 302

    adv = Advisory.objects.get(state=State.TRIAGE)
    assert adv.project == project
    assert adv.created_by == user
    intake = adv.intake
    assert intake.reporter_user == user
    assert not intake.needs_admin_routing  # not unsorted

    # Authenticated reporter is auto-granted viewer access.
    grants = list(adv.access_grants.all())
    assert len(grants) == 1
    assert grants[0].principal_type == "user"
    assert grants[0].principal_id == user.pk
    assert grants[0].permission == "viewer"


def test_form_has_no_email_or_pgp_field(db):
    """Belt-and-braces: the form class itself must not declare these fields.

    Any client that crafts a ``reporter_email=…`` or ``reporter_pgp_key=…``
    POST body posts an unknown form key, which Django silently drops — but
    asserting against the class catches a future regression where someone
    re-adds the field.
    """
    from intake.forms import VulnerabilityReportForm

    form = VulnerabilityReportForm()
    assert "reporter_email" not in form.fields
    assert "reporter_pgp_key" not in form.fields
    # The replacement field for crediting:
    assert "reporter_display_name" in form.fields


def test_crafted_email_in_post_does_not_reach_model(db, client, unsorted_project):
    """Even when a malicious client POSTs a ``reporter_email`` value, no
    advisory or sidecar field is populated from it (the field doesn't exist
    on the form, so Django drops it).
    """
    resp = _post(client, reporter_email="attacker@example.org")
    assert resp.status_code == 302
    adv = Advisory.objects.get(state=State.TRIAGE)
    intake = adv.intake
    # No path for "attacker@example.org" to land anywhere.
    assert intake.reporter_user is None
    assert intake.reporter_display_name == ""
    # No grant materialized.
    assert adv.access_grants.count() == 0


def test_honeypot_submission_creates_honeypot_row_no_advisory(db, client, unsorted_project):
    resp = _post(client, website="https://buy-cheap-pills.example")
    # Still success (timing indistinguishable from a real submission).
    assert resp.status_code == 302
    assert reverse("intake:thank_you") in resp.url
    # No advisory was created.
    assert not Advisory.objects.filter(state=State.TRIAGE).exists()
    # The honeypot row is captured.
    assert HoneypotSubmission.objects.count() == 1
    row = HoneypotSubmission.objects.get()
    assert row.honeypot_field_value == "https://buy-cheap-pills.example"


def test_unknown_project_slug_returns_form_error(db, client, unsorted_project):
    resp = _post(client, project_slug="totally.nonexistent")
    assert resp.status_code == 400
    # Form renders with the error; no rows created.
    assert not Advisory.objects.exists()


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True, RATELIMIT_INTAKE_ANON="1/h", ALTCHA_HMAC_KEY="")
def test_anon_intake_rate_limit_blocks_advisory_creation(client, unsorted_project, make_project):
    """Regression for report 003 / INV-RATELIMIT-1: on the unauthenticated
    ``/report/`` surface, a throttled request must report 429 *and* create no
    ``Advisory(state=triage)`` — the 429 path must not run ``_do_submit``.
    Before the fix all three POSTs created a row despite the 429s."""
    target = make_project(name="technology.demo")
    before = Advisory.objects.filter(state=State.TRIAGE).count()

    statuses = [_post(client, project_slug=target.slug).status_code for _ in range(3)]

    created = Advisory.objects.filter(state=State.TRIAGE).count() - before
    assert statuses == [302, 429, 429]
    assert created == 1  # the 429 path created nothing


def test_unsorted_sentinel_slug_is_not_pickable_directly(db, client, unsorted_project):
    """Submitting with ``project_slug=unsorted`` directly is rejected.
    The form only routes to the sentinel via the explicit ``__unsorted__``
    sentinel value.
    """
    resp = _post(client, project_slug="unsorted")
    assert resp.status_code == 400
    assert not Advisory.objects.exists()


# ---------------------------------------------------------------------------
# Advanced fields (structured OSV payload from the disclosure)
# ---------------------------------------------------------------------------


def test_anonymous_submission_with_advanced_fields_populates_advisory(
    db, client, unsorted_project, make_project
):
    """Reporter fills in CWE / severity / one affected package — those land
    structurally on the resulting Advisory(state=TRIAGE) JSON fields.
    """
    project = make_project("jetty")
    overrides = {
        "project_slug": project.slug,
        # 1 CWE row
        "cwe_ids-TOTAL_FORMS": "1",
        "cwe_ids-0-value": "CWE-79",
        # 1 severity row (CVSS_V3 vector)
        "severity-TOTAL_FORMS": "1",
        "severity-0-type": "CVSS_V3",
        "severity-0-score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity-0-score_ubuntu": "",
        # 1 affected package + 1 event
        "affected-TOTAL_FORMS": "1",
        "affected-0-package_name": "org.eclipse.jetty:jetty-server",
        "affected-0-package_ecosystem": "Maven",
        "affected-0-package_purl": "",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        "affected-0-events-TOTAL_FORMS": "1",
        "affected-0-events-INITIAL_FORMS": "0",
        "affected-0-events-MIN_NUM_FORMS": "0",
        "affected-0-events-MAX_NUM_FORMS": "1000",
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "12.0.0",
    }
    resp = _post(client, **overrides)
    assert resp.status_code == 302, resp.content[:500]
    adv = Advisory.objects.get(state=State.TRIAGE)
    assert adv.cwe_ids == ["CWE-79"]
    assert adv.severity == [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ]
    assert adv.affected == [
        {
            "package": {
                "name": "org.eclipse.jetty:jetty-server",
                "ecosystem": "Maven",
            },
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "12.0.0"}]}],
        }
    ]


def test_honeypot_skips_advanced_field_validation(db, client, unsorted_project):
    """A bot that fills the honeypot field AND posts malformed advanced
    payload still gets a clean redirect — we never validate the advanced
    section on the honeypot path, so the broken data is silently dropped.
    """
    overrides = {
        "website": "https://buy-cheap-pills.example",  # honeypot trip
        # Malformed CWE — would normally re-render with errors:
        "cwe_ids-TOTAL_FORMS": "1",
        "cwe_ids-0-value": "definitely-not-a-cwe",
    }
    resp = _post(client, **overrides)
    assert resp.status_code == 302
    assert reverse("intake:thank_you") in resp.url
    # No advisory created; one honeypot row captured.
    assert not Advisory.objects.exists()
    assert HoneypotSubmission.objects.count() == 1


def test_invalid_cwe_in_advanced_re_renders_with_open_details(db, client, unsorted_project):
    overrides = {
        "cwe_ids-TOTAL_FORMS": "1",
        "cwe_ids-0-value": "CWE-NOTREAL",
    }
    resp = _post(client, **overrides)
    assert resp.status_code == 400
    assert resp.context["advanced_open"] is True
    # No advisory created.
    assert not Advisory.objects.exists()
    # The form re-renders with the bad CWE value still bound so the user
    # can correct it.
    body = resp.content.decode()
    assert "CWE-NOTREAL" in body or "not a recognised CWE" in body.lower()


def test_advanced_range_without_introduced_event_re_renders(db, client, unsorted_project):
    """A reporter posting a range with only a ``fixed`` event must see the
    OSV constraint surfaced inline — no advisory is created."""
    overrides = {
        "affected-TOTAL_FORMS": "1",
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        "affected-0-events-TOTAL_FORMS": "1",
        "affected-0-events-INITIAL_FORMS": "0",
        "affected-0-events-MIN_NUM_FORMS": "0",
        "affected-0-events-MAX_NUM_FORMS": "1000",
        "affected-0-events-0-kind": "fixed",
        "affected-0-events-0-value": "1.2.0",
    }
    resp = _post(client, **overrides)
    assert resp.status_code == 400
    assert resp.context["advanced_open"] is True
    assert not Advisory.objects.exists()
    body = resp.content.decode()
    assert "Introduced" in body


def test_advanced_range_with_fixed_and_last_affected_re_renders(db, client, unsorted_project):
    overrides = {
        "affected-TOTAL_FORMS": "1",
        "affected-0-package_name": "lib",
        "affected-0-package_ecosystem": "npm",
        "affected-0-range_type": "ECOSYSTEM",
        "affected-0-versions": "",
        "affected-0-events-TOTAL_FORMS": "3",
        "affected-0-events-INITIAL_FORMS": "0",
        "affected-0-events-MIN_NUM_FORMS": "0",
        "affected-0-events-MAX_NUM_FORMS": "1000",
        "affected-0-events-0-kind": "introduced",
        "affected-0-events-0-value": "1.0.0",
        "affected-0-events-1-kind": "fixed",
        "affected-0-events-1-value": "1.2.0",
        "affected-0-events-2-kind": "last_affected",
        "affected-0-events-2-value": "1.5.0",
    }
    resp = _post(client, **overrides)
    assert resp.status_code == 400
    assert resp.context["advanced_open"] is True
    assert not Advisory.objects.exists()
    body = resp.content.decode()
    assert "mutually exclusive" in body


# ---------------------------------------------------------------------------
# ALTCHA proof-of-work captcha (optional — engaged only when ALTCHA_HMAC_KEY
# is set; the honeypot above stays the always-on gate). Self-hosted, so a valid
# solution can be minted server-side and the whole flow runs without a browser.
# ---------------------------------------------------------------------------

ALTCHA_TEST_KEY = "altcha-unit-test-key"


def _altcha_solution(hmac_key: str = ALTCHA_TEST_KEY) -> str:
    """Mint a valid ALTCHA solution payload server-side (no browser needed).

    A small ``max_number`` keeps ``solve_challenge`` near-instant; the server
    verifier recomputes the hash from (salt, number) so the bound never affects
    validity. Each call uses a fresh random salt, so payloads don't collide
    across tests in the shared replay-protection cache.
    """
    import altcha

    challenge = altcha.create_challenge(altcha.ChallengeOptions(hmac_key=hmac_key, max_number=500))
    solution = altcha.solve_challenge(challenge)
    assert solution is not None
    payload = altcha.Payload(
        algorithm=challenge.algorithm,
        challenge=challenge.challenge,
        number=solution.number,
        salt=challenge.salt,
        signature=challenge.signature,
    )
    return payload.to_base64()


def test_altcha_field_absent_by_default(db):
    """With no ALTCHA_HMAC_KEY (the dev/test default) neither anonymous nor
    authenticated forms carry a captcha field."""
    from intake.forms import VulnerabilityReportForm

    assert "altcha" not in VulnerabilityReportForm(authenticated=False).fields
    assert "altcha" not in VulnerabilityReportForm(authenticated=True).fields


@override_settings(ALTCHA_HMAC_KEY=ALTCHA_TEST_KEY)
def test_altcha_widget_rendered_when_configured(db, client, unsorted_project):
    """When configured, the anonymous form renders the self-hosted widget and
    pulls the vendored, same-origin assets — no third-party/CDN reference."""
    body = client.get(reverse("intake:report")).content.decode()
    assert "<altcha-widget" in body
    assert "altcha/altcha.external.min.js" in body
    assert "altcha/altcha.css" in body
    assert "advisoryhub-altcha.js" in body
    assert "data-altcha-worker" in body
    assert "hcaptcha" not in body.lower()


@override_settings(ALTCHA_HMAC_KEY=ALTCHA_TEST_KEY)
def test_altcha_missing_solution_rejected(db, client, unsorted_project):
    """No solved captcha → form invalid: no advisory, no honeypot row."""
    resp = _post(client)  # no altcha payload
    assert resp.status_code == 400
    assert not Advisory.objects.exists()
    assert not HoneypotSubmission.objects.exists()


@override_settings(ALTCHA_HMAC_KEY=ALTCHA_TEST_KEY)
def test_altcha_invalid_solution_rejected(db, client, unsorted_project):
    resp = _post(client, altcha="not-a-valid-payload")
    assert resp.status_code == 400
    assert not Advisory.objects.exists()


@override_settings(ALTCHA_HMAC_KEY=ALTCHA_TEST_KEY)
def test_altcha_valid_solution_accepted(db, client, unsorted_project):
    resp = _post(client, altcha=_altcha_solution())
    assert resp.status_code == 302, resp.content[:500]
    assert reverse("intake:thank_you") in resp.url
    assert Advisory.objects.filter(state=State.TRIAGE).count() == 1


@override_settings(ALTCHA_HMAC_KEY=ALTCHA_TEST_KEY)
def test_altcha_solution_is_single_use(db, client, unsorted_project):
    """Replay protection: a solved challenge can't be submitted twice."""
    payload = _altcha_solution()
    first = _post(client, altcha=payload)
    assert first.status_code == 302
    second = _post(client, altcha=payload)
    assert second.status_code == 400
    assert Advisory.objects.filter(state=State.TRIAGE).count() == 1


@override_settings(ALTCHA_HMAC_KEY=ALTCHA_TEST_KEY)
def test_altcha_does_not_break_honeypot(db, client, unsorted_project):
    """Honeypot still wins (INV-INTAKE-1): a solved captcha + a tripped honeypot
    records a HoneypotSubmission and never an Advisory."""
    resp = _post(
        client,
        altcha=_altcha_solution(),
        website="https://buy-cheap-pills.example",
    )
    assert resp.status_code == 302
    assert not Advisory.objects.exists()
    assert HoneypotSubmission.objects.count() == 1
