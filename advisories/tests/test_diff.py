from __future__ import annotations

import pytest
from django.urls import reverse

from advisories.diff import live_vs_version, version_diff
from advisories.models import Advisory
from advisories.services import record_advisory_version


@pytest.fixture
def setup(make_user, make_project, settings):
    settings.OIDC_ADMIN_GROUP = "advisoryhub-security"
    member = make_user(email="m@example.org")
    project = make_project("p", team_members=[member])
    advisory = Advisory.objects.create(
        project=project,
        summary="initial",
        details="initial details",
        aliases=["CVE-2026-1111"],
        cwe_ids=["CWE-79"],
        references=[{"type": "ADVISORY", "url": "https://x"}],
        affected=[],
        created_by=member,
    )
    # v1 is seeded by the signal at Advisory creation time.
    v1 = advisory.versions.get(version=1)
    return {"member": member, "advisory": advisory, "version": v1}


@pytest.mark.django_db
def test_no_change_no_diff(setup):
    diff = live_vs_version(setup["advisory"], setup["version"])
    assert diff == []


@pytest.mark.django_db
def test_scalar_change_appears(setup):
    setup["advisory"].summary = "updated"
    setup["advisory"].save(update_fields=["summary"])
    diff = live_vs_version(setup["advisory"], setup["version"])
    rows = {r["field"]: r for r in diff}
    assert "summary" in rows
    assert rows["summary"]["before"] == "initial"
    assert rows["summary"]["after"] == "updated"


@pytest.mark.django_db
def test_list_field_added_and_removed(setup):
    setup["advisory"].aliases = ["CVE-2026-2222", "GHSA-aaaa-bbbb-cccc"]
    setup["advisory"].save(update_fields=["aliases"])
    diff = live_vs_version(setup["advisory"], setup["version"])
    rows = {r["field"]: r for r in diff}
    aliases = rows["aliases"]
    assert "CVE-2026-1111" in aliases["removed"]
    assert "CVE-2026-2222" in aliases["added"]
    assert "GHSA-aaaa-bbbb-cccc" in aliases["added"]


@pytest.mark.django_db
def test_list_reordering_is_not_a_diff(setup):
    """Order-independent equality: rearranging a list shouldn't count."""
    setup["advisory"].cwe_ids = ["CWE-79"]
    setup["advisory"].save(update_fields=["cwe_ids"])
    diff = live_vs_version(setup["advisory"], setup["version"])
    fields = {r["field"] for r in diff}
    assert "cwe_ids" not in fields


@pytest.mark.django_db
def test_assigned_cve_change_appears_in_diff(setup):
    """assigned_cve_id is set by the CVE workflow, not by editing aliases —
    re-publish diffs must still surface the change."""
    setup["advisory"].assigned_cve_id = "CVE-2026-0001"
    setup["advisory"].save(update_fields=["assigned_cve_id"])
    diff = live_vs_version(setup["advisory"], setup["version"])
    rows = {r["field"]: r for r in diff}
    assert "assigned_cve_id" in rows
    assert rows["assigned_cve_id"]["before"] == ""
    assert rows["assigned_cve_id"]["after"] == "CVE-2026-0001"


@pytest.mark.django_db
def test_version_against_version(setup):
    """Two distinct versions can be diffed against each other."""
    setup["advisory"].summary = "updated again"
    setup["advisory"].save(update_fields=["summary"])
    v2 = record_advisory_version(setup["advisory"], editor=setup["member"])
    diff = version_diff(setup["version"], v2)
    rows = {r["field"]: r for r in diff}
    assert rows["summary"]["before"] == "initial"
    assert rows["summary"]["after"] == "updated again"


# ---- view ---------------------------------------------------------------


@pytest.mark.django_db
def test_diff_view_403_for_outsider(client, setup, make_user):
    outsider = make_user(email="o@example.org")
    client.force_login(outsider)
    response = client.get(
        reverse(
            "advisories:version_diff",
            args=[setup["advisory"].advisory_id, setup["version"].pk],
        )
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_diff_view_404_for_other_advisorys_version(client, setup, make_project):
    """A version id that belongs to a *different* advisory than the URL
    one must return 404, even when the user has access to both."""
    other_project = make_project("other", team_members=[setup["member"]])
    other_adv = Advisory.objects.create(project=other_project, summary="other")
    client.force_login(setup["member"])
    response = client.get(
        reverse(
            "advisories:version_diff",
            args=[other_adv.advisory_id, setup["version"].pk],
        )
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_diff_view_renders_drawer_for_member(client, setup):
    setup["advisory"].summary = "moved on"
    setup["advisory"].save(update_fields=["summary"])
    client.force_login(setup["member"])
    response = client.get(
        reverse(
            "advisories:version_diff",
            args=[setup["advisory"].advisory_id, setup["version"].pk],
        ),
        HTTP_HX_REQUEST="true",
    )
    assert response.status_code == 200
    body = response.content.decode()
    assert 'id="version-diff-drawer"' in body
    assert "initial" in body
    assert "moved on" in body


@pytest.mark.django_db
def test_diff_view_fragment_omits_dialog_shell(client, setup):
    """The ?fragment=1 response is body-only (no <dialog>), safe to swap
    into #version-diff-body without nesting a second drawer."""
    setup["advisory"].summary = "moved on"
    setup["advisory"].save(update_fields=["summary"])
    client.force_login(setup["member"])
    response = client.get(
        reverse(
            "advisories:version_diff",
            args=[setup["advisory"].advisory_id, setup["version"].pk],
        )
        + "?fragment=1",
        HTTP_HX_REQUEST="true",
    )
    assert response.status_code == 200
    body = response.content.decode()
    assert "<dialog" not in body
    assert 'class="diff"' in body
    assert "moved on" in body


@pytest.mark.django_db
def test_diff_view_non_htmx_redirects_to_detail(client, setup):
    """A direct (non-HTMX) hit has no standalone page — it redirects back."""
    client.force_login(setup["member"])
    response = client.get(
        reverse(
            "advisories:version_diff",
            args=[setup["advisory"].advisory_id, setup["version"].pk],
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("advisories:detail", args=[setup["advisory"].advisory_id])


@pytest.mark.django_db
def test_diff_view_against_other_version(client, setup):
    setup["advisory"].summary = "v2"
    setup["advisory"].save(update_fields=["summary"])
    v2 = record_advisory_version(setup["advisory"], editor=setup["member"])
    client.force_login(setup["member"])
    response = client.get(
        reverse(
            "advisories:version_diff",
            args=[setup["advisory"].advisory_id, v2.pk],
        )
        + f"?against={setup['version'].pk}&fragment=1",
        HTTP_HX_REQUEST="true",
    )
    assert response.status_code == 200
    body = response.content.decode()
    assert "v2" in body
    assert "initial" in body
