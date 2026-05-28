"""PMI client tests — parses mocked responses, never makes real calls."""

from __future__ import annotations

import pytest
import responses

from ghsa.pmi import PmiApiError, fetch_project_repos


@responses.activate
def test_fetch_project_repos_parses_github_repos_field(settings):
    settings.PMI_API_BASE_URL = "https://projects.eclipse.org/api"
    responses.add(
        responses.GET,
        "https://projects.eclipse.org/api/projects/technology.jetty",
        json={
            "github_repos": [
                {"url": "https://github.com/eclipse/jetty.project"},
                {"url": "https://github.com/eclipse/jetty.docs.git"},
                {"url": "https://gitlab.com/some/other-repo"},
            ]
        },
        status=200,
    )
    repos = fetch_project_repos("technology.jetty")
    assert ("eclipse", "jetty.project") in repos
    assert ("eclipse", "jetty.docs") in repos
    # GitLab is filtered out.
    assert all(host == "eclipse" for host, _ in repos)


@responses.activate
def test_fetch_project_repos_handles_list_response(settings):
    settings.PMI_API_BASE_URL = "https://projects.eclipse.org/api"
    responses.add(
        responses.GET,
        "https://projects.eclipse.org/api/projects/foo",
        json=[{"github_repos": [{"url": "https://github.com/eclipse/foo"}]}],
        status=200,
    )
    assert fetch_project_repos("foo") == [("eclipse", "foo")]


@responses.activate
def test_fetch_project_repos_raises_on_404(settings):
    settings.PMI_API_BASE_URL = "https://projects.eclipse.org/api"
    responses.add(
        responses.GET,
        "https://projects.eclipse.org/api/projects/nope",
        json={"message": "not found"},
        status=404,
    )
    with pytest.raises(PmiApiError):
        fetch_project_repos("nope")
