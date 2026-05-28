"""Thin client over the Eclipse Foundation PMI API.

The PMI API (https://projects.eclipse.org/api/projects/<slug>) is the
source-of-truth for project↔repo mapping. AdvisoryHub mirrors the result
locally (see ``ghsa.services.sync_project_repos_from_pmi``) so GHSA sync
runs don't depend on PMI uptime.

This module only knows how to *fetch and normalise*; persistence and
audit live in ``services.py``.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from urllib.parse import urlparse

import requests
from django.conf import settings

from audit.services import redact_secrets

_USER_AGENT = "AdvisoryHub/PMI-mirror"
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 30
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_BASE = 1.5


class PmiApiError(Exception):
    """Raised for any non-2xx PMI response or transport failure."""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(redact_secrets(message) if isinstance(message, str) else str(message))
        self.status = status


def fetch_project_repos(project_slug: str) -> list[tuple[str, str]]:
    """Return ``[(owner, name), …]`` of GitHub repos PMI knows for the project.

    PMI publishes a mixed bag of source-repo URLs (GitHub, GitLab,
    Gerrit, …). We filter to ``github.com`` hosts and parse ``owner/name``
    from the path. Repo paths with more than two segments (e.g. forks,
    subdirectories) are skipped — the GitHub API only addresses repos by
    their canonical ``owner/name``.
    """
    if not project_slug:
        raise PmiApiError("project_slug is required")
    base = settings.PMI_API_BASE_URL.rstrip("/")
    url = f"{base}/projects/{project_slug}"
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    token = getattr(settings, "PMI_API_TOKEN", "") or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_exc: Exception | None = None
    resp: requests.Response | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF_BASE**attempt)
                continue
            raise PmiApiError(f"PMI request failed: {exc}") from exc
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF_BASE**attempt)
                continue
        break
    if resp is None:
        raise PmiApiError(f"PMI request failed: {last_exc}")
    if resp.status_code == 404:
        raise PmiApiError(f"PMI project not found: {project_slug}", status=404)
    if resp.status_code >= 400:
        raise PmiApiError(
            f"PMI returned {resp.status_code}: {resp.text[:500]}", status=resp.status_code
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        raise PmiApiError(f"PMI returned non-JSON: {exc}") from exc

    # PMI sometimes returns a list with one entry; sometimes a single
    # object. Normalise.
    if isinstance(payload, list):
        payload = payload[0] if payload else {}

    return list(_extract_github_repos(payload))


def _extract_github_repos(project: dict) -> Iterable[tuple[str, str]]:
    """Walk PMI's repo lists and yield distinct ``(owner, name)`` pairs.

    PMI's schema has shifted a few times; rather than baking in a single
    field name we tolerate the union of shapes that have shown up:

    * ``github_repos: [{url: "https://github.com/owner/name"}, …]``
    * ``github: {repos: ["https://github.com/owner/name", …]}``
    * ``source_repo: [{url: "https://github.com/owner/name", type: "github"}, …]``

    Anything else (or non-GitHub hosts) is ignored.
    """
    seen: set[tuple[str, str]] = set()

    candidate_urls: list[str] = []
    for field in ("github_repos", "github_repo", "source_repo", "source_repos"):
        items = project.get(field) or []
        if isinstance(items, dict):
            items = [items]
        for entry in items:
            if isinstance(entry, str):
                candidate_urls.append(entry)
            elif isinstance(entry, dict):
                url = entry.get("url") or entry.get("html_url") or entry.get("clone_url")
                if url:
                    candidate_urls.append(url)
    nested = project.get("github") or {}
    for url in nested.get("repos") or []:
        if isinstance(url, str):
            candidate_urls.append(url)
        elif isinstance(url, dict):
            u = url.get("url") or url.get("html_url")
            if u:
                candidate_urls.append(u)

    for raw in candidate_urls:
        pair = _parse_github_repo_url(raw)
        if pair and pair not in seen:
            seen.add(pair)
            yield pair


def _parse_github_repo_url(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.netloc or "").lower()
    if host not in {"github.com", "www.github.com"}:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1]
    # Strip a trailing .git suffix that some clone URLs carry.
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        return None
    return owner, name
