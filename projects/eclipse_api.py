"""Thin client over the *authenticated* Eclipse Foundation APIs.

Two endpoints back the security-team roster sync:

* **Project membership** — ``{PMI_API_BASE_URL}/projects/<slug>`` lists the
  project's people (committers, project leads, contributors / individual
  members). This is the same PMI endpoint ``ghsa.pmi`` reads for repos, but
  here we read the *people* and call it authenticated so private fields are
  available.
* **Account email** — ``{ECLIPSE_API_BASE_URL}/account/profile/<username>``
  resolves a member's email, which the public PMI feed hides. This is why the
  sync needs authentication at all.

Both are authenticated with an **OAuth2 client-credentials** bearer token
minted against ``ECLIPSE_API_TOKEN_URL`` and cached in ``django.core.cache``
until shortly before it expires. The ``client_id`` / ``client_secret`` and the
bearer token are never logged; every error message is run through
``audit.services.redact_secrets`` before it can surface.

This module only knows how to *fetch and normalise*; persistence, shadow-user
provisioning and audit live in ``projects.services``.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

import requests
from django.conf import settings
from django.core.cache import cache

from audit.services import redact_secrets

_USER_AGENT = "AdvisoryHub/security-roster"
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 30
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_BASE = 1.5

# Cache keys + TTLs (seconds). The token TTL is derived from the OAuth
# ``expires_in`` minus a safety margin; the email cache keeps per-user lookups
# cheap across a daily beat run so a stable roster isn't re-fetched member by
# member every time.
_TOKEN_CACHE_KEY = "eclipse_api:access_token"
_TOKEN_EXPIRY_MARGIN = 60
_EMAIL_CACHE_PREFIX = "eclipse_api:email:"
_EMAIL_CACHE_TTL = 24 * 60 * 60


class EclipseApiError(Exception):
    """Raised for any non-2xx Eclipse API response or transport failure.

    The message is redacted on construction so a leaked token in a URL or
    error body never propagates into logs / audit / the project's
    ``last_roster_sync_error`` banner.
    """

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(redact_secrets(message) if isinstance(message, str) else str(message))
        self.status = status


# ---------------------------------------------------------------------------
# OAuth2 client-credentials token
# ---------------------------------------------------------------------------


def _get_access_token(*, force_refresh: bool = False) -> str:
    """Return a cached client-credentials bearer token, minting one if needed.

    Caches the token in ``django.core.cache`` for ``expires_in`` minus a
    safety margin. ``force_refresh`` skips the cache (used to retry once after
    a 401, in case the cached token was revoked early).
    """
    if not force_refresh:
        cached = cache.get(_TOKEN_CACHE_KEY)
        if cached:
            return cached

    token_url = getattr(settings, "ECLIPSE_API_TOKEN_URL", "") or ""
    client_id = getattr(settings, "ECLIPSE_API_CLIENT_ID", "") or ""
    client_secret = getattr(settings, "ECLIPSE_API_CLIENT_SECRET", "") or ""
    if not (token_url and client_id and client_secret):
        raise EclipseApiError(
            "Eclipse API credentials are not configured "
            "(ECLIPSE_API_TOKEN_URL / ECLIPSE_API_CLIENT_ID / ECLIPSE_API_CLIENT_SECRET)."
        )

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    scope = getattr(settings, "ECLIPSE_API_SCOPE", "") or ""
    if scope:
        data["scope"] = scope

    try:
        resp = requests.post(
            token_url,
            data=data,
            headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
        )
    except requests.RequestException as exc:
        raise EclipseApiError(f"Eclipse token request failed: {exc}") from exc
    if resp.status_code >= 400:
        raise EclipseApiError(
            f"Eclipse token endpoint returned {resp.status_code}", status=resp.status_code
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise EclipseApiError(f"Eclipse token endpoint returned non-JSON: {exc}") from exc

    token = payload.get("access_token")
    if not token:
        raise EclipseApiError("Eclipse token response had no access_token")
    expires_in = int(payload.get("expires_in") or 3600)
    ttl = max(expires_in - _TOKEN_EXPIRY_MARGIN, 1)
    cache.set(_TOKEN_CACHE_KEY, token, ttl)
    return token


def _authed_get(url: str) -> requests.Response:
    """GET ``url`` with the client-credentials bearer, refreshing once on 401.

    Retries transport errors / 429 / 5xx with exponential backoff (mirroring
    ``ghsa.pmi``). A 401 triggers a single token refresh + retry in case the
    cached token was revoked before its advertised expiry.
    """
    last_exc: Exception | None = None
    resp: requests.Response | None = None
    refreshed = False
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        token = _get_access_token(force_refresh=refreshed)
        headers = {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
            "Authorization": f"Bearer {token}",
        }
        try:
            resp = requests.get(url, headers=headers, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF_BASE**attempt)
                continue
            raise EclipseApiError(f"Eclipse API request failed: {exc}") from exc
        if resp.status_code == 401 and not refreshed:
            # Token may have been revoked early — mint a fresh one and retry.
            refreshed = True
            continue
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF_BASE**attempt)
                continue
        break
    if resp is None:
        raise EclipseApiError(f"Eclipse API request failed: {last_exc}")
    return resp


# ---------------------------------------------------------------------------
# Project membership
# ---------------------------------------------------------------------------


def fetch_project_members(project_slug: str) -> list[dict]:
    """Return ``[{"username": str, "name": str}, …]`` for a project's team.

    The security team is the union of the project's *individual members*,
    *committers* and *project leads* (per the Eclipse PMI model). PMI's schema
    has drifted, so we tolerate the union of shapes that have shown up: each
    role list holds either bare username strings or objects carrying a
    ``username`` (sometimes ``id`` / ``url``) and a display ``fullname`` /
    ``name``. Duplicate usernames across roles collapse to one entry.
    """
    if not project_slug:
        raise EclipseApiError("project_slug is required")
    base = settings.PMI_API_BASE_URL.rstrip("/")
    resp = _authed_get(f"{base}/projects/{project_slug}")
    if resp.status_code == 404:
        raise EclipseApiError(f"PMI project not found: {project_slug}", status=404)
    if resp.status_code >= 400:
        raise EclipseApiError(
            f"PMI returned {resp.status_code} for {project_slug}", status=resp.status_code
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise EclipseApiError(f"PMI returned non-JSON: {exc}") from exc
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    return list(_extract_members(payload))


# Role lists on the PMI project object that together form the security team.
_MEMBER_ROLE_FIELDS = (
    "individual_members",
    "committers",
    "project_leads",
    "leads",
)


def _extract_members(project: dict) -> Iterable[dict]:
    """Yield distinct ``{"username", "name"}`` dicts from a PMI project object."""
    seen: set[str] = set()
    for field in _MEMBER_ROLE_FIELDS:
        items = project.get(field) or []
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, (list, tuple)):
            continue
        for entry in items:
            username = name = ""
            if isinstance(entry, str):
                username = entry.strip()
            elif isinstance(entry, dict):
                username = str(
                    entry.get("username") or entry.get("id") or entry.get("uid") or ""
                ).strip()
                name = str(entry.get("fullname") or entry.get("name") or "").strip()
            if not username or username in seen:
                continue
            seen.add(username)
            yield {"username": username, "name": name}


# ---------------------------------------------------------------------------
# Account email resolution
# ---------------------------------------------------------------------------


def fetch_account_email(username: str) -> str | None:
    """Resolve a member's email via the authenticated account-profile API.

    Returns the email, or ``None`` when the profile has no email / the account
    is unknown (404). Results are cached by username so a stable roster isn't
    re-fetched member by member on every sync run. A ``404`` is a normal
    "no such public account" outcome and is **not** raised — the caller simply
    can't provision that member yet.
    """
    if not username:
        return None
    cache_key = f"{_EMAIL_CACHE_PREFIX}{username}"
    cached = cache.get(cache_key)
    if cached is not None:
        # Empty string is a cached "no email" — distinct from a cache miss.
        return cached or None

    base = getattr(settings, "ECLIPSE_API_BASE_URL", "").rstrip("/")
    if not base:
        raise EclipseApiError("ECLIPSE_API_BASE_URL is not configured")
    resp = _authed_get(f"{base}/account/profile/{username}")
    if resp.status_code == 404:
        cache.set(cache_key, "", _EMAIL_CACHE_TTL)
        return None
    if resp.status_code >= 400:
        raise EclipseApiError(
            f"Eclipse account profile returned {resp.status_code} for {username}",
            status=resp.status_code,
        )
    try:
        payload = resp.json()
    except ValueError as exc:
        raise EclipseApiError(f"Eclipse account profile returned non-JSON: {exc}") from exc
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    email = (payload.get("mail") or payload.get("email") or "").strip()
    cache.set(cache_key, email, _EMAIL_CACHE_TTL)
    return email or None
