"""Thin GitHub REST client scoped to the GHSA surface.

AdvisoryHub is registered as a GitHub App with only two permissions —
``repository_security_advisories: read & write`` and ``metadata: read``.
Every API call goes through an **installation access token** that we
mint just-in-time from the App private key. The private key is the
single load-bearing secret in this module:

* It is loaded from ``settings.GITHUB_APP_PRIVATE_KEY_PATH`` (preferred,
  file on disk) or ``settings.GITHUB_APP_PRIVATE_KEY`` (inline fallback
  for dev).
* It never reaches the DB, never reaches logs, and the audit redactor
  scrubs PEM blocks defensively if one ever surfaces in an error string.
* Installation tokens are cached in **process memory**, keyed by
  installation id, for slightly less than GitHub's stated expiry
  (five-minute safety margin) and never persisted.

Multi-installation routing: AdvisoryHub may be installed on more than one
GitHub account (``eclipse``, ``eclipse-ee4j``, …). Each install has its
own installation id. The client looks up the matching
:class:`ghsa.models.GitHubAppInstallation` row by ``account_login``
(which is the GitHub repo's ``owner``) and uses *that* installation's
token. There is **no env-var fallback** — if no row matches, the call
raises ``GitHubApiError("no installation registered for <owner>")`` and
operators must run ``manage.py discover_github_installations`` (or wait
for the first ``installation.created`` webhook) to populate the table.

Failure shape: every public method either returns the parsed JSON
response (or ``None`` for 404) or raises :class:`GitHubApiError` carrying
an already-redacted message.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import requests
from django.conf import settings

from audit.services import redact_secrets

_GITHUB_API_VERSION = "2022-11-28"
_USER_AGENT = "AdvisoryHub/GHSA-bridge"
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 30
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_BASE = 1.5  # seconds


class GitHubApiError(Exception):
    """Raised for any non-2xx GitHub response or transport failure.

    Always carries a redacted message — never a raw token or PEM body.
    """

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(redact_secrets(message) if isinstance(message, str) else str(message))
        self.status = status


class GitHubAppClient:
    """Process-wide client that routes calls to per-account installation tokens.

    Construct via :func:`get_client` — it keeps a module-level instance
    so the installation-token cache is shared across calls in the same
    process. Each public method takes ``owner`` (= GitHub account_login)
    and looks up the matching :class:`GitHubAppInstallation` row to
    decide which installation's token to mint.
    """

    def __init__(
        self,
        *,
        app_id: int,
        private_key: str,
        api_base_url: str = "https://api.github.com",
        session: requests.Session | None = None,
    ) -> None:
        if not app_id:
            raise GitHubApiError("GITHUB_APP_ID is not configured")
        if not private_key:
            raise GitHubApiError("GITHUB_APP_PRIVATE_KEY(_PATH) is not configured")
        self._app_id = app_id
        self._private_key = private_key
        self._api_base_url = api_base_url.rstrip("/")
        self._session = session or requests.Session()
        self._token_lock = threading.Lock()
        # Per-installation token cache. Keyed by installation_id so
        # routing a request for a different owner doesn't invalidate
        # another owner's still-valid token.
        self._token_cache: dict[int, tuple[str, datetime]] = {}

    # ---- auth -----------------------------------------------------------

    def _mint_app_jwt(self) -> str:
        """Short-lived JWT signed with the App private key (RS256).

        Used both to exchange for installation tokens and (rarely) for
        App-scoped calls like ``GET /app/installations``.
        """
        now = int(time.time())
        payload = {
            "iat": now - 30,  # backdate to tolerate clock skew
            "exp": now + 9 * 60,  # GitHub allows up to 10 min
            "iss": str(self._app_id),
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def _resolve_installation(self, owner: str):
        """Look up the active installation row for ``owner``.

        Raises :class:`GitHubApiError` if no row matches or the matching
        row is suspended. No env-var fallback — operators must populate
        the table via ``discover_github_installations`` or webhooks.
        """
        from .models import GitHubAppInstallation  # local import to avoid app-loading cycles

        row = GitHubAppInstallation.objects.filter(
            account_login=owner, suspended_at__isnull=True
        ).first()
        if row is None:
            raise GitHubApiError(
                f"no installation registered for {owner!r} "
                "(run manage.py discover_github_installations)"
            )
        return row

    def _get_installation_token(self, installation_id: int) -> str:
        """Return a valid installation access token, minting one if needed.

        Tokens are cached per installation_id with a five-minute safety
        margin before GitHub's stated expiry.
        """
        with self._token_lock:
            now = datetime.now(UTC)
            cached = self._token_cache.get(installation_id)
            if cached is not None:
                token, expiry = cached
                if now < expiry:
                    return token
            app_jwt = self._mint_app_jwt()
            url = f"{self._api_base_url}/app/installations/{installation_id}/access_tokens"
            try:
                resp = self._session.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {app_jwt}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": _GITHUB_API_VERSION,
                        "User-Agent": _USER_AGENT,
                    },
                    timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                )
            except requests.RequestException as exc:
                raise GitHubApiError(f"installation token request failed: {exc}") from exc
            if resp.status_code >= 400:
                raise GitHubApiError(
                    f"installation token request returned {resp.status_code}: {resp.text}",
                    status=resp.status_code,
                )
            data = resp.json()
            token = data.get("token")
            if not token:
                raise GitHubApiError("installation token response missing 'token'")
            expires_at = data.get("expires_at")
            if expires_at:
                try:
                    parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    expiry_dt = parsed - timedelta(minutes=5)
                except ValueError:
                    expiry_dt = now + timedelta(minutes=50)
            else:
                expiry_dt = now + timedelta(minutes=50)
            self._token_cache[installation_id] = (token, expiry_dt)
            return token

    # ---- request plumbing ----------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        owner: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> requests.Response:
        """Execute a request with retries on 429/5xx and a redacted error.

        ``owner`` determines which installation token is used.
        """
        installation = self._resolve_installation(owner)
        url = f"{self._api_base_url}{path}"
        attempt = 0
        last_exc: Exception | None = None
        while attempt < _MAX_ATTEMPTS:
            attempt += 1
            try:
                token = self._get_installation_token(installation.installation_id)
                resp = self._session.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": _GITHUB_API_VERSION,
                        "User-Agent": _USER_AGENT,
                    },
                    timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < _MAX_ATTEMPTS:
                    time.sleep(_RETRY_BACKOFF_BASE**attempt)
                    continue
                raise GitHubApiError(f"{method} {path} transport error: {exc}") from exc
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < _MAX_ATTEMPTS:
                    delay = _RETRY_BACKOFF_BASE**attempt
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = max(delay, float(retry_after))
                        except ValueError:
                            pass
                    time.sleep(delay)
                    continue
            return resp
        raise GitHubApiError(f"{method} {path} exhausted retries: {last_exc}")

    @staticmethod
    def _raise_for(resp: requests.Response, *, path: str, method: str) -> None:
        if 200 <= resp.status_code < 300:
            return
        body = resp.text[:2000]
        raise GitHubApiError(
            f"{method} {path} returned {resp.status_code}: {body}",
            status=resp.status_code,
        )

    # ---- public API ----------------------------------------------------

    def list_repo_advisories(
        self,
        owner: str,
        repo: str,
        *,
        state: str | None = None,
        per_page: int = 100,
    ) -> Iterator[dict[str, Any]]:
        """Yield every security advisory in ``owner/repo``.

        ``state`` is a comma-separated GitHub filter (e.g. ``"draft"``,
        ``"published"``, ``"draft,triage,published"``). Pagination is
        traversed transparently using the ``Link`` header.
        """
        installation = self._resolve_installation(owner)
        path = f"/repos/{owner}/{repo}/security-advisories"
        query: dict[str, Any] = {"per_page": per_page}
        if state:
            query["state"] = state
        # ``params`` is cleared to None once pagination follows Link headers,
        # whose target URLs already carry the query string.
        params: dict[str, Any] | None = query
        url: str | None = f"{self._api_base_url}{path}"
        while url:
            if url.startswith(self._api_base_url):
                resp = self._request(
                    "GET", url[len(self._api_base_url) :], owner=owner, params=params
                )
            else:
                resp = self._raw_get(url, installation_id=installation.installation_id)
            self._raise_for(resp, path=path, method="GET")
            yield from resp.json()
            url = self._next_link(resp.headers.get("Link", ""))
            params = None  # query is baked into Link target

    def _raw_get(self, url: str, *, installation_id: int) -> requests.Response:
        token = self._get_installation_token(installation_id)
        return self._session.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": _GITHUB_API_VERSION,
                "User-Agent": _USER_AGENT,
            },
            timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
        )

    @staticmethod
    def _next_link(link_header: str) -> str | None:
        """Extract the ``rel="next"`` URL from a Link header, if any."""
        if not link_header:
            return None
        for part in link_header.split(","):
            segment = part.strip()
            if 'rel="next"' in segment and segment.startswith("<"):
                return segment.split(">", 1)[0][1:]
        return None

    def get_advisory(self, owner: str, repo: str, ghsa_id: str) -> dict[str, Any] | None:
        """Fetch a single repository security advisory by GHSA id.

        Returns ``None`` on 404 so callers can detect "the GHSA was
        deleted upstream" without an exception.
        """
        path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
        resp = self._request("GET", path, owner=owner)
        if resp.status_code == 404:
            return None
        self._raise_for(resp, path=path, method="GET")
        return resp.json()

    def update_advisory_cve(
        self, owner: str, repo: str, ghsa_id: str, cve_id: str
    ) -> dict[str, Any]:
        """PATCH the linked GHSA with the EF-assigned CVE id.

        EF is the CNA, so we set ``cve_id`` directly (we do NOT ask
        GitHub to allocate one via ``CVE`` request). Returns the parsed
        GHSA payload after update.
        """
        path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
        resp = self._request("PATCH", path, owner=owner, json_body={"cve_id": cve_id})
        self._raise_for(resp, path=path, method="PATCH")
        return resp.json()

    # ---- App-scoped (no installation token) -----------------------------

    def list_installations(self) -> list[dict[str, Any]]:
        """Enumerate every installation of this App across GitHub.

        Uses the App JWT directly (no installation token). Backstop for
        cold-start and a "rescan installations" admin action. GitHub
        paginates this endpoint with the same Link-header scheme as the
        rest of the API.
        """
        url: str | None = f"{self._api_base_url}/app/installations"
        params: dict[str, Any] | None = {"per_page": 100}
        items: list[dict[str, Any]] = []
        while url:
            try:
                resp = self._session.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"Bearer {self._mint_app_jwt()}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": _GITHUB_API_VERSION,
                        "User-Agent": _USER_AGENT,
                    },
                    timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                )
            except requests.RequestException as exc:
                raise GitHubApiError(f"GET /app/installations transport error: {exc}") from exc
            self._raise_for(resp, path="/app/installations", method="GET")
            items.extend(resp.json())
            url = self._next_link(resp.headers.get("Link", ""))
            params = None
        return items


# ---------------------------------------------------------------------------
# Module-level accessor — keep the installation-token cache shared across
# all callers in the same process.
# ---------------------------------------------------------------------------

_client_lock = threading.Lock()
_client_instance: GitHubAppClient | None = None


def _load_private_key() -> str:
    path = getattr(settings, "GITHUB_APP_PRIVATE_KEY_PATH", "") or ""
    if path:
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise GitHubApiError(f"could not read GITHUB_APP_PRIVATE_KEY_PATH: {exc}") from exc
    inline = getattr(settings, "GITHUB_APP_PRIVATE_KEY", "") or ""
    if inline:
        # Allow newlines that have been escaped in env files.
        return inline.replace("\\n", "\n")
    raise GitHubApiError(
        "neither GITHUB_APP_PRIVATE_KEY_PATH nor GITHUB_APP_PRIVATE_KEY is configured"
    )


def get_client() -> GitHubAppClient:
    """Return the process-wide GitHubAppClient, lazily constructed."""
    global _client_instance
    with _client_lock:
        if _client_instance is not None:
            return _client_instance
        _client_instance = GitHubAppClient(
            app_id=settings.GITHUB_APP_ID,
            private_key=_load_private_key(),
            api_base_url=settings.GITHUB_APP_API_BASE_URL,
        )
        return _client_instance


def reset_client_for_tests() -> None:
    """Test hook to drop the cached singleton between cases."""
    global _client_instance
    with _client_lock:
        _client_instance = None
