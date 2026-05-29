"""Resolve the active publication repository configuration.

Resolution order:

1. The first ``PublicationRepositoryConfig`` row marked ``is_active=True``.
2. Otherwise, the env-driven defaults from ``settings``.

Returns a plain dataclass so the rest of the pipeline doesn't depend on
the DB row's identity.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings


def _cve_path_parts(cve_id: str) -> tuple[str, str]:
    """Derive ``(year, bucket)`` from a CVE id for the cvelistV5 layout.

    ``CVE-2026-0001`` → ``("2026", "0xxx")``; ``CVE-2026-12345`` →
    ``("2026", "12xxx")``. The bucket is the sequence number with its last
    three digits replaced by ``xxx`` (i.e. ``floor(n / 1000)`` + ``"xxx"``),
    matching CVEProject/cvelistV5. Falls back to safe placeholders for
    unexpected shapes rather than raising.
    """
    parts = cve_id.split("-")
    if len(parts) == 3 and parts[0] == "CVE":
        year = parts[1]
        try:
            bucket = f"{int(parts[2]) // 1000}xxx"
        except ValueError:
            bucket = "xxx"
        return year, bucket
    return "unknown", "xxx"


@dataclass(frozen=True)
class RepoConfig:
    repo_url: str
    branch: str
    auth_method: str  # "ssh" | "token"
    ssh_key_path: str
    token: str
    commit_author_name: str
    commit_author_email: str
    osv_path_template: str
    csaf_path_template: str
    cve_path_template: str
    cve_assigner_org_id: str
    cve_assigner_short_name: str

    def osv_path(self, advisory_id: str) -> str:
        return self.osv_path_template.format(advisory_id=advisory_id)

    def csaf_path(self, advisory_id: str) -> str:
        return self.csaf_path_template.format(advisory_id=advisory_id)

    def cve_path(self, cve_id: str) -> str:
        year, bucket = _cve_path_parts(cve_id)
        return self.cve_path_template.format(year=year, bucket=bucket, cve_id=cve_id)


def active_config() -> RepoConfig:
    try:
        from .models import PublicationRepositoryConfig
    except Exception:  # pragma: no cover — defensive
        return _from_settings()
    row = PublicationRepositoryConfig.objects.filter(is_active=True).first()
    if row is None:
        return _from_settings()
    return RepoConfig(
        repo_url=row.repo_url,
        branch=row.branch,
        auth_method=row.auth_method,
        ssh_key_path=row.ssh_key_path,
        token=row.token,
        commit_author_name=row.commit_author_name,
        commit_author_email=row.commit_author_email,
        osv_path_template=row.osv_path_template,
        csaf_path_template=row.csaf_path_template,
        cve_path_template=row.cve_path_template,
        # CNA identity is a global Eclipse Foundation property, not a
        # per-target-repo setting, so it is always sourced from settings.
        cve_assigner_org_id=settings.PUB_CVE_ASSIGNER_ORG_ID,
        cve_assigner_short_name=settings.PUB_CVE_ASSIGNER_SHORT_NAME,
    )


def _from_settings() -> RepoConfig:
    return RepoConfig(
        repo_url=settings.PUB_REPO_URL,
        branch=settings.PUB_REPO_BRANCH,
        auth_method=settings.PUB_REPO_AUTH,
        ssh_key_path=settings.PUB_REPO_SSH_KEY_PATH,
        token=settings.PUB_REPO_TOKEN,
        commit_author_name=settings.PUB_COMMIT_AUTHOR_NAME,
        commit_author_email=settings.PUB_COMMIT_AUTHOR_EMAIL,
        osv_path_template=settings.PUB_OSV_PATH_TEMPLATE,
        csaf_path_template=settings.PUB_CSAF_PATH_TEMPLATE,
        cve_path_template=settings.PUB_CVE_PATH_TEMPLATE,
        cve_assigner_org_id=settings.PUB_CVE_ASSIGNER_ORG_ID,
        cve_assigner_short_name=settings.PUB_CVE_ASSIGNER_SHORT_NAME,
    )
