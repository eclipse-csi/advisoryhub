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

    def osv_path(self, advisory_id: str) -> str:
        return self.osv_path_template.format(advisory_id=advisory_id)

    def csaf_path(self, advisory_id: str) -> str:
        return self.csaf_path_template.format(advisory_id=advisory_id)


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
    )
