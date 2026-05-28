"""Git publication service.

Each call clones the configured repo into a fresh ``TemporaryDirectory``
(no shared mutable checkout, no race between concurrent publications),
writes the generated files at deterministic paths, commits with a
deterministic message, and pushes the configured branch.

Auth modes:

* ``ssh``: set ``GIT_SSH_COMMAND`` for the GitPython subcalls so the SSH
  client uses a specific identity file and skips host-key prompts. The
  configured ``ssh_key_path`` is used as ``-i``.
* ``token``: rewrite the HTTPS URL to embed ``x-access-token:<TOKEN>@``.
  The token never appears in repo state, audit metadata, or last_error
  (URLs are passed through ``redact_secrets`` before persisting).

Public entry point: :func:`publish_files`.
"""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from git import Actor, Repo
from git.exc import GitCommandError

from .repo_config import RepoConfig

log = logging.getLogger(__name__)


class GitPublicationError(Exception):
    """Raised when any Git step (clone/commit/push) fails."""


@dataclass(frozen=True)
class WrittenFile:
    path: str  # path relative to the repo root
    content: str  # serialized file contents


@dataclass(frozen=True)
class PublishResult:
    commit_sha: str
    pushed_to: str  # branch name


def publish_files(
    *,
    config: RepoConfig,
    files: list[WrittenFile],
    commit_message: str,
) -> PublishResult:
    """Publish ``files`` to the configured repository.

    Idempotent on file content: if the files are unchanged from what's
    already in the repo, no commit is created and the function returns
    the current HEAD of the branch.
    """
    if not config.repo_url:
        raise GitPublicationError("publication repository URL is not configured")

    git_env = _ssh_command_env(config)
    with tempfile.TemporaryDirectory(prefix="advisoryhub-pub-") as workdir:
        try:
            effective_url = _embed_token(config)
            repo = Repo.clone_from(
                effective_url,
                workdir,
                branch=config.branch,
                depth=1,
                env=git_env or None,
            )
        except GitCommandError as exc:
            raise GitPublicationError(_redact(str(exc), config)) from exc

        try:
            # Carry the SSH identity into push too, without mutating the
            # global process env (which would race between concurrent
            # publications under a threaded Celery pool).
            if git_env:
                repo.git.update_environment(**git_env)
            _configure_author(repo, config)
            changed = _write_files(Path(workdir), files)
            if not changed:
                sha = repo.head.commit.hexsha
                return PublishResult(commit_sha=sha, pushed_to=config.branch)

            repo.index.add([f.path for f in files])
            commit = repo.index.commit(
                commit_message, author=_author(config), committer=_author(config)
            )
            origin = repo.remote(name="origin")
            push_info = origin.push(refspec=f"HEAD:{config.branch}")
            _check_push(push_info, config)
            return PublishResult(commit_sha=commit.hexsha, pushed_to=config.branch)
        except GitPublicationError:
            raise
        except GitCommandError as exc:
            raise GitPublicationError(_redact(str(exc), config)) from exc


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _ssh_command_env(config: RepoConfig) -> dict[str, str]:
    """Per-call git environment (``GIT_SSH_COMMAND``) when SSH auth is configured.

    Returned as an explicit env dict that is passed to GitPython's
    clone/push commands rather than mutating the global ``os.environ`` —
    the latter would race between concurrent publications under a threaded
    Celery pool.
    """
    if config.auth_method != "ssh" or not config.ssh_key_path:
        return {}
    cmd = (
        f"ssh -i {config.ssh_key_path} "
        "-o IdentitiesOnly=yes "
        "-o StrictHostKeyChecking=accept-new "
        "-o BatchMode=yes"
    )
    return {"GIT_SSH_COMMAND": cmd}


def _embed_token(config: RepoConfig) -> str:
    """Embed an HTTPS token in the URL when configured.

    The returned URL is *only* used as the argument to ``Repo.clone_from``;
    it is never persisted, logged, or audited. ``_redact`` strips it from
    any error string we surface.
    """
    if config.auth_method != "token" or not config.token:
        return config.repo_url
    if not config.repo_url.startswith("https://"):
        return config.repo_url
    return config.repo_url.replace("https://", f"https://x-access-token:{config.token}@", 1)


def _configure_author(repo: Repo, config: RepoConfig) -> None:
    cw = repo.config_writer()
    cw.set_value("user", "name", config.commit_author_name)
    cw.set_value("user", "email", config.commit_author_email)
    # The publication bot must never sign commits — the deploy key/token
    # is the trust signal. Host-wide GPG config (commit.gpgsign=true)
    # would otherwise abort the commit.
    cw.set_value("commit", "gpgsign", "false")
    cw.set_value("tag", "gpgsign", "false")
    cw.release()


def _author(config: RepoConfig) -> Actor:
    return Actor(config.commit_author_name, config.commit_author_email)


def _write_files(root: Path, files: list[WrittenFile]) -> bool:
    """Write each file to disk; return True if any file changed."""
    changed = False
    for f in files:
        target = root / f.path
        target.parent.mkdir(parents=True, exist_ok=True)
        existing = target.read_text() if target.exists() else None
        if existing == f.content:
            continue
        target.write_text(f.content)
        changed = True
    return changed


def _check_push(push_info_list, config: RepoConfig) -> None:
    for info in push_info_list:
        # GitPython push returns flags; non-zero error flags mean failure.
        # See git.PushInfo.flags constants.
        if info.flags & info.ERROR:
            raise GitPublicationError(_redact(f"git push failed: {info.summary}", config))
        if info.flags & info.REJECTED or info.flags & info.REMOTE_REJECTED:
            raise GitPublicationError(_redact(f"git push rejected: {info.summary}", config))


def _redact(message: str, config: RepoConfig) -> str:
    """Strip the token (if any) and any URL embedded credentials from a message."""
    from audit.services import redact_secrets

    out = redact_secrets(message)
    if config.auth_method == "token" and config.token:
        out = out.replace(config.token, "***")
    return out
