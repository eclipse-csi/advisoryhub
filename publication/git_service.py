"""Git publication service.

Each call clones the configured repo into a fresh ``TemporaryDirectory``
(no shared mutable checkout, no race between concurrent publications),
writes the generated files at deterministic paths, commits with a
deterministic message, and pushes the configured branch.

Every Git operation shells out to the ``git`` binary directly — argument
lists only, never ``shell=True`` — so the production image needs nothing
beyond the ``git``/``ssh`` executables (it has no shell). The per-command
timeouts below are the *only* real hang protection: Celery time limits
are not enforced under the threads pool the production worker runs with.

Auth modes:

* ``ssh``: set ``GIT_SSH_COMMAND`` for the git subprocesses so the SSH
  client uses a specific identity file and skips host-key prompts. The
  configured ``ssh_key_path`` is used as ``-i``.
* ``token``: rewrite the HTTPS URL to embed ``x-access-token:<TOKEN>@``.
  The token never appears in repo state, audit metadata, or last_error
  (error messages are built from git's output — never the argument list —
  and passed through ``redact_secrets`` before persisting).

Public entry point: :func:`publish_files`.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .repo_config import RepoConfig

log = logging.getLogger(__name__)

# Wall-clock caps per git invocation. Network commands (clone/push) get a
# generous budget that still fits inside the publication task's overall
# window; local commands (add/commit/rev-parse) should be near-instant.
_NETWORK_TIMEOUT = 300
_LOCAL_TIMEOUT = 60


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

    env = _git_env(config)
    with tempfile.TemporaryDirectory(prefix="advisoryhub-pub-") as workdir:
        # The token-embedded URL only ever appears in this argument list;
        # _run_git never quotes the argument list in error messages.
        _run_git(
            [
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--branch",
                config.branch,
                "--",
                _embed_token(config),
                workdir,
            ],
            action="clone",
            env=env,
            config=config,
            timeout=_NETWORK_TIMEOUT,
        )

        changed = _write_files(Path(workdir), files)
        if not changed:
            sha = _rev_parse_head(workdir, env=env, config=config)
            return PublishResult(commit_sha=sha, pushed_to=config.branch)

        _run_git(
            ["-C", workdir, "add", "--", *[f.path for f in files]],
            action="add",
            env=env,
            config=config,
            timeout=_LOCAL_TIMEOUT,
        )
        # Author/committer identity comes from the GIT_AUTHOR_*/GIT_COMMITTER_*
        # variables in ``env``. The publication bot must never sign commits —
        # the deploy key/token is the trust signal. Host-wide GPG config
        # (commit.gpgsign=true) would otherwise abort the commit.
        _run_git(
            [
                "-C",
                workdir,
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "commit",
                "-m",
                commit_message,
            ],
            action="commit",
            env=env,
            config=config,
            timeout=_LOCAL_TIMEOUT,
        )
        _run_git(
            ["-C", workdir, "push", "origin", f"HEAD:{config.branch}"],
            action="push",
            env=env,
            config=config,
            timeout=_NETWORK_TIMEOUT,
        )
        sha = _rev_parse_head(workdir, env=env, config=config)
        return PublishResult(commit_sha=sha, pushed_to=config.branch)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _run_git(
    args: list[str],
    *,
    action: str,
    env: dict[str, str],
    config: RepoConfig,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run one git command; raise a redacted :class:`GitPublicationError` on failure.

    Error messages are built from ``action`` and git's own output only —
    never from the argument list, which may embed the HTTPS token.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitPublicationError(f"git {action} timed out after {timeout}s") from exc
    except OSError as exc:  # git binary missing or not executable
        raise GitPublicationError(_redact(f"git {action} failed to start: {exc}", config)) from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "no output"
        raise GitPublicationError(
            _redact(f"git {action} failed (exit {proc.returncode}): {detail}", config)
        )
    return proc


def _rev_parse_head(workdir: str, *, env: dict[str, str], config: RepoConfig) -> str:
    proc = _run_git(
        ["-C", workdir, "rev-parse", "HEAD"],
        action="rev-parse",
        env=env,
        config=config,
        timeout=_LOCAL_TIMEOUT,
    )
    return proc.stdout.strip()


def _git_env(config: RepoConfig) -> dict[str, str]:
    """Per-call environment for the git subprocesses.

    Built as an explicit dict per call rather than mutating the global
    ``os.environ`` — that would race between concurrent publications under
    a threaded Celery pool. It must *extend* the process environment, not
    replace it: the container entrypoint's nss_wrapper variables
    (``LD_PRELOAD``/``NSS_WRAPPER_*``) have to reach the git → ssh child
    processes for ssh to work under an arbitrary OpenShift UID.
    """
    env = {
        **os.environ,
        # Fail fast instead of waiting on an interactive credential prompt.
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": config.commit_author_name,
        "GIT_AUTHOR_EMAIL": config.commit_author_email,
        "GIT_COMMITTER_NAME": config.commit_author_name,
        "GIT_COMMITTER_EMAIL": config.commit_author_email,
    }
    if config.auth_method == "ssh" and config.ssh_key_path:
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {config.ssh_key_path} "
            "-o IdentitiesOnly=yes "
            "-o StrictHostKeyChecking=accept-new "
            "-o BatchMode=yes"
        )
    return env


def _embed_token(config: RepoConfig) -> str:
    """Embed an HTTPS token in the URL when configured.

    The returned URL is *only* used as a ``git clone`` argument; it is
    never persisted, logged, or audited. ``_redact`` strips it from any
    error string we surface.
    """
    if config.auth_method != "token" or not config.token:
        return config.repo_url
    if not config.repo_url.startswith("https://"):
        return config.repo_url
    return config.repo_url.replace("https://", f"https://x-access-token:{config.token}@", 1)


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


def _redact(message: str, config: RepoConfig) -> str:
    """Strip the token (if any) and any URL embedded credentials from a message."""
    from audit.services import redact_secrets

    out = redact_secrets(message)
    if config.auth_method == "token" and config.token:
        out = out.replace(config.token, "***")
    return out
