"""Tests for the Git publication service against a local bare repo.

These tests need a working Git binary on PATH and the GitPython library;
they skip cleanly if either is missing.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

git_module = pytest.importorskip("git")
from git import Repo  # noqa: E402

from publication.git_service import (
    GitPublicationError,
    WrittenFile,
    publish_files,
)
from publication.repo_config import RepoConfig


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not on PATH")


@pytest.fixture
def bare_repo(tmp_path):
    """A local bare repo with an initial commit on ``main``."""
    bare = tmp_path / "remote.git"
    bare.mkdir()
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=main", str(bare)],
        check=True,
        capture_output=True,
    )
    seed = tmp_path / "seed"
    seed.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(seed)], check=True, capture_output=True
    )
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "seed@example.org"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "Seed"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "tag.gpgsign", "false"], check=True)
    (seed / "README.md").write_text("hi\n")
    subprocess.run(["git", "-C", str(seed), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(seed), "commit", "-m", "init"], check=True, capture_output=True
    )
    subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(bare)], check=True)
    subprocess.run(
        ["git", "-C", str(seed), "push", "origin", "main"], check=True, capture_output=True
    )
    return bare


@pytest.fixture
def config(bare_repo) -> RepoConfig:
    return RepoConfig(
        repo_url=str(bare_repo),
        branch="main",
        auth_method="none",  # local repo, no auth
        ssh_key_path="",
        token="",
        commit_author_name="AdvisoryHub Test",
        commit_author_email="bot@example.org",
        osv_path_template="osv/{advisory_id}.json",
        csaf_path_template="csaf/{advisory_id}.json",
    )


def test_publish_files_writes_and_pushes(config, bare_repo, tmp_path):
    result = publish_files(
        config=config,
        files=[
            WrittenFile(
                path="osv/ECL-cccc-ffff-gggg.json", content='{"id": "ECL-cccc-ffff-gggg"}\n'
            ),
            WrittenFile(
                path="csaf/ECL-cccc-ffff-gggg.json", content='{"id": "ECL-cccc-ffff-gggg"}\n'
            ),
        ],
        commit_message="Publish advisory ECL-cccc-ffff-gggg",
    )
    assert result.commit_sha
    assert result.pushed_to == "main"

    # Re-clone the bare repo to verify the files arrived.
    verify = tmp_path / "verify"
    Repo.clone_from(str(bare_repo), str(verify), branch="main")
    assert (
        verify / "osv" / "ECL-cccc-ffff-gggg.json"
    ).read_text() == '{"id": "ECL-cccc-ffff-gggg"}\n'
    assert (verify / "csaf" / "ECL-cccc-ffff-gggg.json").exists()


def test_publish_is_idempotent_when_content_unchanged(config, bare_repo):
    file = WrittenFile(path="osv/ECL-cccc-ffff-gggg.json", content='{"id": "ECL-cccc-ffff-gggg"}\n')
    r1 = publish_files(config=config, files=[file], commit_message="Publish")
    r2 = publish_files(config=config, files=[file], commit_message="Publish")
    assert r1.commit_sha == r2.commit_sha  # no new commit when content unchanged


def test_publish_overwrites_existing_file_on_change(config, bare_repo, tmp_path):
    file_v1 = WrittenFile(path="osv/X.json", content='{"v": 1}\n')
    file_v2 = WrittenFile(path="osv/X.json", content='{"v": 2}\n')
    r1 = publish_files(config=config, files=[file_v1], commit_message="v1")
    r2 = publish_files(config=config, files=[file_v2], commit_message="v2")
    assert r1.commit_sha != r2.commit_sha
    verify = tmp_path / "verify"
    Repo.clone_from(str(bare_repo), str(verify), branch="main")
    assert (verify / "osv" / "X.json").read_text() == '{"v": 2}\n'


def test_publish_clone_failure_raises(config, tmp_path):
    bad_config = RepoConfig(
        repo_url=str(tmp_path / "definitely-not-a-repo.git"),
        branch="main",
        auth_method="none",
        ssh_key_path="",
        token="",
        commit_author_name="x",
        commit_author_email="x@example.org",
        osv_path_template="osv/{advisory_id}.json",
        csaf_path_template="csaf/{advisory_id}.json",
    )
    with pytest.raises(GitPublicationError):
        publish_files(
            config=bad_config,
            files=[WrittenFile(path="x.json", content="{}")],
            commit_message="x",
        )


def test_publish_redacts_token_in_error_message(tmp_path):
    bad_config = RepoConfig(
        repo_url="https://github.test/missing.git",
        branch="main",
        auth_method="token",
        ssh_key_path="",
        token="ghp_supersecrettoken",
        commit_author_name="x",
        commit_author_email="x@example.org",
        osv_path_template="osv/{advisory_id}.json",
        csaf_path_template="csaf/{advisory_id}.json",
    )
    try:
        publish_files(
            config=bad_config,
            files=[WrittenFile(path="x.json", content="{}")],
            commit_message="x",
        )
    except GitPublicationError as exc:
        assert "ghp_supersecrettoken" not in str(exc)
    else:
        pytest.fail("expected GitPublicationError")
