"""Tests for the Git publication service against a local bare repo.

These tests need a working Git binary on PATH; they skip cleanly if it
is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from publication.git_service import (
    GitPublicationError,
    WrittenFile,
    _git_env,
    _write_files,
    _write_ssh_wrapper,
    publish_files,
)
from publication.repo_config import RepoConfig


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not on PATH")


def _clone(url: str, dest: str, branch: str = "main") -> None:
    subprocess.run(
        ["git", "clone", "--branch", branch, "--", url, dest],
        check=True,
        capture_output=True,
    )


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
        osv_path_template="osv/{year}/{advisory_id}.json",
        csaf_path_template="csaf/{year}/{advisory_id}.json",
        cve_path_template="cves/{year}/{bucket}/{cve_id}.json",
        cve_assigner_org_id="",
        cve_assigner_short_name="eclipse",
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
    _clone(str(bare_repo), str(verify))
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
    _clone(str(bare_repo), str(verify))
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
        osv_path_template="osv/{year}/{advisory_id}.json",
        csaf_path_template="csaf/{year}/{advisory_id}.json",
        cve_path_template="cves/{year}/{bucket}/{cve_id}.json",
        cve_assigner_org_id="",
        cve_assigner_short_name="eclipse",
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
        osv_path_template="osv/{year}/{advisory_id}.json",
        csaf_path_template="csaf/{year}/{advisory_id}.json",
        cve_path_template="cves/{year}/{bucket}/{cve_id}.json",
        cve_assigner_org_id="",
        cve_assigner_short_name="eclipse",
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


def test_publish_does_not_follow_symlink_out_of_tree(config, bare_repo, tmp_path):
    """CWE-59 regression (F003, INV-PUB-8): a symlink planted at a publication
    write path must not redirect the write outside the clone tree.

    A publication-repo committer is plausibly lower-trust than the worker. Here
    that committer pushes a symlink at the deterministic OSV write path pointing
    at a file *outside* any clone. The next publish writes that same path; the
    out-of-tree file must stay untouched (the symlink was neutralised by the
    ``core.symlinks=false`` clone, so git checked it out as a plain file).
    Without the fix the clone preserves the symlink and the write follows it,
    overwriting the sentinel.
    """
    outside = tmp_path / "outside.txt"
    outside.write_text("SENTINEL\n")

    # Push a symlink into the publication repo HEAD at the OSV write path.
    work = tmp_path / "plant"
    _clone(str(bare_repo), str(work))
    link = work / "osv" / "ECL-cccc-ffff-gggg.json"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "evil@example.org"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "Evil"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "commit.gpgsign", "false"], check=True)
    subprocess.run(["git", "-C", str(work), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-m", "plant symlink"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(work), "push", "origin", "main"], check=True, capture_output=True
    )

    publish_files(
        config=config,
        files=[
            WrittenFile(
                path="osv/ECL-cccc-ffff-gggg.json", content='{"id": "ECL-cccc-ffff-gggg"}\n'
            )
        ],
        commit_message="Publish advisory ECL-cccc-ffff-gggg",
    )

    # The out-of-tree target is untouched: the write stayed inside the clone.
    assert outside.read_text() == "SENTINEL\n"


def test_write_files_refuses_symlink_escape(tmp_path):
    """CWE-59 regression (F003, INV-PUB-8): the containment check in
    ``_write_files`` refuses a write whose target resolves outside the clone
    root, independently of the ``core.symlinks=false`` clone flag.
    """
    outside = tmp_path / "outside.txt"
    outside.write_text("SENTINEL\n")
    root = tmp_path / "repo"
    (root / "osv").mkdir(parents=True)
    (root / "osv" / "ECL-cccc-ffff-gggg.json").symlink_to(outside)

    with pytest.raises(GitPublicationError):
        _write_files(
            root,
            [WrittenFile(path="osv/ECL-cccc-ffff-gggg.json", content="pwned")],
        )
    assert outside.read_text() == "SENTINEL\n"


def test_git_env_extends_process_environment(config, monkeypatch):
    """_git_env must extend os.environ, never replace it.

    The container entrypoint's nss_wrapper variables (LD_PRELOAD /
    NSS_WRAPPER_*) have to reach the git → ssh child processes for ssh to
    work under an arbitrary OpenShift UID.
    """
    monkeypatch.setenv("NSS_WRAPPER_PASSWD", "/tmp/passwd-sentinel")
    env = _git_env(config)
    assert env["NSS_WRAPPER_PASSWD"] == "/tmp/passwd-sentinel"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_AUTHOR_NAME"] == config.commit_author_name
    assert env["GIT_COMMITTER_EMAIL"] == config.commit_author_email


def test_ssh_wrapper_is_directly_executable(tmp_path):
    """The ssh-auth hook must be a ``GIT_SSH`` program, never a shell line.

    git execs ``GIT_SSH`` directly; ``GIT_SSH_COMMAND`` is run through
    ``/bin/sh`` whenever it carries arguments, and the production image
    has no shell.
    """
    config = RepoConfig(
        repo_url="ssh://git@git.example.org/pub.git",
        branch="main",
        auth_method="ssh",
        ssh_key_path="/etc/advisoryhub/keys/pub-repo-ssh-key",
        token="",
        commit_author_name="AdvisoryHub Test",
        commit_author_email="bot@example.org",
        osv_path_template="osv/{year}/{advisory_id}.json",
        csaf_path_template="csaf/{year}/{advisory_id}.json",
        cve_path_template="cves/{year}/{bucket}/{cve_id}.json",
        cve_assigner_org_id="",
        cve_assigner_short_name="eclipse",
    )
    wrapper = _write_ssh_wrapper(tmp_path, config)
    assert Path(wrapper).name == "ssh"  # basename drives git's variant detection
    assert os.access(wrapper, os.X_OK)
    content = Path(wrapper).read_text()
    assert config.ssh_key_path in content
    assert "BatchMode=yes" in content

    if shutil.which("ssh"):
        # ssh -G resolves the config without contacting anything; a zero
        # exit proves the wrapper execs (shebang + execvp) without a shell.
        out = subprocess.run([wrapper, "-G", "git.example.org"], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        assert "batchmode yes" in out.stdout
