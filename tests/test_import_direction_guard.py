"""Self-test for ``dev/check_import_direction.py``.

The guard freezes the advisories -> workflows back-edges (module-level
forbidden, function-local pinned to a per-file allowlist). These tests pin the
AST classification rules the guard relies on, and ``test_live_tree_passes``
doubles as the proof that the frozen allowlist counters match the real tree.

No database needed — pure filesystem + AST.
"""

from __future__ import annotations

import importlib.util
import pathlib
import textwrap

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "check_import_direction", REPO_ROOT / "dev" / "check_import_direction.py"
)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)


def _scan(source: str):
    return guard.scan_source(textwrap.dedent(source))


def test_module_level_import_is_flagged():
    module_level, function_local, sites = _scan(
        """
        from workflows.models import ReviewTask
        """
    )
    assert module_level == {"workflows.models": 1}
    assert not function_local
    assert sites == [(2, "workflows.models")]


def test_plain_import_and_submodule_forms_are_matched():
    module_level, _, _ = _scan(
        """
        import workflows
        import workflows.services
        from workflows import services
        """
    )
    assert module_level == {"workflows": 2, "workflows.services": 1}


def test_class_body_import_counts_as_module_level():
    # A class body executes at import time — hoisting an import there would
    # still wedge app loading, so it must not count as function-local.
    module_level, function_local, _ = _scan(
        """
        class Config:
            from workflows.models import ReviewTask
        """
    )
    assert module_level == {"workflows.models": 1}
    assert not function_local


def test_try_block_import_counts_as_module_level():
    module_level, _, _ = _scan(
        """
        try:
            from workflows.services import request_cve
        except ImportError:
            request_cve = None
        """
    )
    assert module_level == {"workflows.services": 1}


def test_function_local_import_is_counted():
    module_level, function_local, _ = _scan(
        """
        def transition():
            from workflows.services import cancel_pending_review
            async def inner():
                from workflows.models import CveRequestStatus
        """
    )
    assert not module_level
    assert function_local == {"workflows.services": 1, "workflows.models": 1}


def test_type_checking_block_is_ignored():
    # `if TYPE_CHECKING:` bodies never execute at runtime — no cycle possible.
    module_level, function_local, _ = _scan(
        """
        import typing
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            from workflows.models import ReviewTask
        if typing.TYPE_CHECKING:
            from workflows.services import request_cve
        else:
            from workflows import services
        """
    )
    assert module_level == {"workflows": 1}  # only the runtime `else` branch
    assert not function_local


def test_relative_and_unrelated_imports_are_ignored():
    module_level, function_local, _ = _scan(
        """
        from . import workflows
        from .workflows import helper
        from workflowsextra import thing
        import advisories.models
        """
    )
    assert not module_level
    assert not function_local


def test_live_tree_passes():
    # The authoritative check that the frozen allowlist Counters match the
    # actual repository — if a back-edge is added or removed, this fails.
    assert guard.main() == 0


def test_new_module_level_backedge_fails(tmp_path, capsys):
    app = tmp_path / "advisories"
    app.mkdir()
    (app / "apps.py").write_text("from workflows import services\n", encoding="utf-8")
    assert guard.main(root=tmp_path) == 1
    assert "module-level imports of workflows.* changed" in capsys.readouterr().err


def test_stale_allowlist_fails(tmp_path, capsys):
    # A tree with none of the frozen function-local back-edges: the allowlist
    # for advisories/services.py is now stale, and the guard must say so
    # rather than silently letting the list rot.
    app = tmp_path / "advisories"
    app.mkdir()
    (app / "services.py").write_text("x = 1\n", encoding="utf-8")
    assert guard.main(root=tmp_path) == 1
    assert "shrink the allowlist" in capsys.readouterr().err
