#!/usr/bin/env python3
"""Fail on new advisories -> workflows imports.

``workflows`` sits ABOVE ``advisories`` in the app layering:
``workflows/models.py`` and ``workflows/services.py`` import ``advisories`` at
module level. The reverse edge must therefore never be module-level — a
well-meaning refactor hoisting one of the function-local back-edges to the top
of a file would close the import cycle at app-load time.

The known back-edges are FROZEN below: adding one (or removing one without
shrinking the allowlist) fails this guard, so every change to the cycle is a
conscious decision, not drift. Run by prek (commit stage) and CI
(django-checks job); ``mise run check-imports`` runs it by hand.
"""

from __future__ import annotations

import ast
import pathlib
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent

SOURCE_APP = "advisories"
TARGET_MODULE = "workflows"

# Module-level imports of the target that are deliberately allowed.
# advisories/views_workflow.py is the documented bridge to workflows: a
# URLconf-mounted view module that loads after apps are ready, so its
# top-level imports cannot wedge app loading.
MODULE_LEVEL_ALLOWLIST: dict[str, Counter[str]] = {
    "advisories/views_workflow.py": Counter({"workflows": 1, "workflows.models": 1}),
}

# Function-local back-edges, frozen per file as {imported module: count}.
# Exact match both ways: a NEW site fails (justify it and update this list
# consciously), and a REMOVED site fails too (shrink the list so the ratchet
# only ever moves down).
LOCAL_IMPORT_ALLOWLIST: dict[str, Counter[str]] = {
    "advisories/services.py": Counter({"workflows.services": 3, "workflows.models": 1}),
    "advisories/permissions.py": Counter({"workflows.models": 1}),
    "advisories/views.py": Counter({"workflows.models": 1}),
}


def _target_modules(node: ast.Import | ast.ImportFrom) -> list[str]:
    """Names imported by ``node`` that live in the target app ('' if none)."""
    if isinstance(node, ast.ImportFrom):
        # Relative imports (level > 0) can never reach a sibling app.
        if node.level or not node.module:
            return []
        module = node.module
        if module == TARGET_MODULE or module.startswith(TARGET_MODULE + "."):
            return [module]
        return []
    return [
        alias.name
        for alias in node.names
        if alias.name == TARGET_MODULE or alias.name.startswith(TARGET_MODULE + ".")
    ]


def _is_type_checking_if(node: ast.If) -> bool:
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def scan_source(text: str) -> tuple[Counter[str], Counter[str], list[tuple[int, str]]]:
    """Count target-app imports in ``text``.

    Returns ``(module_level, function_local, module_level_sites)`` where the
    counters map imported module name -> occurrences and ``module_level_sites``
    is ``[(line, module), ...]`` for error reporting. "Module level" means
    executed at import time — including try/if/class bodies — with one
    carve-out: ``if TYPE_CHECKING:`` bodies never execute at runtime and
    cannot create a cycle, so they are ignored.
    """
    module_level: Counter[str] = Counter()
    function_local: Counter[str] = Counter()
    sites: list[tuple[int, str]] = []

    def visit(node: ast.AST, in_function: bool) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for module in _target_modules(node):
                if in_function:
                    function_local[module] += 1
                else:
                    module_level[module] += 1
                    sites.append((node.lineno, module))
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            in_function = True
        elif isinstance(node, ast.If) and not in_function and _is_type_checking_if(node):
            for child in node.orelse:
                visit(child, in_function)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, in_function)

    visit(ast.parse(text), in_function=False)
    return module_level, function_local, sites


def _production_files(root: pathlib.Path) -> list[pathlib.Path]:
    files = []
    for path in sorted((root / SOURCE_APP).rglob("*.py")):
        parts = path.relative_to(root).parts
        if "migrations" in parts or "tests" in parts:
            continue
        if path.name == "tests.py" or path.name.startswith("test_"):
            continue
        files.append(path)
    return files


def main(root: pathlib.Path = ROOT) -> int:
    offenders: list[str] = []

    for path in _production_files(root):
        rel = path.relative_to(root).as_posix()
        module_level, function_local, sites = scan_source(path.read_text(encoding="utf-8"))

        allowed_module_level = MODULE_LEVEL_ALLOWLIST.get(rel, Counter())
        if module_level != allowed_module_level:
            where = ", ".join(f"{module} at line {line}" for line, module in sites) or "none"
            offenders.append(
                f"{rel}: module-level imports of {TARGET_MODULE}.* changed: "
                f"got {where}; allowlist says {dict(allowed_module_level) or 'none'} — "
                f"module-level back-edges wedge app loading, keep them function-local"
            )

        allowed_local = LOCAL_IMPORT_ALLOWLIST.get(rel, Counter())
        if function_local != allowed_local:
            offenders.append(
                f"{rel}: function-local imports of {TARGET_MODULE}.* changed: "
                f"got {dict(function_local) or 'none'}, "
                f"allowlist says {dict(allowed_local) or 'none'} — a new back-edge "
                f"must be justified here; a removed one must shrink the allowlist"
            )

    if offenders:
        sys.stderr.write(
            f"{SOURCE_APP} must not grow new imports of {TARGET_MODULE} "
            f"({TARGET_MODULE} sits above {SOURCE_APP}; see the frozen allowlists "
            f"in dev/check_import_direction.py):\n"
        )
        for offender in offenders:
            sys.stderr.write(f"  {offender}\n")
        return 1

    print(f"OK: {SOURCE_APP} -> {TARGET_MODULE} import direction holds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
