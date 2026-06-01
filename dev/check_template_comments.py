#!/usr/bin/env python3
"""Fail if any Django ``{# #}`` template comment spans more than one line.

Django's ``{# #}`` comment is single-line only: the template lexer regex has no
``re.DOTALL`` flag, so a comment split across a newline is NOT stripped and is
rendered verbatim into the page (visible stray text). ``manage.py check`` does
not catch this, so we guard it here (run by prek and CI). Use ``{% comment %}
… {% endcomment %}`` for genuinely multi-line comments.
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUFFIXES = (".html", ".txt")

offenders: list[str] = []

for base in ("templates",):
    root = ROOT / base
    if not root.exists():
        continue
    for path in sorted(root.rglob("*")):
        if path.suffix not in SUFFIXES or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        idx = 0
        while True:
            open_at = text.find("{#", idx)
            if open_at == -1:
                break
            close_at = text.find("#}", open_at + 2)
            newline_at = text.find("\n", open_at + 2)
            # Bad if there's no close, or a newline appears before the close.
            if close_at == -1 or (newline_at != -1 and newline_at < close_at):
                line = text.count("\n", 0, open_at) + 1
                offenders.append(f"{path.relative_to(ROOT)}:{line}")
                idx = newline_at + 1 if newline_at != -1 else len(text)
            else:
                idx = close_at + 2

if offenders:
    sys.stderr.write(
        "Multi-line Django {# #} comments render as literal text (the {# #} "
        "comment is single-line only). Collapse to one line, or use "
        "{% comment %}…{% endcomment %}:\n"
    )
    for o in offenders:
        sys.stderr.write(f"  {o}\n")
    sys.exit(1)

print("OK: no multi-line {# #} template comments")
