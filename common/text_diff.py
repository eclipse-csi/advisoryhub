"""Line + word level text diff helper.

Used by the description-history and comment-history drawers (see
``templates/common/_diff_chunks.html``). The output is *plain data* —
templates own the HTML. The algorithm is field-agnostic: any two
markdown strings (or any text strings really) can be diffed.

Chunk shape::

    {"kind": "equal"|"insert"|"delete", "lines": [...]}
    {"kind": "replace", "pairs": [
        {"before_runs": [{"op": "equal"|"delete", "text": ...}, ...] | None,
         "after_runs":  [{"op": "equal"|"insert", "text": ...}, ...] | None},
        ...
    ]}

A ``replace`` chunk pairs each before-line with the after-line at the
same index inside the block (the common case is a polish-wording edit
where line counts match). Unpaired lines on the longer side render as
pure insert/delete (``before_runs`` or ``after_runs`` set to ``None``).
"""

from __future__ import annotations

import difflib
import re
from typing import Any

_WORD_RE = re.compile(r"\w+|\s+|[^\w\s]", re.UNICODE)


def text_diff(before: str, after: str) -> list[dict[str, Any]]:
    """Line+word level diff of two text strings."""
    before_lines = before.splitlines() if before else []
    after_lines = after.splitlines() if after else []

    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    chunks: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            chunks.append({"kind": "equal", "lines": before_lines[i1:i2]})
        elif tag == "insert":
            chunks.append({"kind": "insert", "lines": after_lines[j1:j2]})
        elif tag == "delete":
            chunks.append({"kind": "delete", "lines": before_lines[i1:i2]})
        else:  # "replace"
            chunks.append(
                {
                    "kind": "replace",
                    "pairs": _replace_pairs(before_lines[i1:i2], after_lines[j1:j2]),
                }
            )
    return chunks


def _replace_pairs(before: list[str], after: list[str]) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    n = max(len(before), len(after))
    for idx in range(n):
        b = before[idx] if idx < len(before) else None
        a = after[idx] if idx < len(after) else None
        if b is None:
            pairs.append({"before_runs": None, "after_runs": [{"op": "insert", "text": a}]})
        elif a is None:
            pairs.append({"before_runs": [{"op": "delete", "text": b}], "after_runs": None})
        else:
            before_runs, after_runs = _word_runs(b, a)
            pairs.append({"before_runs": before_runs, "after_runs": after_runs})
    return pairs


def _word_runs(before: str, after: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    b_tokens = _WORD_RE.findall(before)
    a_tokens = _WORD_RE.findall(after)
    matcher = difflib.SequenceMatcher(a=b_tokens, b=a_tokens, autojunk=False)
    before_runs: list[dict[str, str]] = []
    after_runs: list[dict[str, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            text = "".join(b_tokens[i1:i2])
            before_runs.append({"op": "equal", "text": text})
            after_runs.append({"op": "equal", "text": text})
        elif tag == "insert":
            after_runs.append({"op": "insert", "text": "".join(a_tokens[j1:j2])})
        elif tag == "delete":
            before_runs.append({"op": "delete", "text": "".join(b_tokens[i1:i2])})
        else:  # "replace"
            before_runs.append({"op": "delete", "text": "".join(b_tokens[i1:i2])})
            after_runs.append({"op": "insert", "text": "".join(a_tokens[j1:j2])})
    return before_runs, after_runs
