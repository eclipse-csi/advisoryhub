"""MkDocs hook: render [OAD(path)] tags to Markdown via essentials-openapi.

Replaces the neoteroi-mkdocs ``neoteroi.mkdocsoad`` plugin with a thin local
hook (registered through mkdocs.yml ``hooks:``) so the docs toolchain depends
only on the essentials-openapi rendering engine. Behaviour is identical: same
OAD tag syntax, the MKDOCS output style (pymdownx tabbed schema views, matching
the old ``use_pymdownx: true``), and the same vendored CSS.

That engine (``openapidocs.mk``) imports rich, jinja2 and httpx at module load —
even though our local-file ``[OAD(...)]`` never exercises the http path. They live
under essentials-openapi's ``[full]`` extra, which also pins ``click~=8.1.3``; to
keep that cap off the runtime ``click``, the ``docs`` extra in pyproject.toml pins
rich/jinja2/httpx directly rather than pulling ``essentials-openapi[full]``.
"""

import re
from pathlib import Path

from openapidocs.mk.v3 import OpenAPIV3DocumentationHandler
from openapidocs.utils.source import read_from_source

_OAD = re.compile(r"\[OAD\(([^)]+)\)\]")


def _render(match, cwd):
    source = match.group(1).strip("'\"")
    data = read_from_source(source, cwd)
    handler = OpenAPIV3DocumentationHandler(data, style="MKDOCS", source=source)
    return handler.write()


def on_page_markdown(markdown, page, **kwargs):
    if "[OAD(" not in markdown:
        return markdown
    cwd = (Path(page.file.src_dir) / page.file.src_path).parent
    return _OAD.sub(lambda m: _render(m, cwd), markdown)
