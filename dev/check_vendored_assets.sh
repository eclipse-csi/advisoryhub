#!/usr/bin/env bash
# Verify vendored, upstream-verbatim assets still match their pinned hashes:
#   - static/htmx.min.js                   vs static/htmx.VERSION
#   - static/fonts/Inter*.woff2            vs static/fonts/Inter.VERSION
#   - docs/assets/css/neoteroi-mkdocs.css  vs docs/assets/css/neoteroi-mkdocs.VERSION
#
# These ship on every page (including the public intake form), so an automated
# tamper/staleness check mirrors how publication/schemas/*.upstream.json are
# kept pinned. Run by prek (pre-commit stage) and CI's django-checks job.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

check() {
  local file="$1" expected="$2"
  if [ -z "$expected" ]; then
    echo "ERROR: no expected hash recorded for $file" >&2
    fail=1
    return
  fi
  local actual
  actual=$(sha256_of "$file")
  if [ "$expected" != "$actual" ]; then
    echo "ERROR: $file sha256 mismatch" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    echo "  If you intentionally upgraded, update the matching .VERSION file." >&2
    fail=1
    return
  fi
  echo "OK: $file matches pinned sha256"
}

# htmx.VERSION records the hash on a `sha256:<hash>` line.
check static/htmx.min.js "$(sed -n 's/^sha256://p' static/htmx.VERSION | head -n1)"

# Inter.VERSION lists `<hash>  <filename>` lines; grep the filename, take the hash.
hash_for() { grep -F "$2" "$1" | grep -oE '[0-9a-f]{64}' | head -n1; }
check static/fonts/InterVariable.woff2 \
  "$(hash_for static/fonts/Inter.VERSION InterVariable.woff2)"
check static/fonts/InterVariable-Italic.woff2 \
  "$(hash_for static/fonts/Inter.VERSION InterVariable-Italic.woff2)"

# Docs-site CSS for the OAD-rendered API reference; same `sha256:<hash>` line
# format as htmx.VERSION. Styles essentials-openapi's HTML output (rendered by
# dev/mkdocs_oad_hook.py); re-vendor from upstream if that engine is bumped.
check docs/assets/css/neoteroi-mkdocs.css \
  "$(sed -n 's/^sha256://p' docs/assets/css/neoteroi-mkdocs.VERSION | head -n1)"

exit "$fail"
