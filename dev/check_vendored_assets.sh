#!/usr/bin/env bash
# Verify vendored, upstream-verbatim assets still match their pinned hashes.
#
# Right now that is the htmx bundle: static/htmx.min.js must match the sha256
# recorded in static/htmx.VERSION. This mirrors how publication/schemas/*.upstream.json
# are kept pinned, and gives us an automated tamper/staleness check for a script
# that ships on every page (including the public intake form). Run by prek
# (pre-commit stage) and CI's django-checks job.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

check_sha256() {
  local file="$1" version_file="$2"
  local expected actual
  expected=$(sed -n 's/^sha256://p' "$version_file" | head -n1)
  if [ -z "$expected" ]; then
    echo "ERROR: could not read sha256 from $version_file" >&2
    fail=1
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | cut -d' ' -f1)
  else
    actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
  fi
  if [ "$expected" != "$actual" ]; then
    echo "ERROR: $file sha256 mismatch" >&2
    echo "  expected ($version_file): $expected" >&2
    echo "  actual   ($file):        $actual" >&2
    echo "  If you intentionally upgraded, update $version_file." >&2
    fail=1
    return
  fi
  echo "OK: $file matches pinned sha256 ($expected)"
}

check_sha256 static/htmx.min.js static/htmx.VERSION

exit "$fail"
