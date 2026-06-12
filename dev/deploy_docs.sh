#!/usr/bin/env bash
# Deploy the documentation site into the LOCAL gh-pages branch with mike:
#
#   dev/deploy_docs.sh dev       -> version "dev" (rolling main snapshot)
#   dev/deploy_docs.sh vX.Y.Z    -> version "X.Y.Z" + alias "latest"
#                                   + root redirect (mike set-default)
#
# mike appends one commit to gh-pages (creating the branch if absent); each
# version lives in its own directory and is never overwritten by other
# versions' deploys. Nothing is pushed — mirrors dev/release.sh: the docs
# workflow (.github/workflows/docs.yml) pushes gh-pages with its own
# credentials. Inspect locally with `git show gh-pages --stat`; discard with
# `git branch -D gh-pages`.
set -euo pipefail
cd "$(dirname "$0")/.."

REF="${1:-}"
if [ "$REF" = "dev" ]; then
  uv run --locked --extra docs mike deploy dev
elif [[ "$REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  VERSION="${REF#v}"
  # --update-aliases moves "latest" off the previous release; the previous
  # release's own directory stays untouched.
  uv run --locked --extra docs mike deploy --update-aliases "$VERSION" latest
  uv run --locked --extra docs mike set-default latest
else
  echo "usage: dev/deploy_docs.sh dev|vX.Y.Z (got '${REF}')" >&2
  exit 1
fi
