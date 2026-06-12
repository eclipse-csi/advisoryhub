# Releasing AdvisoryHub

This is the **maintainer** runbook for cutting a release. (Deploying a released
version is covered by the [operations manual](../operations/README.md).)

A release is one signed git tag `vX.Y.Z` that produces, automatically:

| Artifact | Where | Built by |
|---|---|---|
| Container image `X.Y.Z` / `X.Y` (+ SBOM & SLSA provenance attestations, keyless cosign signature) | `ghcr.io/mbarbero/advisoryhub` | `.github/workflows/release-image.yml` |
| Helm chart `X.Y.Z` (keyless cosign signature) | `oci://ghcr.io/mbarbero/charts/advisoryhub` | `.github/workflows/release.yml` |
| GitHub release with git-cliff notes + chart `.tgz`, CycloneDX dependency SBOM, `checksums.txt` | repo **Releases** page | `.github/workflows/release.yml` |

## The version lockstep rule

One version, recorded in four places, all of which must agree (and match the
tag): `pyproject.toml` `[project] version`, the `advisoryhub` root package in
`uv.lock`, and `version` + `appVersion` in `charts/advisoryhub/Chart.yaml`
(`image.tag` defaults to `appVersion`, so the chart pulls its own release's
image). `dev/check_release_versions.sh` (`mise run release-check`) asserts
this; `release.yml` runs it as its first gate. **Never bump `pyproject.toml`
without `uv lock`** — the lock records the root version and a stale one fails
every `uv sync --locked`. (`mise run release` does all of this for you.)

## Prerequisites

- Push rights to `main`, and your SSH **signing** key loaded (`ssh-add -l`) —
  the release commit and tag are signed (`-S`) per the commit policy.
- A clean tree on `main` (untracked files like `TODO.md` are fine).
- The toolchain: `mise install` (git-cliff, trivy, helm ride `mise.toml`).

## Cutting a release

```sh
mise run release -- X.Y.Z
```

This bumps every recorded version in lockstep (`uv version` handles
pyproject + uv.lock atomically), re-syncs to prove the lock is sound, runs the
version gate, previews the git-cliff notes, then creates the signed
`chore(release): vX.Y.Z` commit and the signed `vX.Y.Z` tag. Nothing is
pushed. Review, then:

```sh
git push origin main vX.Y.Z
```

The tag triggers both release workflows in parallel:

1. **Release image** builds the production image, smoke-tests it under an
   arbitrary UID, gates on Trivy, pushes to ghcr.io with SBOM + provenance,
   and cosign-signs it.
2. **Release** gates the versions, renders the notes, **waits for the image**
   (polls ghcr.io up to ~20 min — a failed image build fails the release run,
   so a GitHub release never exists without its image), pushes + signs the
   chart, and creates the GitHub release.

## Verifying a release

```sh
# Image and chart signatures (identities are also in the release notes):
cosign verify ghcr.io/mbarbero/advisoryhub:X.Y.Z \
  --certificate-identity-regexp 'https://github.com/mbarbero/advisoryhub/\.github/workflows/release-image\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify ghcr.io/mbarbero/charts/advisoryhub:X.Y.Z \
  --certificate-identity-regexp 'https://github.com/mbarbero/advisoryhub/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The chart installs from the OCI ref:
helm pull oci://ghcr.io/mbarbero/charts/advisoryhub --version X.Y.Z

# Release attachments match their checksums (in the downloaded assets dir):
sha256sum -c checksums.txt
```

## When something fails

- **Image build failed** (smoke test, Trivy gate): the Release run fails at
  the wait-for-image poll. Fix the problem; if the fix needs new commits, the
  tag must move — see "re-tagging" below. If the failure was transient, re-run
  the *Release image* workflow for the tag, then re-run *Release*.
- **Release run failed after the image published** (chart push, gh release):
  fix and re-run the *Release* workflow — every step is idempotent-safe to
  retry except `gh release create` (delete the partial release first).

### Re-tagging (the fix needed new commits)

A tag that has been pushed may have been fetched by others — prefer a new
patch version when in doubt. To redo `vX.Y.Z` anyway:

```sh
gh release delete vX.Y.Z --yes                       # if it was created
git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z
# ghcr.io cleanup (image + chart package versions, incl. cosign sig tags):
gh api /user/packages/container/advisoryhub/versions --paginate   # find ids
gh api -X DELETE /user/packages/container/advisoryhub/versions/<id>
gh api -X DELETE "/user/packages/container/charts%2Fadvisoryhub/versions/<id>"
# then fix, and run `mise run release -- X.Y.Z` again
```

### First chart push

The first push to `oci://ghcr.io/mbarbero/charts` creates a brand-new ghcr
package; package creation in a *user* namespace via `GITHUB_TOKEN`
occasionally 403s. If it does: push once with a PAT
(`helm registry login ghcr.io` + `helm push`), grant the repo **write** access
in the package settings, delete the manual version, and re-run the workflow.
