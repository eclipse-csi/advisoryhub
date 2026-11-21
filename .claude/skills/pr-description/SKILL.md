---
name: pr-description
description: Write the description of an AdvisoryHub pull request from the template .github/pull_request_template.md, as a draft, for the exact diff reviewers will see. Fill each section from evidence (the diff, the checks that ran on it, the security review that covers it), map the change to the INV-* invariants and the specification files it must update, classify the type of change and breaking changes with AdvisoryHub's criteria, and leave every box unticked until the evidence supports it. Use it when asked to write, prepare or update the description of a PR, or before opening one. Nothing is posted to GitHub unless the user asks.
---

# Write a pull request description

Draft the description for the exact diff reviewers will see. Reuse test results and review findings only when they
still apply to that diff. Leave each checkbox unticked until the evidence supports it.

The rules every pull request must follow are in `.specify/memory/constitution.md` (principles and quality gates),
`docs/specification/invariant.md` (the `INV-*` catalog) and `CLAUDE.md` (commit policy, checks, releases). The
description follows `.github/pull_request_template.md`: read it, since this skill maps its sections but does not
copy them.

## Ground rules

- **Only evidence.** Every statement and every ticked box comes from the diff, from a check that ran on that diff,
  or from the user. When you do not know, leave the box unticked or ask.
- **Tested means run.** Only the result of a run that happened justifies ticking a test or a manual-testing box. A
  manual test on the dev stack or a chart install on a cluster counts only when the user reports it or asks you to
  run it.
- **A draft.** Write the description in the reply, or in a file the user names. Open or update the pull request
  (`gh pr create --title <title> --body-file <file>`, `gh pr edit`) only when the user asks.
- **A public repository.** `eclipse-csi/advisoryhub` is public, and so is the description. It never contains
  embargoed vulnerability details, real advisory content or identifiers from a deployment, a reporter's identity, a
  token, the dev OIDC client secret (`dev/kanidm/.env.kanidm`) or a value from a local `.env`. `seed_demo` data and
  its `@example.org` users are fine. If the change fixes an undisclosed vulnerability in AdvisoryHub itself, or a
  review finding reveals one in released code, stop and ask the user before drafting: the vulnerability is
  coordinated privately first, and a public description must not disclose it.
- **The security review gate.** When the diff touches an area governed by a Critical-tier invariant (step 2), the
  description reports a security review that covers its exact diff. Reuse a review only if it covers that diff,
  with the same base (see "Reuse" in step 1). Otherwise:
    - for a change planned with Spec Kit, Principle IX makes `/speckit-security-review-branch` mandatory: run it;
    - for any other change, offer to run it; if the user declines, the Security review section says that none ran.

  A finding that is neither fixed nor dispositioned with a maintainer's approval keeps the pull request from being
  ready (Principle IX): you may still draft the description, and it exposes the open finding.

## 1. Define the diff and collect the evidence

`<base>` is the branch the pull request targets, usually `main` of `eclipse-csi/advisoryhub`.

```shell
git rev-parse HEAD
git log --format='%h %s' <base>..HEAD
git diff <base>...HEAD                                       # read it in full, not only --stat
git status --short                                           # local changes are not in the pull request yet
# existing pull request only:
gh pr view <number> -R eclipse-csi/advisoryhub --json title,body,headRefOid,baseRefName
gh pr diff <number> -R eclipse-csi/advisoryhub
```

- **The target diff.** For a new pull request, it is `git diff <base>...HEAD`. For an existing pull request, it is
  its remote diff (`gh pr diff`), whatever `HEAD` is; compare `headRefOid` with `git rev-parse HEAD` to see whether
  the checkout matches it. Use the local diff instead only when the user explicitly prepares the description of a
  future push, and tell them that the draft becomes true once it is pushed.
- **Uncommitted changes** are not covered by the SHA of `HEAD`. If the draft depends on some of them, list them
  separately.
- **The evidence** for that diff: the issue it addresses (from the user, the branch or the commits; never guessed),
  the checks that ran with their results, the checks that were skipped with the reason, the security review report,
  and, for a change planned with Spec Kit, its feature directory (`specs/<NNN-feature>/`: `spec.md`, `plan.md`,
  `tasks.md`, `red-team-findings-*.md`).
- **Reuse.** Reuse a review verdict only when it covers the exact target diff, with the same base. Reuse a check
  result only when the code, configuration, dependencies and migrations relevant to that check are unchanged,
  shared code included: a view test depends on `advisories/permissions.py` as much as on the view. The test database
  is kept between runs (`--reuse-db`): after a migration change, only a run with `--create-db` counts. Otherwise,
  rerun the check or report it as unverified for this draft.

## 2. Map the change to the specification

- **Invariants.** For each changed file, search its path in `docs/specification/invariant.md`: each entry names its
  enforcement points under "Enforced in." and its tests under "Tests.", and its tier in its heading (`[Critical]`,
  `[High]`, `[Medium]`). Read the entries that match and keep the invariants the change enforces, changes or relies
  on; a path match alone is not enough. The load-bearing rules in `CLAUDE.md` point at the most common ones.
- **Specification files.** A behavior change updates, in the same pull request, the file that describes it:
  `invariant.md` (rules), `permissions.md` (capabilities per role, state-conditioned overrides),
  `advisory-lifecycle.md` (states and transitions), `architecture.md` (layout, pipelines, Celery beat schedule,
  env-var inventory), `requirements.md` (functional requirements, use cases), `openapi.yaml` (machine-consumable
  endpoints). A refactoring that moves an enforcement point or a test an invariant names makes its "Enforced in." or
  "Tests." lines stale: that is a specification update too. A missing update is a defect (Principle I): tell the
  user instead of ticking the box, and edit the specification only if they ask.
- **Critical tier.** A Critical-tier invariant in the list triggers the security review gate.
- **Constitution checks** that depend on the diff, reported under Notes for reviewers when they fail:
    - a new or changed configuration knob (`config/settings/base.py`) reaches every surface the constitution lists;
    - migrations stay backward-compatible one release back (`docs/operations/deploy-kubernetes.md` §5);
    - templates and static files follow the strict CSP (Principle VII);
    - vendored assets change only through `dev/update_vendored_assets.py`;
    - workflows keep the zizmor conventions (`CLAUDE.md`, "Workflow conventions");
    - `advisories` does not import `workflows` at module level.

  A conflict with Principles II–V (NON-NEGOTIABLE) admits no waiver: say that the pull request is not ready.

## 3. Fill the sections

Keep the headings of the template, in its order. The HTML comments of the template can be removed.

- **Title**: propose a Conventional Commit, `<type>(<scope>)!: <summary>`. The type is one of the groups of
  `cliff.toml` (`feat`, `fix`, `perf`, `refactor`, `docs`, `style`, `test`, `build`, `ci`, `chore`); the scope is the
  app or area the history already uses (`advisories`, `publication`, `ghsa`, `ui`, `admin_console`, `spec`, …);
  `!` marks a breaking change. A squash merge turns the title into the commit that git-cliff writes into the
  release notes.
- **Description**: what the change does and why, for a reviewer who has not seen the conversation. Start with the
  effect on the people who see it (reporter, security team, collaborator / viewer, global admin, operator, the
  publication repository and its website), then the internals. Describe the final state of the branch, not how you
  got there.
- **Related issue**: `Fixes #<n>` when the change closes the issue, `Relates to #<n>` otherwise. Without a known
  issue, remove the line rather than leave `Fixes #`.
- **Type of change**: tick what applies. A change is **breaking** when users, operators or consumers must act, or
  get a different result without changing anything:
    - a role gains or loses a capability, or a state-conditioned override changes (`permissions.md`);
    - a transition of the lifecycle, review, CVE-request or publication-task machines changes
      (`advisory-lifecycle.md`);
    - a new required setting, a renamed or removed setting or Helm value, or a changed default;
    - a migration that is not backward-compatible one release back, or that needs data work or a maintenance window;
    - the OSV / CSAF payload or the file layout pushed to the publication repository changes, which its CI and
      website consume;
    - an endpoint, field, parameter or status code of `/api/`, the GHSA webhook or the health probes is renamed or
      removed (`openapi.yaml`);
    - a new OIDC claim requirement or group mapping that can block logins or change who gets which role;
    - a management command operators script (`prune_audit`, `forget_user`, …) changes its options or output.

  Tick "Security hardening" when the change closes a gap without changing legitimate use; when it also changes
  legitimate use, it is breaking too. Tick "Build, CI, Helm chart or dependencies" for `.github/workflows/`,
  `Dockerfile`, `docker/`, `charts/advisoryhub/`, `mise.toml`, `pyproject.toml` / `uv.lock`.
- **Breaking change details**: what breaks, who is affected, and the migration path (settings, chart values,
  migrations, data, deploy order). Remove the section for a change that is not breaking. The release notes come from
  the commits through git-cliff: there is no changelog file to edit.
- **Specification & invariants**: keep this section in every case.
    - List the invariants from step 2, each with a few words on how the change relates to it, or "none".
    - Name the Spec Kit feature directory, or remove the line.
    - Tick "Specification updated" with the files and sections, or "No behavior change" when the diff changes no
      behavior and leaves no specification line stale.
    - Tick the deviation box only with a link to the maintainer's confirmation, from the user.
- **Security review**: keep it when the diff touches a Critical-tier area, remove it otherwise.
    - Tick the review only with a report that covers this diff: the command (`/speckit-security-review-branch`,
      `/security-review`), the commit it covers, its verdict and the count of findings by severity.
    - For each finding: fixed (with the commit), accepted (with the maintainer who approved it and the
      justification, from the user, never assumed), or open.
    - When no review ran, leave the box unticked and say so.
    - The red-team line applies to a Spec Kit feature that meets a trigger criterion: give the report path and
      whether every finding is dispositioned, or the waiver recorded in `plan.md`. Remove it otherwise.
- **Tests**: keep this section in every case.
    - Tick "Tests added / updated" and list the test files, or tick "No test added" and say why (documentation only,
      CI configuration). A behavior change without a test that fails without it falls short of Principle VI: say so
      rather than tick a box. Claim that a test fails without the change only if it ran against the base.
    - List the checks that ran on this diff with their result (`mise run test` or the `pytest` targets, `lint`,
      `typecheck`, `check`, `makemigrations-check`, `check-templates`, `check-imports`, `verify-vendor`,
      `docs-build`, `helm-lint`, `helm-validate`, `zizmor`, or the `prek` stages), and the ones skipped, with the
      reason. Report the publication tests that pytest skipped because `git` was missing.
    - The test settings strip OIDC, disable rate limiting and step-up authentication, and run Celery tasks eagerly.
      A change to one of those areas needs its dedicated `@override_settings` tests or a manual test: say which.
    - Under "Manual testing", tick "Dev stack" only with the result of a run, and name the demo users with their
      role and the flows exercised. Tick the chart box only with a live install or upgrade, and its details. Tick
      "Not tested manually" otherwise.
- **How to reproduce / test scenario**: steps a reviewer can follow. Prefer the tests that reproduce the behaviour
  (`mise run test -- <path>::<test>`). Dev-stack steps use the `seed_demo` users, and name the feature flags the
  scenario needs (`SIMILARITY_CHECK_ENABLED`, `GHSA_FEATURE_ENABLED`, `PMI_ROSTER_SYNC_ENABLED`, `STEP_UP_REQUIRED`).
  A step that needs an external service (LLM provider, GitHub, Eclipse API) says so, without its credentials.
- **Screenshots**: required when the change affects `templates/`, the CSS or JS under `static/`, or the e-mail
  notifications. Ask the user for them, or keep the section with a note that they are missing. They show
  `seed_demo` data only. Remove the section otherwise.
- **Checklist**: each item mixes a change and a check; report both against the actual wording of the template. An
  item that does not apply stays unticked, followed by "not applicable".
    - Documentation: tick it when `docs/` was updated as the change needs and `mise run docs-build` passed on this
      diff. If the docs changed but the build did not run, leave it unticked and say so.
    - API contract: tick it when `openapi.yaml` follows the endpoint change and `api/tests/test_openapi_spec.py`
      passed.
    - Configuration knob: compare the settings in the diff with every surface of the item. Tick it only when all
      were updated; otherwise list the missing ones. A secret goes to the expected keys of the env Secret, documented
      in the chart README, never to the ConfigMap.
    - Migrations: tick it when the migration files are in the diff, `makemigrations-check` passed, and you read them
      for compatibility with the previous release (no dropped or renamed column it still reads, no new non-null
      column without a default).
    - CSP: tick it when the diff to templates and static files follows Principle VII and `check-templates` passed.
    - Commits: check every commit of the pull request, since a rebase merge keeps them as they are.
      `git log --format='%G? %h %s%n%(trailers:key=Signed-off-by)%(trailers:key=Assisted-by)' <base>..HEAD` shows
      them; `%G?` is `N` for an unsigned commit, and `E` for a signature git cannot verify locally (no
      `gpg.ssh.allowedSignersFile`), which GitHub verifies on the pull request. No commit carries a `Co-Authored-By`
      trailer.
- **Notes for reviewers**: the security review verdict when the section above does not give it, the risky areas,
  the design decisions, the deviations from a principle that admits one with the maintainer's approval, the
  behaviour that depends on configuration (feature flags off by default, `PUB_REPO_AUTH=ssh|token`,
  `STEP_UP_REQUIRED`, the OIDC provider), what was not tested, and a suggested review order for a large change.

## 4. Check the draft

- Every ticked box matches evidence for this diff, and every section that does not apply is removed, except
  Specification & invariants and Tests.
- The draft meets the public-repository rule: no secret, no real advisory content, no reporter or deployment detail.
  It names a real person only when the user gives the name for the description.
- The draft says which commit it describes, and whether it depends on changes that are not pushed yet.

Present the title and the draft to the user, with the open questions (missing issue, screenshots, manual test
details, maintainer confirmations, dispositions of security findings).
