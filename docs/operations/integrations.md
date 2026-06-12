# Integrations

AdvisoryHub talks to five external systems. The first two are required; the last
three are optional and off by default. Variable defaults are in
[configuration.md](./configuration.md).

---

## 1. OIDC identity provider

Authentication and **group membership** both flow from your OIDC provider;
AdvisoryHub stores a mirror and never the authority ([INV-OIDC-2](../specification/invariant.md#inv-oidc-2)).

**Register a confidential client** for each environment and configure:

- **Redirect URI:** `https://<host>/oidc/callback/`
- **Post-logout redirect:** `https://<host>/accounts/signed-out/`
- **Scopes:** AdvisoryHub requests `openid email profile groups`.
- **PKCE:** enabled (`S256`) by default — keep it on.

Then set the endpoints (from the provider's discovery document) and client
credentials: `OIDC_OP_AUTHORIZATION_ENDPOINT`, `OIDC_OP_TOKEN_ENDPOINT`,
`OIDC_OP_USER_ENDPOINT`, `OIDC_OP_JWKS_ENDPOINT`, `OIDC_RP_CLIENT_ID`,
`OIDC_RP_CLIENT_SECRET`, and `OIDC_RP_SIGN_ALGO` (match the provider's token
signing algorithm).

**Model the groups.** The provider must emit a **`groups`** claim
(`OIDC_GROUP_CLAIM`) listing each user's groups. On every login AdvisoryHub
replaces the user's local groups from that claim ([INV-OIDC-1](../specification/invariant.md#inv-oidc-1)) and recomputes
admin status:

- The **admin group** named by `OIDC_ADMIN_GROUP` (default `advisoryhub-security`)
  grants global admin — owner on every advisory, the exclusive reviewer, and Django
  `is_staff`/`is_superuser` ([INV-OIDC-3](../specification/invariant.md#inv-oidc-3)).
- Each **project security team** is a group referenced by the project's row; its
  members are owners of that project's advisories. Create one group per team and
  point the project at it (in-app, after first run).

**Logout.** Set `OIDC_OP_LOGOUT_ENDPOINT` to the provider's `end_session_endpoint`
for RP-initiated logout (AdvisoryHub stores the ID token so it can pass
`id_token_hint`). Left empty, "Sign out" ends only the local session — and with a
live SSO session at the provider the next protected page silently re-authenticates.

**Step-up.** Publishing (and GitHub-App changes) require a fresh re-login
(`STEP_UP_REQUIRED`, within `STEP_UP_MAX_AGE_SECONDS`). The provider must honour
the re-prompt; otherwise users can't publish.

> **Worked example (dev).** `dev/kanidm/setup.sh` registers the `advisoryhub`
> client against the bundled Kanidm with exactly the redirect URIs above, creates
> the `advisoryhub-security` admin group and two project-team groups, and writes the
> client secret into `dev/kanidm/.env.kanidm`. It uses `ES256` and self-signed TLS
> (`OIDC_VERIFY_SSL=False`) — both dev-only.

---

## 2. Publication Git repository

Publishing builds OSV + CSAF (and, for CVE-assigned advisories, a CVE record) and
**pushes them to an external Git repository** whose own CI renders the public
site. Configure `PUB_REPO_URL` and `PUB_REPO_BRANCH`, choose an auth mode, and set
the CVE-assigner identity. The worker image ships `git` + `openssh-client`.

### SSH mode (`PUB_REPO_AUTH=ssh`) — recommended

- Use an SSH URL (`git@github.com:eclipse/advisories.git`).
- Mount the deploy **private key** as a file and point `PUB_REPO_SSH_KEY_PATH` at
  it (e.g. `/run/secrets/pub_repo_ssh_key`).
- AdvisoryHub points git's `GIT_SSH` hook at a per-publication generated
  wrapper that execs `ssh -i <key> -o IdentitiesOnly=yes -o
  StrictHostKeyChecking=accept-new -o BatchMode=yes`. (`GIT_SSH` is exec'd
  directly by git; `GIT_SSH_COMMAND` would be run through a shell, which
  the production image doesn't have.)
- `accept-new` trusts the remote host key on first contact. For strict checking,
  **pre-populate a `known_hosts`** (e.g. bake one into the image) so a changed host
  key is rejected.

### Token mode (`PUB_REPO_AUTH=token`)

- Use an HTTPS URL (`https://github.com/eclipse/advisories.git`).
- Set `PUB_REPO_TOKEN` to a push-capable token. AdvisoryHub rewrites the URL to
  `https://x-access-token:<token>@…` at push time and **strips the token from
  every error, audit, artifact, and notification surface** — it is never persisted.

### Output paths & CVE identity

`PUB_OSV_PATH_TEMPLATE`, `PUB_CSAF_PATH_TEMPLATE`, and `PUB_CVE_PATH_TEMPLATE`
control where files land (placeholders `{year}`, `{advisory_id}`, `{bucket}`,
`{cve_id}`). To publish a **CVE-assigned** advisory you **must** set
`PUB_CVE_ASSIGNER_ORG_ID` to the Eclipse Foundation CNA's v4 UUID — publishing
fails loudly while it is empty. `PUB_CVE_ASSIGNER_SHORT_NAME` defaults to `eclipse`.

> Set `READYZ_INCLUDE_PUB_REPO=True` to have `/readyz` verify the remote is
> reachable (a `git ls-remote`) — useful as a deploy gate, off by default because
> it egresses on every probe.

---

## 3. GHSA / GitHub App (optional)

Off unless `GHSA_FEATURE_ENABLED=True`. AdvisoryHub authenticates to GitHub as a
**registered GitHub App** to read/write GitHub Security Advisories.

1. **Register a GitHub App** with permissions `repository_security_advisories:
   read & write` (plus the default `metadata: read`). Org admins install it on the
   relevant repositories.
2. Configure `GITHUB_APP_ID`, mount the App **private key** as a file via
   `GITHUB_APP_PRIVATE_KEY_PATH` (preferred; `GITHUB_APP_PRIVATE_KEY` inline is a
   dev-only fallback), and set `GITHUB_APP_WEBHOOK_SECRET`.
3. **Webhook:** point the App's webhook at `https://<host>/ghsa/webhook/`. Inbound
   deliveries are HMAC-verified against `GITHUB_APP_WEBHOOK_SECRET` and rejected
   otherwise. (This path stays reachable during maintenance mode, since it is
   machine traffic, not a user action.)
4. **Installations** are stored in the database — after enabling, run
   **`python manage.py discover_github_installations`** once to populate the
   registry, or wait for the first `installation.created` webhook.

The Eclipse PMI API (`PMI_API_BASE_URL`, usually unauthenticated) is the
source-of-truth for the project↔repository mapping the beat task mirrors. GHSA-linked
advisories' content is read-only in AdvisoryHub and re-homed only by PMI sync
([INV-GHSA-1](../specification/invariant.md#inv-ghsa-1)).

---

## 4. Security-team roster sync (optional)

Off unless `PMI_ROSTER_SYNC_ENABLED=True`. This pre-provisions **notification-only
"shadow" users** for each project's Eclipse security-team members, so `@team`
mentions and team notifications reach members who have **never logged in**.

- It needs the **authenticated** Eclipse API (the public PMI feed hides member
  emails): set `ECLIPSE_API_CLIENT_ID` and `ECLIPSE_API_CLIENT_SECRET` (OAuth2
  client-credentials), with `ECLIPSE_API_TOKEN_URL` / `ECLIPSE_API_BASE_URL` /
  optional `ECLIPSE_API_SCOPE`.
- The beat task `projects.tasks.run_roster_sync` runs every
  `PMI_ROSTER_SYNC_INTERVAL_HOURS` (and no-ops while disabled); trigger it by hand
  with **`python manage.py sync_roster --all`**.
- A shadow user holds **no authorization** — it is in no group and can act on
  nothing. On first OIDC login it is linked by email, the provisioned flag clears,
  and access then comes entirely from the OIDC group claim; the roster never grants
  access ([INV-OIDC-5](../specification/invariant.md#inv-oidc-5), [INV-ROSTER-1](../specification/invariant.md#inv-roster-1)).

---

## 5. Similarity LLM provider (optional)

Off unless `SIMILARITY_CHECK_ENABLED=True`. LLM-assisted duplicate detection
compares new reports against the project's existing advisories and surfaces
candidate duplicates (owner-only, on the advisory page).

> **Enabling the switch is the consent** for advisory content — including
> potentially embargoed drafts — to be sent to the configured LLM provider on
> every check ([INV-SIM-2](../specification/invariant.md#inv-sim-2)). Leave it off if that egress is not acceptable.

- **Provider**: `SIMILARITY_LLM_PROVIDER=anthropic` (default, needs
  `SIMILARITY_LLM_API_KEY`) or `openai` — which covers any OpenAI-compatible
  endpoint. For **on-prem inference**, set `SIMILARITY_LLM_PROVIDER=openai` and
  point `SIMILARITY_LLM_BASE_URL` at a local server (Ollama, vLLM, LM Studio);
  the API key may be blank for keyless local servers.
- **Where it runs**: on the **worker** tier, as the Celery task
  `similarity.run_similarity_check` — the egress to the provider comes from the
  worker, not web, and there is no beat entry. Size network policy / proxy rules
  accordingly.
- **When it fires**: automatically on public intake submissions and on GHSA sync.
  It is best-effort — a failed or timed-out check never fails intake or sync.
- **Rollout**: after enabling, run **`python manage.py backfill_fingerprints`**
  once so existing advisories enter the candidate corpus (one LLM call per
  advisory; idempotent — see [maintenance.md §4](./maintenance.md#4-management-command-reference)).
- **Tuning**: `SIMILARITY_LLM_TIMEOUT` (read timeout), `SIMILARITY_CANDIDATE_LIMIT`
  (prefilter cap per check), `SIMILARITY_MIN_CONFIDENCE` (persistence threshold) —
  defaults in [configuration.md §11](./configuration.md#11-llm-duplicate-detection-similarity).

---

## Related pages

- [configuration.md](./configuration.md) — the variables referenced here.
- [running-in-production.md](./running-in-production.md) — health probes, beat schedule.
- [../specification/architecture.md](../specification/architecture.md) — the publication and GHSA pipelines in depth.
