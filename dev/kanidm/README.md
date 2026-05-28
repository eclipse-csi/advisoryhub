# Kanidm dev OIDC bundle

This directory wires a [Kanidm](https://kanidm.com/) IDM into the
AdvisoryHub `docker-compose.yml` so the **real** mozilla-django-oidc
authentication path runs in dev — no `force_login` shortcut, no faked
sessions. We pick Kanidm because it's a single Rust binary
(~30 MB image) and feels light for a local dev IDP.

## One-time setup

```sh
docker compose up -d kanidm
bash dev/kanidm/setup.sh
cat dev/kanidm/.env.kanidm >> .env       # or: source dev/kanidm/.env.kanidm
docker compose up -d web worker
```

Then open <http://localhost:8000/>, click **Sign in**, and pick a demo user.

`setup.sh` is idempotent — re-running it is safe and only does work that
hasn't already been done. To **reset from scratch** (wipes all kanidm
state including users, passwords, OAuth2 clients):

```sh
docker compose rm -sf kanidm
docker volume rm advisoryhub_kanidm-data
bash dev/kanidm/setup.sh
```

## Demo users

All four demo users get the password **`correcthorsebatterystaple`** by default. They
mirror what `python manage.py seed_demo` creates on the Django side, so
the OIDC group claim flows naturally into Django group membership.

| SPN | Group | What they can do |
| --- | --- | --- |
| `eclipse-admin@example.org` | `advisoryhub-security` | Global admin/security team |
| `alice@example.org` | `eclipse-jetty-security` | Eclipse Jetty security team member |
| `bob@example.org` | `eclipse-vert-x-security` | Eclipse Vert.x security team member |
| `carol@example.org` | (none) | Outsider — sees only published advisories |

To change passwords, re-run `setup.sh` with `DEMO_PW` set — it idempotently
re-applies the same password to every demo user via the kanidm credential-
update HTTP API:

```sh
DEMO_PW=hunter2 bash dev/kanidm/setup.sh
```

## Why MFA is disabled in the dev IDM

Kanidm's default account policy on `idm_all_persons` sets
`credential-type-minimum=mfa`, which forces every person to enrol TOTP
before they can sign in. `setup.sh` relaxes that to `any` so the dev flow
is password-only (matching what `seed_demo` and `CLAUDE.md` document).

**This is a dev-only convenience.** Never replicate this relaxation in a
production kanidm deployment — it removes the second factor for every
human account.

## Why HTTPS is mandatory and the cert is self-signed

Kanidm refuses to start without TLS, even for `localhost`. `setup.sh`
generates a self-signed cert/key pair **with openssl on the host**
(not via `kanidmd cert-generate`) and copies it into the container's
`/data` volume. We use openssl rather than the kanidm CLI because:

* The CLI surface for cert generation has shifted between kanidm
  releases — the `cert-generate` subcommand isn't in every version.
* The kanidm container runs as a non-root user (uid 389 on the
  official image); `kanidmd cert-generate` writing into a root-owned
  `/data` volume sometimes fails silently.
* openssl is observable: if something goes wrong, you can inspect the
  resulting `chain.pem`/`key.pem` without learning kanidm internals.

The cert's Subject Alternative Names cover **both** `localhost` (so the
host browser can hit `https://localhost:8443/oauth2/authorise` during
the OIDC redirect) and `kanidm` (so the web container can hit
`https://kanidm:8443/oauth2/token` for the server-side calls). That
dual-name is also why kanidm's auto-generated cert wouldn't have been
sufficient — it only carries `KANIDM_DOMAIN`, which is `localhost`.

The web container points `OIDC_VERIFY_SSL=False` so it trusts the
self-signed cert without us having to import it into the system trust
store. **Don't carry `OIDC_VERIFY_SSL=False` into production** — set
it back to `True` and use a real cert.

## Why `setup.sh` and not "just spin up the container"

Kanidm's first-time bootstrap is unavoidably a multi-step dance:

1. `kanidmd cert-generate` — needs to run before the server can serve.
2. `kanidmd recover-account admin` (and `idm_admin`) — generates one-time
   passwords printed to stdout. There is no way to set them via env var.
3. `kanidm login` against the running server using one of those one-time
   passwords.
4. `kanidm system oauth2 create …` etc. to seed the realm.

`setup.sh` automates all of that and stashes the recovery passwords
inside the container's volume so re-runs don't have to redo the
account-recovery step (which is one-shot per Kanidm lifetime).

## Known gotchas

- The kanidm CLI has no non-interactive password setter (every version
  through 1.10.x drops into a TTY session). `setup.sh` works around this
  by driving the `/v1/person/<spn>/_credential/_update` HTTP API directly
  with curl. If the request shape changes in a future kanidm release the
  bootstrap will fail loudly with the HTTP body — adjust the curl payload
  in `setup.sh` accordingly.
- If you hit "redirect URI not allowed" errors at sign-in time,
  inspect `kanidm system oauth2 show advisoryhub` and confirm the
  `http://localhost:8000/oidc/callback/` redirect is registered.
- If the bootstrap can't extract the recovery password from
  `kanidmd recover-account` output (the JSON shape has changed
  between versions), re-run those commands manually inside the
  container and stash the passwords in `/data/.bootstrap-passwords`
  with the same `ADMIN_PWD=…` / `IDM_PWD=…` shape `setup.sh` expects.
