#!/usr/bin/env bash
# One-shot kanidm bootstrap for the AdvisoryHub dev environment.
#
# Tested against kanidm/server:latest + kanidm/tools:latest
# (kanidmd 1.10.x as of 2026-05). Idempotent; safe to re-run.
#
# What this does:
#   1. Generates a self-signed TLS cert (openssl, host-side).
#   2. Drops it into the kanidm container's /data volume.
#   3. Fixes ownership to uid 389:389 via a busybox sidecar
#      (kanidm's image is distroless — no shell, no chown).
#   4. (Re)starts kanidm; waits for /status.
#   5. Runs `kanidmd recover-account` for admin + idm_admin and stashes
#      the printed passwords inside the persistent volume.
#   6. Uses a kanidm/tools sidecar to:
#        - log in as idm_admin
#        - relax the idm_all_persons account policy to
#          credential-type-minimum=any (disables the default MFA
#          requirement so password-only auth works in dev)
#        - create three groups + four demo users
#        - create the AdvisoryHub OAuth2 client + redirect + scope map
#        - read the OAuth2 basic secret
#        - emit the idm_admin bearer JWT for the next stage
#   7. Uses a curl sidecar to drive the kanidm credential-update HTTP
#      API and set every demo user's password to $DEMO_PW
#      (default `correcthorsebatterystaple`) non-interactively.
#   8. Writes OIDC_RP_CLIENT_ID + OIDC_RP_CLIENT_SECRET to
#      dev/kanidm/.env.kanidm so docker-compose loads them.
#
# To re-bootstrap from scratch:
#   docker compose down -v && bash dev/kanidm/setup.sh

set -euo pipefail

KANIDM_SERVICE="${KANIDM_SERVICE:-kanidm}"
TOOLS_IMAGE="${TOOLS_IMAGE:-kanidm/tools:latest}"
BUSYBOX_IMAGE="${BUSYBOX_IMAGE:-busybox:stable}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:latest}"
DEMO_PW="${DEMO_PW:-correcthorsebatterystaple}"
ENV_OUT="$(dirname "$0")/.env.kanidm"
COMPOSE="${COMPOSE:-docker compose}"

ec() { printf "\033[36m==>\033[0m %s\n" "$*"; }
warn() { printf "\033[33m[warn]\033[0m %s\n" "$*"; }
fatal() { printf "\033[31m[fatal]\033[0m %s\n" "$*" >&2; exit 1; }

# ---- helpers ------------------------------------------------------------

# Run a one-shot busybox container that mounts kanidm's volumes by
# attaching --volumes-from to the kanidm container. Works whether the
# main container is running, stopped, or crash-looping. Runs as root
# (uid 0) by numeric id since the kanidm image has no /etc/passwd.
in_busybox_root() {
  local cid
  cid="$($COMPOSE ps -q --all "$KANIDM_SERVICE")"
  if [ -z "$cid" ]; then
    fatal "no kanidm container exists yet — run \`docker compose up -d kanidm\` first"
  fi
  docker run --rm --volumes-from "$cid" --user 0:0 "$BUSYBOX_IMAGE" sh -c "$1"
}

# Run a kanidm CLI command authenticated as idm_admin, against the
# running kanidm in the compose network. We cannot keep a persistent
# session across `docker run` invocations (no shared state), so each
# call does its own `kanidm login`. KANIDM_ACCEPT_INVALID_CERTS is set
# because our self-signed cert isn't anchored in any CA bundle.
in_tools() {
  local net cid idm_pwd
  net="$($COMPOSE config --format json 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(iter(d["networks"]))) ' 2>/dev/null \
    || echo "${COMPOSE_PROJECT_NAME:-$(basename "$(pwd)")}_default")"
  cid="$($COMPOSE ps -q --all "$KANIDM_SERVICE")"
  idm_pwd="$2"
  docker run --rm --network "$net" \
    -e KANIDM_URL="https://${KANIDM_SERVICE}:8443" \
    -e KANIDM_ACCEPT_INVALID_CERTS=true \
    -e KANIDM_SKIP_HOSTNAME_VERIFICATION=true \
    --entrypoint /bin/sh "$TOOLS_IMAGE" -c "
      /sbin/kanidm -D idm_admin login --password '$idm_pwd' >/dev/null 2>&1
      $1
    "
}

# ---- 1. Make sure the kanidm container exists ---------------------------

ec "Ensuring kanidm container exists..."
$COMPOSE up -d --no-recreate "$KANIDM_SERVICE" 2>/dev/null || true

# ---- 2. Generate self-signed TLS cert if /data/chain.pem is absent ------

if ! in_busybox_root 'test -f /data/chain.pem' >/dev/null 2>&1; then
  command -v openssl >/dev/null 2>&1 \
    || fatal "openssl is required on the host to generate the dev cert."

  ec "Generating self-signed TLS cert (openssl, host-side)..."
  ec "  using: $(command -v openssl)  ($(openssl version 2>&1))"
  TMP_CERT_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_CERT_DIR"' EXIT

  if ! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:${KANIDM_SERVICE},IP:127.0.0.1" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -keyout "$TMP_CERT_DIR/key.pem" \
        -out    "$TMP_CERT_DIR/chain.pem" 2>"$TMP_CERT_DIR/err.log"; then
    warn "openssl req failed; output below:"
    sed 's/^/  | /' "$TMP_CERT_DIR/err.log" >&2
    fatal "openssl cert generation failed (see output above)"
  fi

  ec "Copying cert + key into the kanidm container's /data volume..."
  $COMPOSE cp "$TMP_CERT_DIR/chain.pem" "${KANIDM_SERVICE}:/data/chain.pem" \
    || fatal "docker compose cp chain.pem failed"
  $COMPOSE cp "$TMP_CERT_DIR/key.pem" "${KANIDM_SERVICE}:/data/key.pem" \
    || fatal "docker compose cp key.pem failed"
fi

# Always fix ownership + permissions — `compose cp` writes as root, but
# kanidm runs as uid 389. Idempotent.
ec "Fixing cert/key ownership + permissions (busybox sidecar)..."
in_busybox_root '
  chown 389:389 /data/chain.pem /data/key.pem 2>/dev/null || true
  chmod 0644 /data/chain.pem
  chmod 0640 /data/key.pem
' || fatal "could not chown/chmod cert/key"

# ---- 3. (Re)start kanidm so it picks up the cert ------------------------

ec "Starting kanidm (force-recreate to drop any cert-less crashed container)..."
$COMPOSE up -d --force-recreate "$KANIDM_SERVICE"

ec "Waiting for kanidm to become healthy..."
for i in $(seq 1 60); do
  if $COMPOSE exec -T "$KANIDM_SERVICE" /sbin/kanidmd --help >/dev/null 2>&1 \
     && in_busybox_root 'wget -qO- --no-check-certificate https://kanidm:8443/status >/dev/null 2>&1 || true' >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    warn "kanidm didn't go healthy within 120s. Last logs:"
    $COMPOSE logs --tail=30 "$KANIDM_SERVICE" >&2
    fatal "kanidm did not become healthy"
  fi
done
# Give the HTTPS listener a moment after the binary is ready.
sleep 3

# ---- 4. Recover admin + idm_admin (one-time) ----------------------------

PASSWD_FILE=/data/.bootstrap-passwords
if ! in_busybox_root "test -f $PASSWD_FILE" >/dev/null 2>&1; then
  ec "Recovering admin and idm_admin one-time passwords..."

  # Output is plain text; extract `new_password: "..."` line.
  ADMIN_OUT="$($COMPOSE exec -T "$KANIDM_SERVICE" /sbin/kanidmd recover-account admin --config-path /data/server.toml 2>&1)"
  IDM_OUT="$($COMPOSE exec -T "$KANIDM_SERVICE" /sbin/kanidmd recover-account idm_admin --config-path /data/server.toml 2>&1)"
  ADMIN_PWD="$(printf '%s\n' "$ADMIN_OUT" | sed -nE 's/.*new_password: "([^"]+)".*/\1/p' | tail -1)"
  IDM_PWD="$(  printf '%s\n' "$IDM_OUT"   | sed -nE 's/.*new_password: "([^"]+)".*/\1/p' | tail -1)"

  if [ -z "$ADMIN_PWD" ] || [ -z "$IDM_PWD" ]; then
    warn "could not parse new_password from recover-account output:"
    printf '%s\n' "$ADMIN_OUT" | sed 's/^/  | /' >&2
    fatal "recover-account output did not match expected pattern"
  fi

  # Stash inside the volume (root-owned, mode 0600).
  in_busybox_root "
    cat > $PASSWD_FILE <<EOF
ADMIN_PWD=$ADMIN_PWD
IDM_PWD=$IDM_PWD
EOF
    chmod 600 $PASSWD_FILE
  " || fatal "could not write $PASSWD_FILE"
fi

# Read passwords back (handles both fresh-bootstrap and re-run cases).
ADMIN_PWD="$(in_busybox_root "grep ^ADMIN_PWD= $PASSWD_FILE | cut -d= -f2-")"
IDM_PWD="$(  in_busybox_root "grep ^IDM_PWD= $PASSWD_FILE | cut -d= -f2-")"
ADMIN_PWD="$(printf '%s' "$ADMIN_PWD" | tr -d '\r\n')"
IDM_PWD="$(printf '%s' "$IDM_PWD" | tr -d '\r\n')"
[ -n "$IDM_PWD" ] || fatal "IDM_PWD is empty after re-read; check $PASSWD_FILE manually"

# ---- 5. Seed groups, users, OAuth2 client via tools sidecar -------------

ec "Configuring groups, users, and OAuth2 client..."

# Locate the actual Docker network (not the compose network *key*) so
# the tools container can resolve `kanidm` by name. The most reliable
# source is the kanidm container itself — it knows what networks it's on.
KANIDM_CID="$($COMPOSE ps -q --all "$KANIDM_SERVICE")"
NET="$(docker inspect "$KANIDM_CID" \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null \
  | head -1)"
if [ -z "$NET" ]; then
  fatal "could not determine docker network for the kanidm container"
fi

TOOLS_SCRIPT='
  set -e
  set -o pipefail
  KANIDM=/sbin/kanidm

  KANIDM_VERSION="$($KANIDM version 2>&1 | head -1 || true)"
  echo "INFO: kanidm tools: $KANIDM_VERSION" >&2
  case "$KANIDM_VERSION" in
    *1.10.*|*1.11.*|*1.12.*) ;;
    *) echo "WARN: untested kanidm version: $KANIDM_VERSION" >&2 ;;
  esac

  $KANIDM -D idm_admin login --password "$IDM_PWD" >/dev/null 2>&1

  # Disable MFA requirement on the global persons group so password-only
  # auth works in dev. idm_all_persons defaults to credential-type-minimum=mfa,
  # which is what forces TOTP enrolment on first login.
  # NEVER do this in production.
  $KANIDM -D idm_admin group account-policy credential-type-minimum \
          idm_all_persons any >/dev/null 2>&1 || true

  # kanidms `<entity> get` returns 0 even when the entity is missing,
  # and `create` returns 409 if it already exists. Idempotent pattern:
  # just try to create, swallow conflict errors.
  for g in advisoryhub-security eclipse-jetty-security eclipse-vert-x-security; do
    $KANIDM -D idm_admin group create "$g" >/dev/null 2>&1 || true
  done

  seed_user() {
    local spn="$1" display="$2" mail="$3"
    $KANIDM -D idm_admin person create "$spn" "$display" >/dev/null 2>&1 || true
    # Always (re)set the primary mail. The Django-side seed_demo identifies
    # users by email, and mozilla-django-oidc rejects logins lacking an
    # `email` claim — so users with no `mail` attribute trigger a redirect
    # loop on the OIDC callback.
    $KANIDM -D idm_admin person update "$spn" -m "$mail" >/dev/null 2>&1 || true
  }
  # SPN → email mapping must match dashboard/management/commands/seed_demo.py.
  seed_user eclipse-admin Eclipse-Security-Admin admin@example.org
  seed_user alice         Alice-Doe              alice@example.org
  seed_user bob           Bob-Smith              bob@example.org
  seed_user carol         Carol-Outsider         carol@example.org

  $KANIDM -D idm_admin group add-members advisoryhub-security    eclipse-admin >/dev/null 2>&1 || true
  $KANIDM -D idm_admin group add-members eclipse-jetty-security  alice         >/dev/null 2>&1 || true
  $KANIDM -D idm_admin group add-members eclipse-vert-x-security bob           >/dev/null 2>&1 || true

  $KANIDM -D idm_admin system oauth2 create advisoryhub "AdvisoryHub" "http://localhost:8000" >/dev/null 2>&1 || true
  $KANIDM -D idm_admin system oauth2 add-redirect-url advisoryhub "http://localhost:8000/oidc/callback/" >/dev/null 2>&1 || true
  # Permit the post-logout landing URL so RP-initiated logout
  # (post_logout_redirect_uri) is accepted by kanidm.
  $KANIDM -D idm_admin system oauth2 add-redirect-url advisoryhub "http://localhost:8000/accounts/signed-out/" >/dev/null 2>&1 || true
  for g in advisoryhub-security eclipse-jetty-security eclipse-vert-x-security; do
    $KANIDM -D idm_admin system oauth2 update-scope-map advisoryhub "$g" openid email profile groups >/dev/null 2>&1 || true
  done

  # show-basic-secret prints just the secret on stdout; some kanidm
  # versions also print warnings to stderr, so 2>/dev/null silences
  # those before the pipeline.
  SECRET="$($KANIDM -D idm_admin system oauth2 show-basic-secret advisoryhub 2>/dev/null | tail -1 | tr -d "\r\n ")"
  echo "OAUTH2_SECRET=$SECRET"

  # Extract the idm_admin bearer JWT for the curl sidecar (next stage).
  # Token cache is a JSON object keyed `<spn>@<domain>`; KANIDM_DOMAIN
  # defaults to `localhost` in this dev compose.
  TOKEN="$(sed -nE '"'"'s/.*"idm_admin@localhost"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p'"'"' \
            "$HOME/.cache/kanidm_tokens" 2>/dev/null | head -1)"
  if [ -z "$TOKEN" ]; then
    echo "FATAL: could not extract idm_admin bearer token from $HOME/.cache/kanidm_tokens" >&2
    echo "       (kanidm token-cache format may have changed across versions)" >&2
    exit 1
  fi
  echo "KANIDM_TOKEN=$TOKEN"
'

# Run with set +e around the docker call so we can surface a useful
# error if the sidecar exits non-zero (otherwise the outer script's
# set -e silently kills before we can validate the output).
set +e
TOOLS_OUTPUT="$(docker run --rm --network "$NET" \
  -e HOME=/root \
  -e KANIDM_URL="https://${KANIDM_SERVICE}:8443" \
  -e KANIDM_ACCEPT_INVALID_CERTS=true \
  -e KANIDM_SKIP_HOSTNAME_VERIFICATION=true \
  -e IDM_PWD="$IDM_PWD" \
  --entrypoint /bin/sh "$TOOLS_IMAGE" -c "$TOOLS_SCRIPT" 2>&1)"
TOOLS_RC=$?
set -e

if [ "$TOOLS_RC" -ne 0 ]; then
  warn "tools sidecar exited $TOOLS_RC. Full output:"
  printf '%s\n' "$TOOLS_OUTPUT" | sed 's/^/  | /' >&2
  fatal "kanidm bootstrap (tools sidecar) failed"
fi

# Echo warnings (drop the secret + bearer token lines — kept in memory only).
printf '%s\n' "$TOOLS_OUTPUT" | grep -vE "^(OAUTH2_SECRET|KANIDM_TOKEN)="

OAUTH2_SECRET="$(printf '%s\n' "$TOOLS_OUTPUT" | sed -nE 's/^OAUTH2_SECRET=(.*)/\1/p')"
if [ -z "$OAUTH2_SECRET" ]; then
  warn "Could not extract OAuth2 secret. Sidecar output was:"
  printf '%s\n' "$TOOLS_OUTPUT" | sed 's/^/  | /' >&2
  fatal "OAuth2 client secret extraction failed"
fi

KANIDM_TOKEN="$(printf '%s\n' "$TOOLS_OUTPUT" | sed -nE 's/^KANIDM_TOKEN=(.*)/\1/p')"
if [ -z "$KANIDM_TOKEN" ]; then
  warn "Could not extract idm_admin bearer token. Sidecar output was:"
  printf '%s\n' "$TOOLS_OUTPUT" | sed 's/^/  | /' >&2
  fatal "idm_admin bearer token extraction failed"
fi

# ---- 5b. Set demo-user passwords via the credential-update HTTP API -----
#
# kanidm 1.10.x has no non-interactive CLI for setting a person's password
# (`kanidm person credential update` always drops into a TTY session). We
# drive the admin-authenticated HTTP API instead:
#   GET  /v1/person/{spn}/_credential/_update      -> [CUSessionToken, CUStatus]
#   POST /v1/credential/_update                    -> body: [CURequest, CUSessionToken]
#   POST /v1/credential/_commit                    -> body: CUSessionToken
# CURequest::Password is an externally-tagged enum, so it serializes as
# {"Password": "<pw>"}. The kanidm/tools image has no curl, so we use a
# curlimages/curl sidecar attached to the same compose network.

ec "Setting demo-user passwords via credential-update API..."

CURL_SCRIPT='
  set -e
  fail() { echo "FATAL: $*" >&2; exit 1; }

  set_password() {
    spn="$1"
    # 1. Begin a credential-update session as idm_admin.
    body="$(curl -sk -H "Authorization: Bearer $TOKEN" \
            -w "\n%{http_code}" \
            "$URL/v1/person/$spn/_credential/_update")"
    code="$(printf "%s" "$body" | tail -n1)"
    payload="$(printf "%s" "$body" | sed "\$d")"
    [ "$code" = "200" ] || fail "begin($spn) HTTP $code: $payload"
    # Response is [CUSessionToken, CUStatus]; CUSessionToken is
    # {"token": "..."}. Extract the first {"token":"..."} object.
    sess="$(printf "%s" "$payload" | sed -nE "s/^\[(\{\"token\":\"[^\"]+\"\}),.*/\1/p")"
    [ -n "$sess" ] || fail "begin($spn): could not extract session token from: $payload"

    # 2. Submit the password.
    out="$(curl -sk -o /tmp/upd.out -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -X POST "$URL/v1/credential/_update" \
            --data-raw "[{\"password\":\"$PW\"},$sess]")"
    [ "$out" = "200" ] || fail "update($spn) HTTP $out: $(cat /tmp/upd.out)"

    # 3. Commit the session.
    out="$(curl -sk -o /tmp/com.out -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $TOKEN" \
            -X POST "$URL/v1/credential/_commit" \
            --data-raw "$sess")"
    [ "$out" = "200" ] || fail "commit($spn) HTTP $out: $(cat /tmp/com.out)"

    echo "password set: $spn"
  }

  for spn in eclipse-admin alice bob carol; do
    set_password "$spn"
  done
'

set +e
CURL_OUTPUT="$(docker run --rm --network "$NET" \
  -e URL="https://${KANIDM_SERVICE}:8443" \
  -e TOKEN="$KANIDM_TOKEN" \
  -e PW="$DEMO_PW" \
  --entrypoint /bin/sh "$CURL_IMAGE" -c "$CURL_SCRIPT" 2>&1)"
CURL_RC=$?
set -e

if [ "$CURL_RC" -ne 0 ]; then
  warn "credential-update sidecar exited $CURL_RC. Full output:"
  printf '%s\n' "$CURL_OUTPUT" | sed 's/^/  | /' >&2
  fatal "kanidm password automation failed"
fi
printf '%s\n' "$CURL_OUTPUT"

# ---- 6. Write .env.kanidm so compose loads OIDC vars next time up -------

cat > "$ENV_OUT" <<EOF
# Generated by dev/kanidm/setup.sh — do not edit by hand.
# Re-run setup.sh to regenerate.
OIDC_RP_CLIENT_ID=advisoryhub
OIDC_RP_CLIENT_SECRET=$OAUTH2_SECRET
EOF

ec "Wrote $ENV_OUT"
ec "Bootstrap complete. Now:"
echo "    docker compose up -d web worker"
echo "    open http://localhost:8000/   # then click 'Sign in'"
echo
ec "All four demo users have password \`$DEMO_PW\`. SPNs accepted at sign-in:"
echo "    eclipse-admin   global admin"
echo "    alice           Eclipse Jetty security team"
echo "    bob             Eclipse Vert.x security team"
echo "    carol           outsider (no project membership)"
