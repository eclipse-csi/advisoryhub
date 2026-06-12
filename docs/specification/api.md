# API

Rendered reference for AdvisoryHub's **machine-consumable** HTTP surface: the
internal `/api/` JSON namespace, the GitHub App webhook receiver, the public
project picker, and the health probes. Server-rendered HTML/HTMX UI routes are
deliberately not part of this contract.

The machine-readable source of truth is [`openapi.yaml`](openapi.yaml)
(OpenAPI 3.0.3), kept honest by drift guards in
`api/tests/test_openapi_spec.py`: the document must validate, and every
`/api/` route must match the Django URLconf bidirectionally — paths *and*
methods. `info.version` tracks the application version in lockstep
(`dev/release.sh` bumps it, `dev/check_release_versions.sh` gates it).

Authentication in one line: `/api/` uses the OIDC-established session cookie
(plus the CSRF header on unsafe methods, no API tokens), the webhook uses an
HMAC-SHA256 signature, and the intake picker and health probes are
unauthenticated. Details in the rendered description below and in
[permissions](permissions.md).

[OAD(./docs/specification/openapi.yaml)]
