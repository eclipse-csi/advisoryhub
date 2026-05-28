"""Audit redaction covers the new GHSA-era token shapes."""

from __future__ import annotations

from audit.services import redact_secrets


def test_redact_pem_private_key_block():
    msg = (
        "configuration error: -----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEogIBAAKCAQEA23KAZTU4uvLGAoeK3SMFp28O1h/0qisl...\n"
        "-----END RSA PRIVATE KEY-----\nthe rest is harmless"
    )
    out = redact_secrets(msg)
    assert "BEGIN" not in out
    assert "MIIEogIB" not in out
    assert "the rest is harmless" in out
    assert "***" in out


def test_redact_github_installation_token():
    msg = "Authorization header had ghs_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa in it"
    out = redact_secrets(msg)
    assert "ghs_aaaaaaaaa" not in out
    assert "***" in out


def test_redact_github_personal_access_token():
    msg = "leaked: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAA1234567890"
    out = redact_secrets(msg)
    assert "ghp_AAAA" not in out


def test_redact_oauth_user_to_server_token():
    msg = "Bearer gho_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb worked"
    out = redact_secrets(msg)
    assert "gho_bbbb" not in out


def test_redact_jwt_shape():
    jwt_like = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    out = redact_secrets(f"signed: {jwt_like}")
    assert "eyJhbGci" not in out


def test_redact_json_private_key_field():
    msg = '{"foo": 1, "private_key": "secretvalue", "bar": 2}'
    out = redact_secrets(msg)
    assert "secretvalue" not in out
    # Surrounding shape preserved enough to be useful.
    assert "private_key" in out
    assert "foo" in out
