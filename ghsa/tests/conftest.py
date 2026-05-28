"""Test fixtures for the ghsa app.

Two extras on top of the project-wide ``conftest.py``:

* ``ghsa_settings`` — pre-populates the GitHub App settings with sentinel
  values so anything reading from ``django.conf.settings`` finds a
  coherent configuration. Tests that don't touch the live client don't
  need this; tests that exercise ``get_client`` do.

* ``ghsa_payload`` — a representative GHSA REST payload that the
  translator + services tests share.
"""

from __future__ import annotations

import pytest

from ghsa.client import reset_client_for_tests


@pytest.fixture
def ghsa_settings(settings, db):
    """Configure GitHub App settings for the test session.

    Also pre-populates a single ``GitHubAppInstallation`` row for the
    ``eclipse`` org so Phase-1 tests (which assume one default install)
    keep passing without any env-var fallback. Tests that exercise
    multi-installation routing add additional rows on top.
    """
    from ghsa.models import GitHubAppAccountType, GitHubAppInstallation

    settings.GHSA_FEATURE_ENABLED = True
    settings.GITHUB_APP_ID = 12345
    settings.GITHUB_APP_API_BASE_URL = "https://api.github.com"
    settings.GITHUB_APP_PRIVATE_KEY_PATH = ""
    settings.GITHUB_APP_PRIVATE_KEY = _TEST_RSA_PRIVATE_KEY
    settings.GITHUB_APP_WEBHOOK_SECRET = "test-webhook-secret"
    GitHubAppInstallation.objects.update_or_create(
        installation_id=67890,
        defaults={
            "account_login": "eclipse",
            "account_type": GitHubAppAccountType.ORGANIZATION,
        },
    )
    reset_client_for_tests()
    yield settings
    reset_client_for_tests()


@pytest.fixture
def ghsa_payload():
    return {
        "ghsa_id": "GHSA-abcd-1234-efgh",
        "cve_id": None,
        "html_url": "https://github.com/eclipse/example/security/advisories/GHSA-abcd-1234-efgh",
        "url": "https://api.github.com/repos/eclipse/example/security-advisories/GHSA-abcd-1234-efgh",
        "summary": "Path traversal in example library",
        "description": "A path traversal vulnerability exists in the file handler.",
        "severity": "high",
        "state": "published",
        "cvss": {
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "score": 7.5,
        },
        "cwes": [{"cwe_id": "CWE-22", "name": "Path Traversal"}],
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-abcd-1234-efgh"},
        ],
        "references": ["https://example.org/fix"],
        "credits_detailed": [
            {"user": {"login": "reporter1"}, "type": "reporter"},
        ],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "maven", "name": "org.example:library"},
                "vulnerable_version_range": ">= 1.0.0, < 1.2.3",
                "patched_versions": "1.2.3",
            }
        ],
    }


# RSA key generated only for the ghsa test suite. Not used for any
# real-world auth and exists only so the JWT minting path can round-trip
# during tests.
_TEST_RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA23KAZTU4uvLGAoeK3SMFp28O1h/0qislk8AODs48usuQL9L0
EDlk5rwolUbHsFcyjsVuOcidEkwGJCUe1oR3Y/v6t4WbZMTwT4meb6L1Sr+szliJ
zblMv/UuwTR8cWnsX+uUc2esJHuJcTl2cx1IpteNsZKpRU3hTzSbiGBftKvTsIg0
cB9C223xRltjfX68nUcnkNaInlj4fkeS/yVhrv6jGZFoI//URLqmOYVOUdAqOnoU
U6NCrLBdIIbR+NiFhB+tNqYBE61k11Ytb8fCaaWbcnMxLB1vwzMnENQzvUOUczBK
66teQAS9sedvdV+H8WPFwM8+hMt6M6KWkd0QJwIDAQABAoIBAD3PG2DmQ6tMU/9E
ZBVzFtWZD0m6SHRhoLzj3FHJPwux6FPADCRBtizTFG8vN3FwrfnOnAREgBE2PoiR
uATd3K7Zuz1TsXgJjFIqxehVstcx859PCslaBscObPPYL7DWD9DYjsCOk8rWzNiK
QdWciukLT4qTb3/otqxTefdIhcxiD3ZTDdFltYEQiO6SMtORB513haXlELOkLs+w
A+pGSisJVF5qxT3Ofk3jBPFumpdGRXdJ76h1efIpdnq65cB+95HvTFYRI5oB9OFi
zgr/ogk2LbXRDXhsZJHAWiF92zWZ6sHu9eqkQ7BVxo86qYKbL4ZcHHuwlLza7bXa
XUg8B0kCgYEA/VRFoyJfRLVATvqhGgEcCXY/xtPcdGHFJerF1pLmLSXPGn+K0PZ2
T0CQgiqopfDQ520ltLvxhmtpIrLuV5iTiczzhH1Gg0lDU4ymszIu4GUXD071GztT
V6RreRlDyBrLeoPrtht0N2x4Qxo3KpvUzAIqz7dPtpFqBJHmgjLYPeMCgYEA3cLI
giAPQMbjAdlL2JlUzQ1UFVfEm4A63P5IiJ6kd6e+v61iZDBiSKs4kQfyo5wbXL4O
AUfg91OGC0Inbbjy8yHZ9M8ZNcTmmFNGQ7nZqZpD3cFZEQZGFFF4gWjUNtSk1hsD
Zq2Y0s1e7A0f4wfvwED/JSpPcVpN098r4togN+0CgYBpDQ5HpRROoL8HQWWXLAid
X9z4rZiI5pZjr+TUo1wyMrCcc3F0UBAls0d5wwjmr2Nh5OAy/5EbxeT2T68IwivE
hCojsfOQs8volLX4L4JC6YjTf1GjNknMWVF8CV8TVxE0QAp6HQ5ngWKpqPBhifeH
lgp80q6KreiB9qLZMQ59MwKBgHvKh/Nbwif+3iniCxzWOyhcEFv5qp7Dbhh/Oi5J
oLXKxghp2UrkV3kJW4JaVXBPbFbRITBF16c40NLoEuqFG9ntQ6YNFZ2WVMMjeU3F
KWQr4Uag7/846VXeRM64nf4dpgZ+/d8LeQvz6NEMYohxnbxMjCFLBR3ZsyhapDz2
VpXhAoGAFmcAcowZohh1uLjG0gj2Suw3iKyJr9YsQvO9PHs7GTKr/SMY4F4W7bR/
bFn5KgZiAhYxP+u8jkkwdVz2InUIj9klJ+c8aLc13EgyZ+LpcrsVs1LOsy+jfCKr
5TswxSiIDDpgeAxjZtwohAVzbY1A4VfWEPy3QJg/48kJbqauE1M=
-----END RSA PRIVATE KEY-----
"""
