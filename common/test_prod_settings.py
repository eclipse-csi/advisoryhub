"""Tests for the production startup guards in ``config.settings._guards``.

A bare-metal / docker-compose-prod deploy that forgets to set
``DJANGO_SECRET_KEY`` lands on the well-known development default (the env()
default in ``base.py``). Booting production with that key lets anyone forge
session cookies, CSRF tokens, and other signed values, so ``prod.py`` calls
``require_production_secret_key`` at import time to fail closed. Django's
``security.W009`` only warns (under ``check --deploy``, advisory-only) and
never fails the boot, which is why this guard exists.

These exercise the pure guard directly — no DB, no settings reload — so they
run under any settings module.
"""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured

from config.settings._guards import (
    INSECURE_SECRET_KEY_DEFAULT,
    require_production_secret_key,
)


@pytest.mark.parametrize("bad_key", ["", INSECURE_SECRET_KEY_DEFAULT])
def test_rejects_empty_and_default_secret_key(bad_key: str):
    with pytest.raises(ImproperlyConfigured, match="DJANGO_SECRET_KEY"):
        require_production_secret_key(bad_key)


def test_accepts_a_real_secret_key():
    # A genuine, unique key passes without raising.
    require_production_secret_key("x" * 50)
