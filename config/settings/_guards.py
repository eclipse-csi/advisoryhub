"""Startup guards for production settings.

Kept dependency-light (only ``django.core.exceptions``) and free of any
settings import so it can be pulled into both ``base`` (for the sentinel
default) and ``prod`` (for the guard) without an import cycle, and unit-tested
in isolation.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

# The development / unset default for ``DJANGO_SECRET_KEY``. Single source of
# truth: ``base.py`` uses it as the env() default so a bare-metal deploy that
# forgets to set the var lands on exactly this value, and the production guard
# below rejects it. Keep the two in lockstep by importing this constant rather
# than duplicating the literal.
INSECURE_SECRET_KEY_DEFAULT = "insecure-change-me"


def require_production_secret_key(secret_key: str) -> None:
    """Refuse to boot production with the dev-default / empty ``SECRET_KEY``.

    Running with the well-known development key lets anyone forge session
    cookies, CSRF tokens, and other signed values (auth bypass). Django's
    ``security.W009`` only *warns*, and only under ``check --deploy`` — nothing
    fails the actual boot — so we fail closed here instead.
    """
    if not secret_key or secret_key == INSECURE_SECRET_KEY_DEFAULT:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set to a unique, secret value in "
            "production; the development default is not permitted."
        )
