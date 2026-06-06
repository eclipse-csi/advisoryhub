from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"

    def ready(self) -> None:
        # Register signal receivers (logout auditing) by importing for side
        # effects — the standard Django idiom, mirroring advisories/apps.py.
        # Login / step-up auditing is registered separately via
        # accounts.step_up (imported by config.urls).
        from . import signals  # noqa: F401
