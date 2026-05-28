from django.apps import AppConfig


class AdvisoriesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "advisories"

    def ready(self) -> None:
        # Register the post_save safety net for the AdvisoryVersion v1
        # invariant. Importing for side effects is the standard Django
        # signal-registration idiom.
        from . import signals  # noqa: F401
