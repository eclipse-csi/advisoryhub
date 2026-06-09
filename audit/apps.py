from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "audit"

    def ready(self):
        # Connect the Celery metrics signal handlers + worker-local exporter.
        # Lives here (a always-installed, feature-neutral app) rather than in
        # publication/ because the per-task metrics are cross-cutting. Inert in
        # the web process — worker_process_init only fires in Celery workers.
        from common import celery_metrics  # noqa: F401
