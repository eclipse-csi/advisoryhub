from django.contrib import admin

from .models import AccessLogEntry, AuditLogEntry


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "advisory")
    list_filter = ("action",)
    search_fields = ("action", "actor__email")
    readonly_fields = (
        "actor",
        "action",
        "advisory",
        "comment_id",
        "previous_value",
        "new_value",
        "metadata",
        "ip_address",
        "user_agent",
        "created_at",
    )

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(AccessLogEntry)
class AccessLogEntryAdmin(admin.ModelAdmin):
    """Read-only view of the retention-managed access log.

    Like the ledger admin, mutation is disabled here; the access log has no
    ``previous_value``/``new_value``/``comment_id`` columns, and retention is
    handled by the partition-maintenance task, not by per-row admin deletes.
    """

    list_display = ("created_at", "actor", "action", "advisory")
    list_filter = ("action",)
    search_fields = ("action", "actor__email")
    readonly_fields = (
        "actor",
        "action",
        "advisory",
        "metadata",
        "ip_address",
        "user_agent",
        "created_at",
    )

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
