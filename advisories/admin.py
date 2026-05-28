from django.contrib import admin

from .models import Advisory, AdvisoryVersion


@admin.register(Advisory)
class AdvisoryAdmin(admin.ModelAdmin):
    list_display = ("advisory_id", "project", "state", "review_status", "published_at")
    list_filter = ("state", "review_status", "project")
    search_fields = ("advisory_id", "summary")
    readonly_fields = ("created_at", "modified_at", "published_at")

    def has_delete_permission(self, request, obj=None) -> bool:
        return False

    def get_actions(self, request):
        # Strip the bulk "Delete selected" action entirely so it does not
        # render in the changelist dropdown.
        actions = super().get_actions(request)
        actions.pop("delete_selected", None)
        return actions


@admin.register(AdvisoryVersion)
class AdvisoryVersionAdmin(admin.ModelAdmin):
    list_display = ("advisory", "version", "editor", "created_at")
    search_fields = ("advisory__advisory_id",)

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
