from django.contrib import admin

from .models import AdvisoryComment


@admin.register(AdvisoryComment)
class AdvisoryCommentAdmin(admin.ModelAdmin):
    list_display = ("advisory", "author", "created_at", "edited_at", "redacted_at")
    list_filter = ("redacted_at",)
    search_fields = ("advisory__advisory_id", "author__email")
    readonly_fields = ("created_at", "edited_at", "redacted_at", "redacted_by")
