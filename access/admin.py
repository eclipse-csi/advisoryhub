from django.contrib import admin

from .models import AdvisoryAccessGrant, PendingInvitation


@admin.register(AdvisoryAccessGrant)
class AdvisoryAccessGrantAdmin(admin.ModelAdmin):
    list_display = ("advisory", "principal_type", "principal_id", "permission", "created_at")
    list_filter = ("permission", "principal_type")
    search_fields = ("advisory__advisory_id",)


@admin.register(PendingInvitation)
class PendingInvitationAdmin(admin.ModelAdmin):
    list_display = ("advisory", "email", "permission", "expires_at", "redeemed_at")
    list_filter = ("permission",)
    search_fields = ("advisory__advisory_id", "email")
    readonly_fields = ("token", "redeemed_at", "redeemed_by")
