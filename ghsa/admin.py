from django.contrib import admin

from .models import GhsaCvePushTask, GhsaSyncRun, GitHubAppInstallation, WebhookDelivery


@admin.register(GhsaCvePushTask)
class GhsaCvePushTaskAdmin(admin.ModelAdmin):
    list_display = ("advisory", "cve_id", "status", "attempts", "finished_at")
    list_filter = ("status",)
    search_fields = ("cve_id", "advisory__advisory_id")


@admin.register(GhsaSyncRun)
class GhsaSyncRunAdmin(admin.ModelAdmin):
    list_display = ("scope", "project", "status", "started_at", "advisories_created")
    list_filter = ("scope", "status")


@admin.register(GitHubAppInstallation)
class GitHubAppInstallationAdmin(admin.ModelAdmin):
    list_display = ("account_login", "installation_id", "account_type", "suspended_at")
    search_fields = ("account_login", "installation_id")
    list_filter = ("account_type",)


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = ("delivery_id", "event", "action", "status", "received_at")
    list_filter = ("event", "status")
    search_fields = ("delivery_id",)
