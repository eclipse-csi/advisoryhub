from django.contrib import admin

from .models import CveRequestTask, ReviewTask


@admin.register(CveRequestTask)
class CveRequestTaskAdmin(admin.ModelAdmin):
    list_display = ("advisory", "status", "cve_id", "assignee", "created_at", "finished_at")
    list_filter = ("status",)
    search_fields = ("advisory__advisory_id", "cve_id")


@admin.register(ReviewTask)
class ReviewTaskAdmin(admin.ModelAdmin):
    list_display = ("advisory", "status", "reviewer", "created_at", "decided_at")
    list_filter = ("status",)
    search_fields = ("advisory__advisory_id",)
