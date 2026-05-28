from django.contrib import admin

from .models import PublicationArtifact, PublicationRepositoryConfig, PublicationTask


@admin.register(PublicationTask)
class PublicationTaskAdmin(admin.ModelAdmin):
    list_display = ("advisory", "status", "attempts", "created_at", "finished_at", "commit_sha")
    list_filter = ("status",)
    search_fields = ("advisory__advisory_id", "commit_sha")
    readonly_fields = ("created_at", "started_at", "finished_at", "celery_task_id", "commit_sha")


@admin.register(PublicationArtifact)
class PublicationArtifactAdmin(admin.ModelAdmin):
    list_display = ("task", "kind", "path", "created_at")
    list_filter = ("kind",)


@admin.register(PublicationRepositoryConfig)
class PublicationRepositoryConfigAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "repo_url", "branch", "auth_method")
    list_filter = ("is_active", "auth_method")
