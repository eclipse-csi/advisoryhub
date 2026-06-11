from django.contrib import admin

from .models import AdvisoryFingerprint, SimilarityCandidate, SimilarityCheck


class SimilarityCandidateInline(admin.TabularInline):
    model = SimilarityCandidate
    extra = 0
    readonly_fields = ("matched_advisory", "confidence", "rationale", "rank")
    can_delete = False


@admin.register(SimilarityCheck)
class SimilarityCheckAdmin(admin.ModelAdmin):
    list_display = ("advisory", "status", "attempts", "candidate_pool_size", "created_at")
    list_filter = ("status",)
    search_fields = ("advisory__advisory_id",)
    readonly_fields = (
        "created_at",
        "started_at",
        "finished_at",
        "celery_task_id",
        "candidate_pool_size",
        "provider",
        "model",
    )
    inlines = [SimilarityCandidateInline]


@admin.register(AdvisoryFingerprint)
class AdvisoryFingerprintAdmin(admin.ModelAdmin):
    list_display = ("advisory", "provider", "model", "updated_at")
    search_fields = ("advisory__advisory_id",)
    readonly_fields = ("created_at", "updated_at")
