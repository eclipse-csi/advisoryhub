from django.contrib import admin

from .models import Project


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "security_team", "is_mature_publisher")
    list_filter = ("is_mature_publisher",)
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
