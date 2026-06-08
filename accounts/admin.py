from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import NotificationPreference, User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    ordering = ("email",)
    list_display = ("email", "display_name", "is_staff", "is_superuser")
    search_fields = ("email", "display_name", "oidc_subject")
    # Ban metadata is read-only here: the audited toggle (with session kill +
    # is_active coupling) lives in the admin console (INV-AUTH-8). Surfaced for
    # visibility only.
    readonly_fields = ("banned_at", "banned_by", "ban_reason")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Profile", {"fields": ("display_name", "first_name", "last_name", "oidc_subject")}),
        (
            "Permissions",
            {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")},
        ),
        ("Ban (managed by admin console)", {"fields": ("banned_at", "banned_by", "ban_reason")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = ((None, {"classes": ("wide",), "fields": ("email", "password1", "password2")}),)


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = ("user", "on_advisory_created", "on_advisory_published", "comments_level")
