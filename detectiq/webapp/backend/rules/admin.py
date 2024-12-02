from django.contrib import admin

from .models import RuleVersion, StoredRule


@admin.register(StoredRule)
class StoredRuleAdmin(admin.ModelAdmin):
    list_display = ("title", "type", "severity", "integration", "enabled", "user")
    list_filter = ("type", "severity", "integration", "enabled")
    search_fields = ("title", "description", "content")
    ordering = ("-created_at",)


@admin.register(RuleVersion)
class RuleVersionAdmin(admin.ModelAdmin):
    list_display = ("rule", "version", "created_at")
    list_filter = ("rule__type", "created_at")
    search_fields = ("rule__title", "content")
    ordering = ("-created_at",)
