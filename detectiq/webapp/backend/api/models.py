from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class StoredRule(models.Model):
    """Model for storing detection rules."""

    title = models.CharField(max_length=255)
    content = models.TextField()
    type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    enabled = models.BooleanField(default=True)
    description = models.TextField(blank=True)
    integration = models.CharField(max_length=50, default="manual")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    source = models.CharField(
        max_length=50,
        choices=[
            ("DetectIQ", "DetectIQ"),
            ("SigmaHQ", "SigmaHQ"),
            ("YARA-Forge", "YARA-Forge"),
            ("Snort3 Community", "Snort3 Community"),
        ],
        default="DetectIQ",
    )

    class Meta:
        app_label = "api"
        db_table = "api_stored_rule"
        ordering = ["-created_at"]

    def __str__(self):
        return self.title


class RuleVersion(models.Model):
    """Model for tracking rule versions."""

    rule = models.ForeignKey(StoredRule, related_name="versions", on_delete=models.CASCADE)
    content = models.TextField()
    version = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "api"
        db_table = "api_rule_version"
        ordering = ["-version"]
        unique_together = ["rule", "version"]

    def __str__(self):
        return f"{self.rule.title} v{self.version}"
