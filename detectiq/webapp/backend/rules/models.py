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
        ordering = ["-version"]
        unique_together = ["rule", "version"]

    def __str__(self):
        return f"{self.rule.title} v{self.version}"


from typing import Any, Dict, List, Optional, Tuple

import yaml
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()

# Define types for rule choices
SeverityChoices = List[Tuple[str, str]]
SEVERITY_CHOICES: SeverityChoices = [
    ("informational", "Informational"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]


class BaseRule(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)  # Allow blank descriptions
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="%(class)s_rules",  # Dynamically set related name
    )
    enabled = models.BooleanField(default=True)
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="medium",
    )
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        abstract = True
        app_label = "backend"
        ordering = ["-created_at"]  # Default ordering

    def __str__(self) -> str:
        return f"{self.name} ({self.severity})"


class SigmaRule(BaseRule):
    content = models.TextField()
    mitre_attack_info = models.JSONField(default=dict, blank=True)
    iocs = models.JSONField(default=dict, blank=True)

    @classmethod
    def create_from_content(cls, content: str, created_by, **kwargs) -> "SigmaRule":
        """Create a SigmaRule instance from YAML content."""
        try:
            yaml_content = yaml.safe_load(content)
            if not yaml_content:
                raise ValueError("Empty or invalid YAML content")

            # Extract severity from Sigma rule's level field
            severity = yaml_content.get("level", "medium").lower()
            valid_severities = [choice[0] for choice in SEVERITY_CHOICES]
            if severity not in valid_severities:
                severity = "medium"  # Default if invalid severity

            # Create instance with validated severity
            return cls.objects.create(content=content, created_by=created_by, severity=severity, **kwargs)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML content: {str(e)}")
        except Exception as e:
            raise ValueError(f"Error creating Sigma rule: {str(e)}")

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Override save to update severity from content if it changes."""
        if self.content:
            try:
                yaml_content = yaml.safe_load(self.content)
                if yaml_content:
                    severity = yaml_content.get("level", "medium").lower()
                    valid_severities = [choice[0] for choice in SEVERITY_CHOICES]
                    if severity in valid_severities:
                        self.severity = severity
            except yaml.YAMLError:
                pass  # Keep existing severity if YAML parsing fails
        super().save(*args, **kwargs)

    class Meta:
        app_label = "backend"
        indexes = [
            models.Index(fields=["name", "severity"]),
            models.Index(fields=["created_at"]),
        ]


class YaraRule(BaseRule):
    content = models.TextField()
    file_hash = models.CharField(max_length=64, blank=True)

    def clean(self) -> None:
        """Validate YARA rule content."""
        super().clean()
        if not self.content.strip():
            raise ValueError("YARA rule content cannot be empty")

    class Meta:
        app_label = "backend"
        indexes = [
            models.Index(fields=["file_hash"]),
        ]


class SnortRule(BaseRule):
    content = models.TextField()
    pcap_hash = models.CharField(max_length=64, blank=True)

    def clean(self) -> None:
        """Validate Snort rule content."""
        super().clean()
        if not self.content.strip():
            raise ValueError("Snort rule content cannot be empty")

    class Meta:
        app_label = "backend"
        indexes = [
            models.Index(fields=["pcap_hash"]),
        ]
