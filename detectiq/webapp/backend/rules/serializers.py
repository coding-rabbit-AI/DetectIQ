from rest_framework import serializers

from .models import RuleVersion, StoredRule


class RuleVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleVersion
        fields = ["id", "content", "version", "created_at"]


class StoredRuleSerializer(serializers.ModelSerializer):
    versions = RuleVersionSerializer(many=True, read_only=True)
    name = serializers.SerializerMethodField()

    class Meta:
        model = StoredRule
        fields = [
            "id",
            "title",
            "content",
            "type",
            "severity",
            "enabled",
            "description",
            "created_at",
            "updated_at",
            "metadata",
            "integration",
            "versions",
            "name",
            "source",
            "package_type",
            "mitre_tactics",
            "mitre_techniques",
        ]
        read_only_fields = ("created_at", "updated_at")

    def get_name(self, obj):
        """Map title to name for frontend compatibility."""
        return obj.title

    def create(self, validated_data):
        # Set source based on rule type if not provided
        if "source" not in validated_data:
            rule_type = validated_data.get("type", "").lower()
            source_mapping = {"sigma": "SigmaHQ", "yara": "YARA-Forge", "snort": "Snort3 Community"}
            validated_data["source"] = source_mapping.get(rule_type, "DetectIQ")

            # If this is an AI-generated rule
            if validated_data.get("metadata", {}).get("ai_generated", False):
                validated_data["source"] = "DetectIQ"

        return super().create(validated_data)
