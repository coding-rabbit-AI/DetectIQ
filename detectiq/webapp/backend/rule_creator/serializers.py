from rest_framework import serializers


class RuleCreatorSerializer(serializers.Serializer):
    description = serializers.CharField(required=False, allow_blank=True)
    type = serializers.ChoiceField(choices=["sigma", "yara", "snort"], default="sigma")
    file = serializers.FileField(required=False)

    def validate(self, data):
        """
        Check that either description or file is provided.
        """
        if not data.get("description") and not data.get("file"):
            raise serializers.ValidationError("Either description or file is required")
        return data
