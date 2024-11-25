from rest_framework import serializers

from detectiq.webapp.backend.models.workflows import Workflow


class WorkflowSerializer(serializers.ModelSerializer):
    class Meta:
        model = Workflow
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at", "created_by")
