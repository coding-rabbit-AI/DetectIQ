from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from detectiq.webapp.backend.models.workflows import Workflow

from .serializers import WorkflowSerializer


class WorkflowViewSet(viewsets.ModelViewSet):
    queryset = Workflow.objects.all()
    serializer_class = WorkflowSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
