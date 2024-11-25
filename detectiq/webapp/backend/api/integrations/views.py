from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated


class IntegrationViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        # Implementation for listing integrations
        pass

    def create(self, request):
        # Implementation for creating integration
        pass

    def retrieve(self, request, pk=None):
        # Implementation for retrieving integration
        pass

    def update(self, request, pk=None):
        # Implementation for updating integration
        pass

    def destroy(self, request, pk=None):
        # Implementation for deleting integration
        pass
