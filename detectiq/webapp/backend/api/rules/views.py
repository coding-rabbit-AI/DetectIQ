from django.db.models import Q
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from detectiq.core.settings.base import get_settings
from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.api.models import StoredRule
from detectiq.webapp.backend.api.rules.serializers import StoredRuleSerializer
from detectiq.webapp.backend.models import SigmaRule
from detectiq.webapp.backend.services.rule_deployment_service import RuleDeploymentService

logger = get_logger(__name__)


class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class RuleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for handling rule operations.
    """

    serializer_class = StoredRuleSerializer
    permission_classes = [AllowAny]
    pagination_class = PageNumberPagination

    def get_queryset(self):
        queryset = StoredRule.objects.all()

        # Get all filter parameters
        enabled = self.request.GET.get("enabled")
        rule_type = self.request.GET.get("type")
        severity = self.request.GET.get("severity")
        integration = self.request.GET.get("integration")
        source = self.request.GET.get("source")

        # Apply filters if they exist
        if enabled is not None:
            queryset = queryset.filter(enabled=enabled.lower() == "true")
        if rule_type:
            queryset = queryset.filter(type__iexact=rule_type)
        if severity:
            queryset = queryset.filter(severity__iexact=severity)
        if integration:
            queryset = queryset.filter(integration__iexact=integration)
        if source:
            queryset = queryset.filter(source=source)

        logger.debug(
            f"Applied filters: enabled={enabled}, type={rule_type}, severity={severity}, integration={integration}, source={source}"
        )
        logger.debug(f"Filtered queryset count: {queryset.count()}")

        return queryset.order_by("-created_at")

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error in list view: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error retrieving rule: {str(e)}")
            return Response({"detail": "Rule not found or error occurred"}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=["post"])
    async def deploy(self, request, pk=None):
        """Deploy rule to integration."""
        try:
            if pk is None:
                return Response({"error": "Rule ID is required"}, status=status.HTTP_400_BAD_REQUEST)

            rule_id = int(pk)  # Convert pk to integer
            integration_type = request.data.get("integration")
            if not integration_type:
                return Response({"error": "Integration type required"}, status=status.HTTP_400_BAD_REQUEST)

            # Get integration settings
            settings = await get_settings(request.user)
            integration_config = getattr(settings.settings.integrations, integration_type, None)

            if not integration_config or not integration_config.enabled:
                return Response(
                    {"error": f"Integration {integration_type} not configured or enabled"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            deployment_service = RuleDeploymentService()
            result = await deployment_service.deploy_sigma_rule(
                rule_id,
                integration_type,
                integration_config,  # Pass the converted integer
            )

            if result["success"]:
                return Response(result, status=status.HTTP_200_OK)
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_serializer(self, *args, **kwargs):
        if self.action == "partial_update":
            kwargs["partial"] = True
        return super().get_serializer(*args, **kwargs)

    # Alternative fix if the above doesn't work:
    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return super().partial_update(request, *args, **kwargs)

    @action(detail=False, methods=["post"])
    def create_rule(self, request):
        try:
            # Extract data from request
            data = request.data

            # Set source based on rule type
            rule_type = data.get("type", "").lower()
            source_mapping = {"sigma": "SigmaHQ", "yara": "YARA-Forge", "snort": "Snort3 Community"}

            # Set source based on whether it's AI-generated or based on rule type
            if data.get("metadata", {}).get("ai_generated", False):
                data["source"] = "DetectIQ"
            else:
                data["source"] = source_mapping.get(rule_type, "DetectIQ")

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error creating rule: {str(e)}")
            return Response({"error": "Failed to create rule", "detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SigmaRuleViewSet(RuleViewSet):
    def get_queryset(self):
        return super().get_queryset().filter(type="sigma")


class YaraRuleViewSet(RuleViewSet):
    def get_queryset(self):
        return super().get_queryset().filter(type="yara")


class SnortRuleViewSet(RuleViewSet):
    def get_queryset(self):
        return super().get_queryset().filter(type="snort")
