from typing import Any, Dict, cast

from asgiref.sync import async_to_sync
from django.db.models import Q
from django.http import QueryDict
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response

from detectiq.core.config.base import get_config
from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.services.rule_deployment_service import RuleDeploymentService
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository
from detectiq.webapp.backend.utils.decorators import async_action

from .models import RuleVersion, StoredRule
from .serializers import StoredRuleSerializer

logger = get_logger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class RuleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing detection rules."""

    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    serializer_class = StoredRuleSerializer
    pagination_class = PageNumberPagination

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rule_repository = DjangoRuleRepository()

        # Initialize settings
        self.detectiq_config = async_to_sync(get_config)().config

    def get_queryset(self):
        """Get filtered queryset based on request parameters."""
        try:
            queryset = StoredRule.objects.all()

            # Apply filters
            filters = self._get_filters()
            if filters:
                queryset = queryset.filter(**filters)

            # Apply search
            search_query = self.request.GET.get("search")
            if search_query:
                queryset = queryset.filter(
                    Q(title__icontains=search_query)
                    | Q(description__icontains=search_query)
                    | Q(content__icontains=search_query)
                )

            # Apply enabled filter
            enabled = self.request.GET.get("enabled")
            if enabled is not None:
                queryset = queryset.filter(enabled=enabled.lower() == "true")

            return queryset.order_by("-created_at")
        except Exception as e:
            logger.error(f"Error in get_queryset: {e}")
            return StoredRule.objects.none()

    def _get_filters(self) -> Dict[str, Any]:
        """Extract filters from query parameters."""
        filters = {}
        params = cast(DRFRequest, self.request).GET

        filter_fields = {
            "type": "type__iexact",
            "severity": "severity__iexact",
            "integration": "integration__iexact",
            "source": "source__iexact",
        }

        for param, filter_name in filter_fields.items():
            value = params.get(param)
            if value:
                filters[filter_name] = value

        return filters

    @async_action(detail=True, methods=["post"])
    async def deploy(self, request, pk=None):
        """Deploy rule to integration."""
        try:
            if pk is None:
                return Response({"error": "Rule ID is required"}, status=status.HTTP_400_BAD_REQUEST)

            integration_type = request.data.get("integration")
            if not integration_type:
                return Response({"error": "Integration type required"}, status=status.HTTP_400_BAD_REQUEST)

            integration_config = getattr(self.detectiq_config.integrations, integration_type, None)

            if not integration_config or not integration_config.enabled:
                return Response(
                    {"error": f"Integration {integration_type} not configured or enabled"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            deployment_service = RuleDeploymentService()
            result = await deployment_service.deploy_sigma_rule(int(pk), integration_type, integration_config)

            return Response(result, status=status.HTTP_200_OK if result["success"] else status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=["post"])
    def create_version(self, request: DRFRequest, pk: str | None = None) -> Response:
        """Create a new version for a rule."""
        try:
            rule = get_object_or_404(StoredRule.objects.prefetch_related("versions"), pk=pk)
            latest_version = RuleVersion.objects.filter(rule=rule).order_by("-version").first()
            new_version_number = (latest_version.version + 1) if latest_version else 1
            content = cast(Dict[str, Any], request.data).get("content", "")

            version = RuleVersion.objects.create(rule=rule, content=content, version=new_version_number)

            return Response({"version": version.version}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error creating rule version: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_serializer_context(self) -> Dict[str, Any]:
        """Add extra context to serializer."""
        context = super().get_serializer_context()
        context["request"] = self.request
        return context

    def list(self, request: DRFRequest) -> Response:
        """List rules with optional filters."""
        try:
            enabled = request.GET.get("enabled")
            filter_type = request.GET.get("type")

            filters = {}
            if enabled is not None:
                filters["enabled"] = enabled.lower() == "true"
            if filter_type:
                filters["type"] = filter_type

            queryset = self.get_queryset().filter(**filters)

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response({"count": queryset.count(), "results": serializer.data})

        except Exception as e:
            logger.error(f"Error listing rules: {e}")
            return Response({"error": f"Error loading rules: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request):
        logger.info(f"Creating new rule with data: {request.data}")
        return super().create(request)

    def _process_request_data(self, request: DRFRequest) -> Dict[str, Any]:
        """Process request data from either JSON or form data."""
        if isinstance(request.data, QueryDict):
            return dict(request.data.items())
        return cast(Dict[str, Any], request.data)
