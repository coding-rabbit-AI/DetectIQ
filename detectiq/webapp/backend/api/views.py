import asyncio
import os
import re
import tempfile
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Type, Union, cast

import keyring
import yaml
from asgiref.sync import async_to_sync, sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import UploadedFile
from django.db.models import Q, QuerySet
from django.http import HttpRequest, QueryDict
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from pydantic import SecretStr
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response

from detectiq.core.integrations import get_integration
from detectiq.core.integrations.base import BaseSIEMIntegration, SIEMCredentials
from detectiq.core.integrations.elastic import ElasticCredentials
from detectiq.core.integrations.microsoft_xdr import MicrosoftXDRCredentials
from detectiq.core.integrations.splunk import SplunkCredentials
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.tools.sigma.create_sigma_rule import CreateSigmaRuleTool
from detectiq.core.llm.tools.snort.create_snort_rule import CreateSnortRuleTool
from detectiq.core.llm.tools.yara.create_yara_rule import CreateYaraRuleTool
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.settings import settings_manager
from detectiq.core.settings.base import get_settings
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.pcap_analyzer import PcapAnalyzer
from detectiq.core.utils.yara.file_analyzer import FileAnalyzer
from detectiq.core.utils.yara.rule_scanner import YaraScanner
from detectiq.globals import DEFAULT_DIRS
from detectiq.webapp.backend.api.models import RuleVersion, StoredRule
from detectiq.webapp.backend.services.rule_deployment_service import RuleDeploymentService
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

from .rules.serializers import StoredRuleSerializer

User = get_user_model()

# Initialize logger
logger = get_logger(__name__)


def async_action(detail=False, methods=None, url_path=None, **kwargs):
    """Decorator to handle async actions in DRF viewsets."""

    def decorator(func):
        @action(detail=detail, methods=methods, url_path=url_path, **kwargs)
        @wraps(func)
        def wrapped(viewset, request, *args, **kwargs):
            try:
                # Set new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                # Run the async function and get result
                result = async_to_sync(func)(viewset, request, *args, **kwargs)

                # Clean up
                loop.close()
                return result

            except Exception as e:
                logger.error(f"Error in async action: {str(e)}")
                raise

        return wrapped

    return decorator


class RuleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing detection rules."""

    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    serializer_class = StoredRuleSerializer
    pagination_class = PageNumberPagination

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rule_repository = DjangoRuleRepository()

        # Initialize LLM and embeddings
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
        self.embeddings = OpenAIEmbeddings()

        # Initialize vector stores
        self.sigmadb = self._init_vector_store("sigma")
        self.yaradb = self._init_vector_store("yara")
        self.snortdb = self._init_vector_store("snort")

    def _init_vector_store(self, rule_type: str):
        """Initialize vector store for given rule type."""
        try:
            from langchain_community.vectorstores import FAISS

            vector_store_path = settings.VECTOR_STORE_DIRS[rule_type]
            # Load FAISS vector store from disk
            if Path(vector_store_path).exists():
                return FAISS.load_local(str(vector_store_path), self.embeddings, allow_dangerous_deserialization=True)
            return None
        except Exception as e:
            logger.error(f"Error initializing {rule_type} vector store: {e}")
            return None

    def get_queryset(self) -> QuerySet[StoredRule]:
        """Get filtered queryset based on request parameters."""
        try:
            queryset = StoredRule.objects.all()

            # Apply filters
            filters = self._get_filters()
            if filters:
                queryset = queryset.filter(**filters)

            # Apply search if present
            search_query = self.request.GET.get("search")
            if search_query:
                queryset = queryset.filter(
                    Q(title__icontains=search_query)
                    | Q(description__icontains=search_query)
                    | Q(content__icontains=search_query)
                )

            # Apply enabled filter separately since it needs boolean conversion
            request = cast(DRFRequest, self.request)
            enabled = request.GET.get("enabled")
            if enabled is not None:
                queryset = queryset.filter(enabled=enabled.lower() == "true")

            return queryset.order_by("-created_at")
        except Exception as e:
            logger.error(f"Error in get_queryset: {e}")
            return StoredRule.objects.none()

    def _get_filters(self) -> Dict[str, Any]:
        """Extract filters from query parameters."""
        filters: Dict[str, Any] = {}
        request = cast(DRFRequest, self.request)
        params = request.GET

        # Handle all filter parameters
        filter_fields = {
            "type": "type__iexact",
            "severity": "severity__iexact",
            "integration": "integration__iexact",
            "source": "source__iexact",  # Add source filter
        }

        for param, filter_name in filter_fields.items():
            value = params.get(param)
            if value:
                filters[filter_name] = value

        return filters

    async def get_integration_credentials(
        self, user_id: str, integration_name: str, cred_class: Type[SIEMCredentials]
    ) -> SIEMCredentials:
        """Get integration credentials from settings manager."""
        # Get integration settings from settings manager
        integration_settings = getattr(settings_manager.settings.integrations, integration_name, None)
        if not integration_settings:
            raise ValueError(f"No credentials found for {integration_name}")

        # Convert to appropriate credentials class if needed
        if not isinstance(integration_settings, cred_class):
            integration_settings = cred_class(**integration_settings.dict())

        return integration_settings

    @async_action(detail=False, methods=["post"])
    async def sync(self, request: DRFRequest) -> Response:
        """Sync rules with integration."""
        data = cast(Dict[str, Any], request.data)
        integration_name = data.get("integration")

        if not integration_name:
            logger.warning("Sync attempt without integration name")
            return Response(
                {"error": "Integration name is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            logger.info(f"Starting sync for integration: {integration_name}")

            # Get integration class
            IntegrationClass = cast(Type[BaseSIEMIntegration], get_integration(integration_name))

            # Initialize integration with integration_name
            integration = IntegrationClass()

            # Get and sync rules
            rules = await integration.get_enabled_rules()
            repo = DjangoRuleRepository(request.user.id)
            await repo.sync_rules(integration_name, rules)

            return Response({"message": f"Successfully synced {len(rules)} rules"})

        except Exception as e:
            logger.error(f"Error syncing rules: {e}")
            return Response(
                {"error": f"Failed to sync rules: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @async_action(detail=False, methods=["post"])
    async def create_with_llm(self, request: DRFRequest) -> Response:
        """Create rule using LLM with optional file analysis."""
        try:
            # Add debug logging
            logger.debug(f"Request FILES: {request.FILES}")
            logger.debug(f"Request data: {request.data}")
            logger.debug(f"Request content type: {request.content_type}")

            # Properly type request.data
            if isinstance(request.data, QueryDict):
                data = dict(request.data)
                data = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in data.items()}
            else:
                data = cast(Dict[str, Any], request.data)

            description = str(data.get("description", ""))
            rule_type = data.get("type", "sigma")  # Note: changed from rule_type to type to match frontend

            # Check both request.FILES and request.data for the file
            uploaded_file = None
            if request.FILES:
                uploaded_file = request.FILES.get("file")  # type: ignore
            elif isinstance(data.get("file"), UploadedFile):
                uploaded_file = data["file"]

            logger.debug(f"Processed data: description={description}, rule_type={rule_type}, file={uploaded_file}")

            # Only require description if no file is uploaded
            if not description and not uploaded_file:
                return Response({"error": "Either description or file is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Analyze file if provided
            file_analysis = None
            if uploaded_file:
                try:
                    analyzer = FileAnalyzer() if rule_type != "snort" else PcapAnalyzer()
                    if not isinstance(uploaded_file, UploadedFile):
                        return Response({"error": "Invalid file upload"}, status=status.HTTP_400_BAD_REQUEST)

                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        for chunk in uploaded_file.chunks():
                            temp_file.write(chunk)
                        temp_path = temp_file.name
                    matching_rules = None
                    analysis = await analyzer.analyze_file(Path(temp_path))
                    if rule_type == "yara":
                        matching_rules = YaraScanner(rule_dir=str(DEFAULT_DIRS.YARA_RULE_DIR)).scan_file(temp_path)
                    file_analysis = analysis
                    Path(temp_path).unlink(missing_ok=True)
                except Exception as e:
                    logger.error(f"Error analyzing file: {e}")
                    return Response(
                        {"error": f"File analysis failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

            # Initialize the appropriate LLM tool based on rule_type
            if rule_type == "sigma":
                if not self.sigmadb:
                    return Response({"error": "Sigma vector store not initialized"}, status=status.HTTP_400_BAD_REQUEST)
                tool = CreateSigmaRuleTool(llm=self.llm, sigmadb=self.sigmadb, verbose=True)
                result = await tool._arun(description)
            elif rule_type == "yara":
                if not self.yaradb:
                    return Response({"error": "YARA vector store not initialized"}, status=status.HTTP_400_BAD_REQUEST)
                tool = CreateYaraRuleTool(llm=self.llm, yaradb=self.yaradb, verbose=True)
                result = await tool._arun(description, file_analysis=file_analysis, matching_rules=matching_rules)
            elif rule_type == "snort":
                if not self.snortdb:
                    return Response({"error": "Snort vector store not initialized"}, status=status.HTTP_400_BAD_REQUEST)
                tool = CreateSnortRuleTool(llm=self.llm, snortdb=self.snortdb, verbose=True)
                result = await tool._arun(description, file_analysis=file_analysis)
            else:
                return Response({"error": "Unsupported rule type"}, status=status.HTTP_400_BAD_REQUEST)

            if not result:
                return Response(
                    {"error": "Failed to generate rule content"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            rule_data = {
                "title": result.get("title", "Untitled Rule"),
                "content": result.get("rule", "") or result.get("content", ""),
                "type": rule_type,
                "severity": result.get("severity", "medium"),
                "description": result.get("description", "No description available"),
                "enabled": True,
                "integration": "llm",
            }

            # Use async create
            rule = await self.rule_repository.create_rule(rule_data)

            return Response(
                {
                    "id": str(rule.pk),
                    "title": rule.title,
                    "content": rule.content,
                    "type": rule.type,
                    "severity": rule.severity,
                    "description": rule_data.get("description", "") or rule.description,
                    "agent_output": result.get("agent_output", "") or result.get("output", ""),
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error creating rule with LLM: {e}")
            return Response({"error": f"Failed to create rule: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @method_decorator(csrf_exempt)
    @async_action(detail=False, methods=["post"])
    async def translate_rule(self, request: DRFRequest) -> Response:
        """Translate rule to different format."""
        try:
            data = cast(Dict[str, Any], request.data)
            source_type = str(data.get("sourceType", ""))
            target_type = str(data.get("targetType", ""))
            rule_content = data.get("rule")

            if not all([source_type, target_type, rule_content]):
                return Response(
                    {"error": "Missing required fields"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Get appropriate LLM class based on target type
            llm_classes = {"sigma": SigmaLLM, "yara": YaraLLM, "snort": SnortLLM}

            LLMClass = llm_classes.get(target_type)
            if not LLMClass:
                return Response(
                    {"error": f"Unsupported target rule type: {target_type}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Initialize LLM
            llm = LLMClass()

            # Translate rule
            translated_rule = await llm.translate_rule(rule_content, source_type=source_type, target_type=target_type)

            return await sync_to_async(Response)({"translated_rule": translated_rule})

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=["post"])
    def create_version(self, request: DRFRequest, pk: str | None = None) -> Response:
        """Create a new version for a rule."""
        try:
            rule = get_object_or_404(StoredRule.objects.prefetch_related("versions"), pk=pk)

            # Get the latest version number using related_name
            latest_version = RuleVersion.objects.filter(rule=rule).order_by("-version").first()
            new_version_number = (latest_version.version + 1) if latest_version else 1

            # Get content safely from request data
            request_data = cast(Dict[str, Any], request.data)
            content = request_data.get("content", "")

            # Create new version
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
        logger.info("Fetching rule list")
        queryset = self.get_queryset()

        # Add pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response({"count": queryset.count(), "results": serializer.data})

    def create(self, request):
        logger.info(f"Creating new rule with data: {request.data}")
        # ... rest of create logic

    def update(self, request, *args, **kwargs):
        """Handle PUT and PATCH requests."""
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def perform_update(self, serializer):
        """Perform the update of the Rule instance."""
        try:
            serializer.save()
        except Exception as e:
            logger.error(f"Error updating rule: {e}")
            raise

    @async_action(detail=True, methods=["post"])
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
            result = await deployment_service.deploy_sigma_rule(rule_id, integration_type, integration_config)

            if result["success"]:
                return Response(result, status=status.HTTP_200_OK)
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_serializer(self, *args, **kwargs):
        if self.action == "partial_update":
            kwargs["partial"] = True
        return super().get_serializer(*args, **kwargs)


@method_decorator(csrf_exempt, name="dispatch")
class SettingsViewSet(viewsets.ViewSet):
    """ViewSet for managing user settings."""

    authentication_classes = []
    permission_classes = [AllowAny]
    basename = "settings"

    @async_action(detail=False, methods=["GET"], url_path="get_settings")
    async def get_settings(self, request):
        try:
            settings_manager = await get_settings(request.user)
            current_settings = settings_manager.settings

            # Convert SecretStr to string or empty string
            splunk_dict = current_settings.integrations.splunk.dict(exclude_none=True)
            if "password" in splunk_dict and isinstance(splunk_dict["password"], SecretStr):
                splunk_dict["password"] = splunk_dict["password"].get_secret_value()

            settings_dict = {
                "openai_api_key": current_settings.openai_api_key or "",
                "rule_directories": current_settings.rule_directories,
                "vector_store_directories": current_settings.vector_store_directories,
                "log_level": current_settings.log_level,
                "model": current_settings.model,
                "integrations": {
                    "splunk": splunk_dict,
                    "elastic": current_settings.integrations.elastic.dict(exclude_none=True),
                    "microsoft_xdr": current_settings.integrations.microsoft_xdr.dict(exclude_none=True),
                },
            }
            return Response(settings_dict)
        except Exception as e:
            logger.error(f"Error getting settings: {str(e)}")
            return Response(
                {"error": f"Failed to get settings: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @async_action(detail=False, methods=["POST"], url_path="update_settings")
    async def update_settings(self, request):
        try:
            settings_data = request.data

            # If updating integrations, ensure proper structure
            if "integrations" in settings_data:
                integrations_data = settings_data["integrations"]
                if "splunk" in integrations_data:
                    # Convert to proper credential model
                    splunk_data = integrations_data["splunk"]
                    splunk_creds = SplunkCredentials(
                        hostname=splunk_data.get("hostname", ""),
                        username=splunk_data.get("username", ""),
                        password=SecretStr(splunk_data.get("password", "")),  # Convert to SecretStr
                        app=splunk_data.get("app"),
                        owner=splunk_data.get("owner"),
                        verify_ssl=splunk_data.get("verify_ssl", True),
                        enabled=splunk_data.get("enabled", False),
                    )
                    integrations_data["splunk"] = splunk_creds

            # Update settings
            settings_manager.update_settings(**settings_data)
            return Response({"status": "success"})

        except Exception as e:
            logger.error(f"Error updating settings: {str(e)}")
            return Response(
                {"error": f"Failed to update settings: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @async_action(detail=False, methods=["POST"], url_path="test_integration")
    async def test_integration(self, request):
        try:
            integration_name = request.data.get("integration")
            if not integration_name:
                return Response({"error": "Integration name is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Get stored settings
            integration_settings = getattr(settings_manager.settings.integrations, integration_name, None)
            if not integration_settings:
                return Response(
                    {"error": f"No credentials found for {integration_name}"}, status=status.HTTP_400_BAD_REQUEST
                )

            # Get integration class
            IntegrationClass = cast(Type[BaseSIEMIntegration], get_integration(integration_name))
            if not IntegrationClass:
                return Response(
                    {"error": f"Unknown integration type: {integration_name}"}, status=status.HTTP_400_BAD_REQUEST
                )

            # Get stored password from keyring for Splunk
            if integration_name == "splunk":
                stored_password = keyring.get_password(settings_manager.APP_NAME, f"{integration_name}_password")
                if stored_password:
                    integration_settings.password = SecretStr(stored_password)

            # Initialize integration
            integration = IntegrationClass()
            result = await integration.test_connection()

            return Response(result)

        except ValueError as ve:
            logger.error(f"Integration configuration error: {str(ve)}")
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error testing integration: {str(e)}")
            return Response(
                {"error": f"Failed to test integration: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(["GET"])
async def list_rules(request: Union[HttpRequest, DRFRequest], rule_type: Optional[str] = None) -> Response:
    """Get rules with optional type and filters."""
    try:
        # Initialize repository without requiring user ID
        repository = DjangoRuleRepository()

        # Get filters from query params
        enabled = request.GET.get("enabled")
        filter_type = request.GET.get("type") or rule_type

        logger.debug(f"Listing rules with enabled={enabled}, type={filter_type}")

        # Get rules using repository
        filters = {}
        if enabled is not None:
            filters["enabled"] = enabled.lower() == "true"
        if filter_type:
            filters["type"] = filter_type

        rules = repository.get_rules(filters)

        # Convert queryset to list for serialization using proper model fields
        rule_list = [
            {
                "pk": str(rule.pk),
                "title": getattr(rule, "title", ""),
                "content": getattr(rule, "content", ""),
                "rule_type": getattr(rule, "rule_type", ""),
                "is_enabled": getattr(rule, "is_enabled", True),
                "metadata": getattr(rule, "metadata", {}),
                "description": getattr(rule, "description", ""),
                "source": getattr(rule, "source", ""),
                "version": getattr(rule, "version", "1.0.0"),
            }
            for rule in rules
        ]

        # Return array directly instead of wrapping in object
        return Response(rule_list)

    except Exception as e:
        logger.error(f"Error listing rules: {str(e)}")
        return Response({"error": f"Error loading rules: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["GET"])
async def search_rules(request: Union[HttpRequest, DRFRequest], rule_type: str) -> Response:
    """Search rules by query."""
    try:
        query = request.GET.get("q")
        if not query:
            return Response({"error": "Query parameter 'q' is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Initialize appropriate LLM handler
        llm_handlers = {
            "sigma": SigmaLLM(
                rule_dir=str(settings.RULE_DIRS["sigma"]), vector_store_dir=str(settings.VECTOR_STORE_DIRS["sigma"])
            ),
            "yara": YaraLLM(
                rule_dir=str(settings.RULE_DIRS["yara"]), vector_store_dir=str(settings.VECTOR_STORE_DIRS["yara"])
            ),
            "snort": SnortLLM(
                rule_dir=str(settings.RULE_DIRS["snort"]), vector_store_dir=str(settings.VECTOR_STORE_DIRS["snort"])
            ),
        }

        if rule_type not in llm_handlers:
            return Response(
                {"error": f"Invalid rule type. Must be one of: {', '.join(llm_handlers.keys())}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        llm_handler = llm_handlers[rule_type]

        # Load vector store
        llm_handler.load_vectordb()
        if not llm_handler.vectordb:
            return Response({"error": "Vector store not initialized"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Search rules
        results = llm_handler.vectordb.similarity_search(query)

        # Format response
        rules = [
            {"content": doc.page_content, "metadata": doc.metadata, "score": doc.metadata.get("score", 0)}
            for doc in results
        ]

        return Response({"rules": rules, "count": len(rules)})

    except Exception as e:
        logger.error(f"Error searching rules: {str(e)}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
