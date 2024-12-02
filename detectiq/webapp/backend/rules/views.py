import asyncio
import tempfile
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, Type, Union, cast

from asgiref.sync import async_to_sync, sync_to_async
from django.conf import settings as django_settings
from django.core.files.uploadedfile import UploadedFile
from django.db.models import Q
from django.http import HttpRequest, QueryDict
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response

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
from detectiq.webapp.backend.services.rule_deployment_service import RuleDeploymentService
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

from .models import RuleVersion, StoredRule
from .serializers import StoredRuleSerializer

logger = get_logger(__name__)


def async_action(detail=False, methods=None, url_path=None, **kwargs):
    """Decorator to handle async actions in DRF viewsets."""

    def decorator(func):
        @action(detail=detail, methods=methods, url_path=url_path, **kwargs)
        @wraps(func)
        def wrapped(viewset, request, *args, **kwargs):
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = async_to_sync(func)(viewset, request, *args, **kwargs)
                loop.close()
                return result
            except Exception as e:
                logger.error(f"Error in async action: {str(e)}")
                raise

        return wrapped

    return decorator


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
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
        self.embeddings = OpenAIEmbeddings()

        # Initialize settings
        self.settings = async_to_sync(get_settings)().settings

        # Initialize vector stores
        self.sigmadb = self._init_vector_store("sigma")
        self.yaradb = self._init_vector_store("yara")
        self.snortdb = self._init_vector_store("snort")

    def _init_vector_store(self, rule_type: str):
        """Initialize vector store for given rule type."""
        try:
            from langchain_community.vectorstores import FAISS

            vector_store_path = self.settings.vector_store_directories[rule_type]
            if Path(vector_store_path).exists():
                return FAISS.load_local(str(vector_store_path), self.embeddings, allow_dangerous_deserialization=True)
            return None
        except Exception as e:
            logger.error(f"Error initializing {rule_type} vector store: {e}")
            return None

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
                        matching_rules = YaraScanner(rule_dir=str(self.settings.rule_directories["yara"])).scan_file(
                            temp_path
                        )
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

    @async_action(detail=True, methods=["post"])
    async def deploy(self, request, pk=None):
        """Deploy rule to integration."""
        try:
            if pk is None:
                return Response({"error": "Rule ID is required"}, status=status.HTTP_400_BAD_REQUEST)

            integration_type = request.data.get("integration")
            if not integration_type:
                return Response({"error": "Integration type required"}, status=status.HTTP_400_BAD_REQUEST)

            integration_config = getattr(self.settings.integrations, integration_type, None)

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

    @async_action(detail=False, methods=["GET"])
    async def search_rules(self, request: DRFRequest, rule_type: str) -> Response:
        """Search rules by query."""
        try:
            query = request.GET.get("q")
            if not query:
                return Response({"error": "Query parameter 'q' is required"}, status=status.HTTP_400_BAD_REQUEST)

            llm_handlers = {
                "sigma": SigmaLLM(
                    rule_dir=str(self.settings.rule_directories["sigma"]),
                    vector_store_dir=str(self.settings.vector_store_directories["sigma"]),
                ),
                "yara": YaraLLM(
                    rule_dir=str(self.settings.rule_directories["yara"]),
                    vector_store_dir=str(self.settings.vector_store_directories["yara"]),
                ),
                "snort": SnortLLM(
                    rule_dir=str(self.settings.rule_directories["snort"]),
                    vector_store_dir=str(self.settings.vector_store_directories["snort"]),
                ),
            }

            if rule_type not in llm_handlers:
                return Response(
                    {"error": f"Invalid rule type. Must be one of: {', '.join(llm_handlers.keys())}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            llm_handler = llm_handlers[rule_type]
            llm_handler.load_vectordb()

            if not llm_handler.vectordb:
                return Response({"error": "Vector store not initialized"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            results = llm_handler.vectordb.similarity_search(query)
            rules = [
                {"content": doc.page_content, "metadata": doc.metadata, "score": doc.metadata.get("score", 0)}
                for doc in results
            ]

            return Response({"rules": rules, "count": len(rules)})

        except Exception as e:
            logger.error(f"Error searching rules: {str(e)}")
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

    @property
    def drf_settings(self):
        """Access DRF settings from Django settings."""
        return django_settings.REST_FRAMEWORK

    def get_format_suffix(self, **kwargs):
        """Get format suffix from DRF settings."""
        format_kwarg = self.drf_settings.get("FORMAT_SUFFIX_KWARG")
        return kwargs.get(format_kwarg) if format_kwarg else None

    def get_exception_handler(self):
        """Get exception handler from DRF settings."""
        return self.drf_settings.get("EXCEPTION_HANDLER")

    def get_view_description(self, html=False):
        """Get view description function from DRF settings."""
        view_desc_func = self.drf_settings.get("VIEW_DESCRIPTION_FUNCTION", "rest_framework.views.get_view_description")
        if isinstance(view_desc_func, str):
            from django.utils.module_loading import import_string

            view_desc_func = import_string(view_desc_func)
        return view_desc_func(self, html)

    def get_view_name(self):
        """Get view name function from DRF settings."""
        view_name_func = self.drf_settings.get("VIEW_NAME_FUNCTION", "rest_framework.views.get_view_name")
        if isinstance(view_name_func, str):
            from django.utils.module_loading import import_string

            view_name_func = import_string(view_name_func)
        return view_name_func(self)
