import tempfile
from pathlib import Path
from typing import Any, Dict, cast

from asgiref.sync import async_to_sync
from django.core.files.uploadedfile import UploadedFile
from django.http import QueryDict
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from rest_framework import status, viewsets
from rest_framework.request import Request, Request as DRFRequest
from rest_framework.response import Response

from detectiq.core.config.base import get_config
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.tools.sigma.create_sigma_rule import CreateSigmaRuleTool
from detectiq.core.llm.tools.snort.create_snort_rule import CreateSnortRuleTool
from detectiq.core.llm.tools.yara.create_yara_rule import CreateYaraRuleTool
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.pcap_analyzer import PcapAnalyzer
from detectiq.core.utils.yara.file_analyzer import FileAnalyzer
from detectiq.core.utils.yara.rule_scanner import YaraScanner
from detectiq.webapp.backend.rule_creator.serializers import RuleCreatorSerializer
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository
from detectiq.webapp.backend.utils.decorators import async_action

logger = get_logger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class RuleCreatorViewSet(viewsets.ViewSet):
    """ViewSet for AI-assisted rule creation functionality."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rule_repository = DjangoRuleRepository()
        # Initialize settings
        self.detectiq_config = async_to_sync(get_config)().config

        # Initialize LLM and embeddings
        self.llm = ChatOpenAI(model=self.detectiq_config.llm_model, temperature=self.detectiq_config.temperature)
        self.embeddings = OpenAIEmbeddings(model=self.detectiq_config.embeddings_model)

        # Initialize vector stores
        self.sigmadb = self._init_vector_store("sigma")
        self.yaradb = self._init_vector_store("yara")
        self.snortdb = self._init_vector_store("snort")

    def _init_vector_store(self, rule_type: str):
        """Initialize vector store for given rule type."""
        try:
            from langchain_community.vectorstores import FAISS

            vector_store_path = self.detectiq_config.vector_store_directories[rule_type]
            if Path(vector_store_path).exists():
                return FAISS.load_local(str(vector_store_path), self.embeddings, allow_dangerous_deserialization=True)
            return None
        except Exception as e:
            logger.error(f"Error initializing {rule_type} vector store: {e}")
            return None

    @async_action(detail=False, methods=["post"])
    async def create_with_llm(self, request: Request) -> Response:
        """Create rule using LLM with optional file analysis."""
        try:
            # Validate input data using serializer
            serializer = RuleCreatorSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            validated_data = serializer.validated_data  # type: ignore
            description = validated_data.get("description", "")  # type: ignore
            rule_type = validated_data.get("type", "sigma")  # type: ignore

            # Handle file upload
            file_analysis = await self._handle_file_upload(validated_data, rule_type)
            if isinstance(file_analysis, Response):
                return file_analysis

            # Generate rule using appropriate tool
            result = await self._generate_rule(rule_type, description, file_analysis)
            if isinstance(result, Response):
                return result

            # Create rule in database
            rule = await self.rule_repository.create_rule(
                {
                    "title": result.get("title", "Untitled Rule"),
                    "content": result.get("rule", "") or result.get("content", ""),
                    "type": rule_type,
                    "severity": result.get("severity", "medium"),
                    "description": result.get("description", "No description available"),
                    "enabled": True,
                    "integration": "llm",
                }
            )

            return Response(
                {
                    "id": str(rule.pk),
                    "title": rule.title,
                    "content": rule.content,
                    "type": rule.type,
                    "severity": rule.severity,
                    "description": rule.description,
                    "agent_output": result.get("agent_output", "") or result.get("output", ""),
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error creating rule with LLM: {e}")
            return Response({"error": f"Failed to create rule: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _handle_file_upload(self, validated_data: Any, rule_type: str) -> Response | Dict[str, Any]:
        """Handle file upload and analysis."""
        uploaded_file = validated_data.get("file")
        if not uploaded_file:
            return {}

        try:
            analyzer = FileAnalyzer() if rule_type != "snort" else PcapAnalyzer()
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)
                temp_path = temp_file.name

            analysis = await analyzer.analyze_file(Path(temp_path))

            if rule_type == "yara":
                matching_rules = YaraScanner(rule_dir=str(self.detectiq_config.rule_directories["yara"])).scan_file(
                    temp_path
                )
                analysis["matching_rules"] = matching_rules

            Path(temp_path).unlink(missing_ok=True)
            return analysis

        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
            return Response({"error": f"File analysis failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _generate_rule(
        self, rule_type: str, description: str, file_analysis: Dict[str, Any]
    ) -> Response | Dict[str, Any]:
        """Generate rule using appropriate LLM tool."""
        try:
            if rule_type == "sigma":
                if not self.sigmadb:
                    return Response({"error": "Sigma vector store not initialized"}, status=status.HTTP_400_BAD_REQUEST)
                tool = CreateSigmaRuleTool(llm=self.llm, sigmadb=self.sigmadb, verbose=True)
                return await tool._arun(description)

            elif rule_type == "yara":
                if not self.yaradb:
                    return Response({"error": "YARA vector store not initialized"}, status=status.HTTP_400_BAD_REQUEST)
                tool = CreateYaraRuleTool(llm=self.llm, yaradb=self.yaradb, verbose=True)
                return await tool._arun(
                    description, file_analysis=file_analysis, matching_rules=file_analysis.get("matching_rules")
                )

            elif rule_type == "snort":
                if not self.snortdb:
                    return Response({"error": "Snort vector store not initialized"}, status=status.HTTP_400_BAD_REQUEST)
                tool = CreateSnortRuleTool(llm=self.llm, snortdb=self.snortdb, verbose=True)
                return await tool._arun(description, file_analysis=file_analysis)

            return Response({"error": "Unsupported rule type"}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error generating rule: {e}")
            return Response(
                {"error": f"Rule generation failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @async_action(detail=False, methods=["GET"])
    async def search_rules(self, request: DRFRequest, rule_type: str) -> Response:
        """Search rules by query."""
        try:
            query = request.GET.get("q")
            if not query:
                return Response({"error": "Query parameter 'q' is required"}, status=status.HTTP_400_BAD_REQUEST)

            llm_handlers = {
                "sigma": SigmaLLM(
                    rule_dir=str(self.detectiq_config.rule_directories["sigma"]),
                    vector_store_dir=str(self.detectiq_config.vector_store_directories["sigma"]),
                ),
                "yara": YaraLLM(
                    rule_dir=str(self.detectiq_config.rule_directories["yara"]),
                    vector_store_dir=str(self.detectiq_config.vector_store_directories["yara"]),
                ),
                "snort": SnortLLM(
                    rule_dir=str(self.detectiq_config.rule_directories["snort"]),
                    vector_store_dir=str(self.detectiq_config.vector_store_directories["snort"]),
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
