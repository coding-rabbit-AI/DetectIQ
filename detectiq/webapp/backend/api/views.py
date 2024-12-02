import asyncio
from functools import wraps
from typing import Any, Dict, Optional, Type, Union, cast

import keyring
import yaml
from asgiref.sync import async_to_sync
from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from pydantic import SecretStr
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.permissions import AllowAny
from rest_framework.request import Request as DRFRequest
from rest_framework.response import Response

from detectiq.core.integrations import get_integration
from detectiq.core.integrations.base import BaseSIEMIntegration
from detectiq.core.integrations.splunk import SplunkCredentials
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.yara_rules import YaraLLM
from detectiq.core.settings import settings_manager
from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

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


@method_decorator(csrf_exempt, name="dispatch")
class SettingsViewSet(viewsets.ViewSet):
    """ViewSet for managing DetectIQ settings while preserving DRF functionality."""

    authentication_classes = []
    permission_classes = [AllowAny]
    basename = "settings"

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

    @action(detail=False, methods=["GET"], url_path="get-app-settings")
    def get_app_settings(self, request):
        """Get DetectIQ settings."""
        try:
            current_settings = settings_manager.settings
            return Response(current_settings.dict())
        except Exception as e:
            return Response({"error": str(e)}, status=500)

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

        # Use settings_manager directly for DetectIQ-specific settings
        llm_handlers = {
            "sigma": SigmaLLM(
                rule_dir=str(settings_manager.settings.RULE_DIRS["sigma"]),
                vector_store_dir=str(settings_manager.settings.VECTOR_STORE_DIRS["sigma"]),
            ),
            "yara": YaraLLM(
                rule_dir=str(settings_manager.settings.RULE_DIRS["yara"]),
                vector_store_dir=str(settings_manager.settings.VECTOR_STORE_DIRS["yara"]),
            ),
            "snort": SnortLLM(
                rule_dir=str(settings_manager.settings.RULE_DIRS["snort"]),
                vector_store_dir=str(settings_manager.settings.VECTOR_STORE_DIRS["snort"]),
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
