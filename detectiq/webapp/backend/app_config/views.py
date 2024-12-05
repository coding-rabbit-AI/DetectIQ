from pathlib import Path
from typing import Type, cast

import keyring
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from pydantic import SecretStr
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from detectiq.core.config import config_manager
from detectiq.core.integrations import get_integration
from detectiq.core.integrations.base import BaseSIEMIntegration
from detectiq.core.integrations.splunk import SplunkCredentials
from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.services.ruleset_manager import (
    SigmaRulesetManager,
    SnortRulesetManager,
    YaraRulesetManager,
)
from detectiq.webapp.backend.utils.decorators import async_action

logger = get_logger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class AppConfigViewSet(viewsets.ViewSet):
    """ViewSet for managing DetectIQ config/settings"""

    authentication_classes = []
    permission_classes = [AllowAny]
    basename = "app-config"

    @action(detail=False, methods=["GET"], url_path="get-config")
    def get_config(self, request):
        """Get DetectIQ config."""
        try:
            current_config = config_manager.config

            # Helper function to handle SecretStr serialization
            def handle_integration_config(integration_config):
                if not integration_config:
                    return {}
                config_dict = integration_config.model_dump()
                # Convert SecretStr to string or empty string
                for key, value in config_dict.items():
                    if isinstance(value, SecretStr):
                        config_dict[key] = value.get_secret_value() if value else ""
                return config_dict

            # Convert Pydantic model to dict and structure response
            response_data = {
                "openai_api_key": current_config.openai_api_key,
                "llm_model": current_config.llm_model,
                "embeddings_model": current_config.embeddings_model,
                "temperature": current_config.temperature,
                "rule_directories": current_config.rule_directories,
                "vector_store_directories": current_config.vector_store_directories,
                "integrations": {
                    "splunk": handle_integration_config(
                        current_config.integrations.splunk if current_config.integrations else None
                    ),
                    "elastic": handle_integration_config(
                        current_config.integrations.elastic if current_config.integrations else None
                    ),
                    "microsoft_xdr": handle_integration_config(
                        current_config.integrations.microsoft_xdr if current_config.integrations else None
                    ),
                },
            }
            return Response(response_data)
        except Exception as e:
            logger.exception(f"Error getting config: {str(e)}")
            return Response({"error": f"Failed to get config: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @async_action(
        detail=False, methods=["POST"], url_path="update-config"
    )  # TODO: Change to update-config where we used update-settings
    async def update_config(self, request):
        try:
            config_data = request.data

            # If updating integrations, ensure proper structure
            if "integrations" in config_data:
                integrations_data = config_data["integrations"]
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

            # Update config
            config_manager.update_config(**config_data)
            return Response({"status": "success"})

        except Exception as e:
            logger.error(f"Error updating config: {str(e)}")
            return Response(
                {"error": f"Failed to update config: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @async_action(detail=False, methods=["POST"], url_path="test-integration")
    async def test_integration(self, request):
        try:
            integration_name = request.data.get("integration")
            if not integration_name:
                return Response({"error": "Integration name is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Get stored config
            integrations_config = getattr(config_manager.config.integrations, integration_name, None)
            if not integrations_config:
                return Response(
                    {"error": f"No credentials found for {integration_name}"}, status=status.HTTP_400_BAD_REQUEST
                )

            # Get integration class
            IntegrationClass = cast(Type[BaseSIEMIntegration], get_integration(integration_name))
            if not IntegrationClass:
                return Response(
                    {"error": f"Unknown integration type: {integration_name}"}, status=status.HTTP_400_BAD_REQUEST
                )

            try:
                # Get stored password from keyring for Splunk
                if integration_name == "splunk":
                    stored_password = keyring.get_password(config_manager.APP_NAME, f"{integration_name}_password")
                    if stored_password:
                        integrations_config.password = SecretStr(stored_password)

                    # Ensure we're using the correct credential class
                    if not isinstance(integrations_config, SplunkCredentials):
                        integrations_config = SplunkCredentials(**integrations_config.model_dump())

                # Initialize integration
                integration = IntegrationClass(credentials=integrations_config)
                result = await integration.test_connection()
                await integration.close()  # Ensure we close the connection

                return Response(result)

            except ValueError as ve:
                logger.error(f"Credential validation error: {str(ve)}")
                return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error testing integration: {str(e)}")
            return Response(
                {"error": f"Failed to test integration: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=["GET"], url_path="check-vectorstores")
    def check_vectorstores(self, request):
        """Check if vectorstores exist for each rule type."""
        try:
            status = {}
            for rule_type in ["sigma", "yara", "snort"]:
                vector_store_dir = Path(config_manager.config.vector_store_directories[rule_type])
                status[rule_type] = {
                    "exists": (
                        vector_store_dir.exists()
                        and (vector_store_dir / "index.faiss").exists()
                        and (vector_store_dir / "index.pkl").exists()
                    )
                }
            return Response(status)
        except Exception as e:
            logger.exception(f"Error checking vectorstores: {str(e)}")
            return Response(
                {"error": f"Failed to check vectorstores: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,  # type: ignore
            )

    @async_action(detail=False, methods=["POST"], url_path="create-vectorstore")
    async def create_vectorstore(self, request):
        """Create vectorstore for specified rule type."""
        try:
            rule_type = request.data.get("type")
            if not rule_type:
                return Response({"error": "Rule type is required"}, status=status.HTTP_400_BAD_REQUEST)

            managers = {"sigma": SigmaRulesetManager(), "yara": YaraRulesetManager(), "snort": SnortRulesetManager()}

            manager = managers.get(rule_type)
            if not manager:
                return Response({"error": f"Invalid rule type: {rule_type}"}, status=status.HTTP_400_BAD_REQUEST)

            await manager.create_vector_store()
            return Response({"status": "success"})

        except Exception as e:
            logger.error(f"Error creating vectorstore: {str(e)}")
            return Response(
                {"error": f"Failed to create vectorstore: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @async_action(detail=False, methods=["GET"], url_path="check-rule-packages")
    async def check_rule_packages(self, request):
        """Check if rule package updates are available."""
        try:
            status_data = {}
            
            # Use existing ruleset managers
            managers = {
                "sigma": SigmaRulesetManager(),
                "yara": YaraRulesetManager(),
                "snort": SnortRulesetManager()
            }

            for rule_type, manager in managers.items():
                needs_update, latest_version = await manager.updater.check_for_updates()
                status_data[rule_type] = {
                    "current_version": manager.updater.installed_version or "Not installed",
                    "latest_version": latest_version,
                    "needs_update": needs_update
                }

            return Response(status_data)

        except Exception as e:
            logger.exception(f"Error checking rule packages: {str(e)}")
            return Response(
                {"error": f"Failed to check rule packages: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @async_action(detail=False, methods=["POST"], url_path="update-rule-package")
    async def update_rule_package(self, request):
        """Update specified rule package."""
        try:
            rule_type = request.data.get("type")
            if not rule_type:
                return Response(
                    {"error": "Rule type is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            managers = {
                "sigma": SigmaRulesetManager(),
                "yara": YaraRulesetManager(),
                "snort": SnortRulesetManager()
            }

            manager = managers.get(rule_type)
            if not manager:
                return Response(
                    {"error": f"Invalid rule type: {rule_type}"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            await manager.update_rules()
            return Response({"status": "success"})

        except Exception as e:
            logger.exception(f"Error updating rule package: {str(e)}")
            return Response(
                {"error": f"Failed to update rule package: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
