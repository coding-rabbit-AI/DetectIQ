import json
from typing import Any, Dict, Optional, cast

import keyring
import yaml
from pydantic import SecretStr
from sigmaiq import SigmAIQBackend

from detectiq.core.config import config_manager
from detectiq.core.integrations.base import SIEMCredentials
from detectiq.core.integrations.elastic import ElasticIntegration
from detectiq.core.integrations.microsoft_xdr import MicrosoftXDRIntegration
from detectiq.core.integrations.splunk import SplunkCredentials, SplunkIntegration
from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.rules.models import StoredRule

logger = get_logger(__name__)


class RuleDeploymentService:
    SIGMA_BACKEND_INTEGRATION_MAP = {"splunk": "splunk", "elastic": "elasticsearch", "microsoft_xdr": "microsoft_xdr"}

    def __init__(
        self,
    ):
        self.translator = SigmAIQBackend
        self.integration = None

    async def deploy_sigma_rule(
        self, rule_id: int, integration_type: str, integration_config: Dict[str, Any] | SIEMCredentials
    ) -> Dict[str, Any]:
        """Deploy a Sigma rule to the specified integration."""
        try:
            # Log initial config
            logger.debug(f"Deploying rule {rule_id} to {integration_type}")

            # Get the rule
            rule = await StoredRule.objects.aget(id=rule_id)

            # Translate rule for target integration
            backend_name = self.SIGMA_BACKEND_INTEGRATION_MAP.get(integration_type)
            if not backend_name:
                raise ValueError(f"Unsupported integration type: {integration_type}")

            output_format = "stanza" if integration_type == "splunk" else "default"
            try:
                query = (
                    self.translator(backend=backend_name, output_format=output_format)
                    .create_backend()
                    .translate(rule.content)[0]
                )
            except Exception as e:
                logger.error(f"Error translating rule: {str(e)}")
                return {"success": False, "message": f"Failed to translate rule: {str(e)}"}

            # Deploy to integration
            if integration_type == "splunk":
                config_dict = (
                    integration_config if isinstance(integration_config, dict) else integration_config.model_dump()
                )
                integration_config = SplunkCredentials(**config_dict)

            self.integration = self._get_integration(integration_type, integration_config)

            # Create rule config for target integration
            rule_config = self._create_rule_config(rule, query, integration_type)

            # Log rule config before deployment
            async with self.integration:
                result = await self.integration.create_rule(rule_config)
                if integration_type == "splunk":
                    rule_name = result.get("title", "")
                    if rule_name:
                        permissions_update = self.integration.update_rule_permissions(rule_name=rule_name)
            return {
                "success": True,
                "rule_id": result.get("id"),
                "message": f"Successfully deployed rule to {integration_type}",
            }

        except Exception as e:
            logger.error(f"Error deploying rule: {str(e)}")
            return {"success": False, "message": f"Failed to deploy rule: {str(e)}"}

    def _create_rule_config(self, rule: StoredRule, query: str, integration_type: str) -> Dict[str, Any]:
        """Create integration-specific rule configuration."""
        base_config: Dict[str, Any] = {
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity,
        }

        if integration_type == "splunk":
            rule_content = yaml.safe_load(rule.content)
            name, rule_config = self.parse_splunk_stanza_string(query)
            severity = base_config.pop("severity")
            base_config.update({"title": name, "owner": "admin"})
            base_config.update(rule_config)
            base_config["description"] = rule.description
            base_config.pop("counttype")
            base_config["alert.track"] = "1"
            base_config["alert_type"] = "number of events"
            base_config["alert_comparator"] = "greater than"
            base_config["alert_threshold"] = "0"
            base_config["alert_condition"] = None
            base_config["action.correlationsearch.label "] = name
            base_config.pop("enableSched")
            base_config.pop("quantity")
            base_config.pop("relation")
            base_config["action.notable.param.severity"] = severity
            base_config["alert.severity"] = {
                "informational": "0",
                "low": "1",
                "medium": "2",
                "high": "3",
                "critical": "4",
            }.get(
                severity.lower(), 2
            )  # Default to medium (2) if severity not found
            base_config["is_visible"] = "1"
            base_config["actions"] = "notable"
            base_config["action.customsearchbuilder.enabled"] = "0"
            # base_config['request.ui_dispatch_app'] = 'SplunkEnterpriseSecuritySuite'
            base_config["is_scheduled"] = "1"
            annotations = json.loads(base_config["action.correlationsearch.annotations"].replace("'", '"'))
            annotations["Sigma"] = [rule_content.get("id"), rule.integration]
            base_config["action.correlationsearch.annotations"] = json.dumps(annotations).replace("'", '"')
            print(base_config["action.correlationsearch.annotations"])
            print()
        elif integration_type == "elastic":
            base_config.update(
                {"query": query, "type": "query", "risk_score": self._map_severity_to_risk_score(rule.severity)}
            )
        elif integration_type == "microsoft_xdr":
            base_config.update({"queryContent": query, "severity": rule.severity.upper(), "triggerThreshold": 1})

        return base_config

    def _get_integration(self, integration_type: str, config: Dict[str, Any] | SIEMCredentials):
        """Get integration instance based on type."""
        try:
            if integration_type == "splunk":
                config_dict = config if isinstance(config, dict) else config.model_dump()
                stored_password = keyring.get_password(config_manager.APP_NAME, f"{integration_type}_password")
                splunk_config = SplunkCredentials(
                    **{**config_dict, "password": SecretStr(stored_password) if stored_password else ""}
                )
                return SplunkIntegration(credentials=cast(SplunkCredentials, splunk_config))
            elif integration_type == "elastic":
                return ElasticIntegration()
            elif integration_type == "microsoft_xdr":
                return MicrosoftXDRIntegration()
            else:
                raise ValueError(f"Unsupported integration type: {integration_type}")
        except Exception as e:
            logger.error(f"Error initializing integration: {str(e)}")
            raise

    def _map_severity_to_risk_score(self, severity: str) -> int:
        """Map severity to Elastic risk score."""
        mapping = {"critical": 100, "high": 75, "medium": 50, "low": 25, "informational": 0}
        return mapping.get(severity.lower(), 50)

    def parse_splunk_stanza_string(self, stanza_string: str) -> tuple[str, dict]:
        """Parse a Splunk stanza string into a name and configuration dictionary."""
        # Split into lines
        lines = stanza_string.strip().split("\n")

        # Extract name from first line (between square brackets and hyphens, if present)
        name = lines[0].split("[")[1].split("]")[0].strip()
        # Extract name between hyphens if present, otherwise use full name
        if name.count("-") == 2 and name.endswith("Rule"):
            # Split on hyphens and take middle part
            name = name.split("-")[1].strip()

        # Create dictionary from remaining lines
        config = {}
        for line in lines[1:]:
            if "=" in line:
                key, value = line.split("=", 1)  # Split on first occurrence of =
                config[key.strip()] = value.strip()

        return name, config
