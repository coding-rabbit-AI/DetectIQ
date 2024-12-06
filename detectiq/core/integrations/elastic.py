import json
from typing import Any, Dict, List, Optional, Tuple, cast

from elasticsearch import AsyncElasticsearch
from pydantic import SecretStr

from detectiq.core.integrations.base import BaseSIEMIntegration, SIEMCredentials


class ElasticCredentials(SIEMCredentials):
    """Elasticsearch-specific credentials model."""

    cloud_id: Optional[str] = None

    class Config:
        extra = "allow"


class ElasticIntegration(BaseSIEMIntegration):
    """Elasticsearch integration implementation."""

    credentials_class = ElasticCredentials
    integration_name = "elasticsearch"
    client: AsyncElasticsearch

    def __init__(self, credentials: Optional[ElasticCredentials] = None) -> None:
        super().__init__(credentials)

    def _validate_credentials(self) -> None:
        """Validate Elasticsearch credentials."""
        if not self.credentials.hostname:
            raise ValueError("Elasticsearch integration requires hostname")
        if not (self.credentials.api_key or (self.credentials.username and self.credentials.password)):
            raise ValueError("Elasticsearch requires either API key or username/password")

    def _initialize_client(self) -> None:
        """Initialize the Elasticsearch client."""
        # Cast credentials to correct type
        credentials = cast(ElasticCredentials, self.credentials)

        auth: Optional[Tuple[str, str]] = None
        api_key: Optional[str] = None

        if credentials.api_key:
            api_key = credentials.api_key.get_secret_value()
        elif credentials.username and credentials.password:
            auth = (
                credentials.username,
                credentials.password.get_secret_value(),
            )

        self.client = AsyncElasticsearch(
            credentials.hostname,
            cloud_id=credentials.cloud_id,
            api_key=api_key,
            basic_auth=auth,
            verify_certs=credentials.verify_ssl,
        )

    async def execute_search(self, query: str, **kwargs) -> Dict[str, Any]:
        """Execute an Elasticsearch query."""
        # Convert string query to dict if needed
        if isinstance(query, str):
            try:
                query_body = json.loads(query)
            except json.JSONDecodeError:
                query_body = {"query_string": {"query": query}}
        else:
            query_body = query

        response = await self.client.search(body=query_body, **kwargs)
        # Convert response to dict and ensure string keys
        return {str(k): v for k, v in response.items()}

    async def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Get all enabled detection rules."""
        # Using security rules API endpoint with query parameter in URL
        response = await self.client.transport.perform_request(
            "GET", "/_security/detection_engine/rules/_find?filter=enabled:true"
        )

        # Ensure we're working with a dictionary
        response_dict = cast(Dict[str, Any], response)

        rules = []
        for rule in response_dict.get("data", []):
            # Ensure all keys are strings
            rule_dict = {str(k): v for k, v in rule.items()}
            rules.append(
                {
                    "id": str(rule_dict["id"]),
                    "name": str(rule_dict["name"]),
                    "description": str(rule_dict.get("description", "")),
                    "query": rule_dict.get("query"),
                    "severity": str(rule_dict.get("severity", "")),
                    "risk_score": rule_dict.get("risk_score"),
                    "enabled": bool(rule_dict["enabled"]),
                }
            )

        return rules

    async def create_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new detection rule."""
        response = await self.client.transport.perform_request("POST", "/_security/detection_engine/rules", body=rule)

        # Cast response to Dict[str, Any] and ensure string keys
        response_dict = cast(Dict[str, Any], response)
        return {
            "id": str(response_dict["id"]),
            "name": str(response_dict["name"]),
            "created": True,
        }

    async def update_rule(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing detection rule."""
        response = await self.client.transport.perform_request(
            "PUT", f"/_security/detection_engine/rules/{rule_id}", body=rule
        )

        # Cast response to Dict[str, Any] and ensure string keys
        response_dict = cast(Dict[str, Any], response)
        return {
            "id": str(response_dict["id"]),
            "name": str(response_dict["name"]),
            "updated": True,
        }

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a detection rule."""
        try:
            await self.client.transport.perform_request("DELETE", f"/_security/detection_engine/rules/{rule_id}")
            return True
        except Exception:
            return False

    async def enable_rule(self, rule_id: str) -> bool:
        """Enable a detection rule."""
        try:
            await self.client.transport.perform_request("POST", f"/_security/detection_engine/rules/{rule_id}/_enable")
            return True
        except Exception:
            return False

    async def disable_rule(self, rule_id: str) -> bool:
        """Disable a detection rule."""
        try:
            await self.client.transport.perform_request("POST", f"/_security/detection_engine/rules/{rule_id}/_disable")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        """Close the Elasticsearch client connection."""
        if hasattr(self, "client"):
            await self.client.close()

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to Elasticsearch."""
        try:
            info = await self.client.info()
            return {
                "success": True,
                "message": f"Successfully connected to Elasticsearch {info['version']['number']}",
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to connect to Elasticsearch: {str(e)}",
            }
