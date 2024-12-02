import asyncio
from typing import Any, Dict, List, Optional, cast
from urllib.parse import quote, urlparse

import splunklib.client as splunk_client
import splunklib.results as splunk_results
from pydantic import Field, SecretStr

from detectiq.core.integrations.base import BaseSIEMIntegration, SIEMCredentials


class SplunkCredentials(SIEMCredentials):
    """Splunk-specific credentials model."""

    model_config = {"extra": "allow"}

    # Override parent fields with required fields
    username: str = Field(default="", description="Splunk username")
    password: SecretStr = Field(default=SecretStr(""), description="Splunk password")

    # Add Splunk-specific fields
    app: Optional[str] = Field(default=None, description="Splunk app context")
    owner: Optional[str] = Field(default=None, description="Splunk owner context")


class SplunkIntegration(BaseSIEMIntegration):
    """Splunk integration implementation."""

    credentials_class = SplunkCredentials
    integration_name = "splunk"
    service: Any  # Type hint for splunk service

    def __init__(self, credentials: Optional[SplunkCredentials] = None):
        """Initialize Splunk integration."""
        super().__init__(credentials)

    async def execute_search(self, query: str, **kwargs) -> Dict[str, Any]:
        """Execute a Splunk search query."""
        # Use asyncio to run blocking Splunk operations in a thread pool
        job = await asyncio.to_thread(self.service.jobs.create, query, **kwargs)

        while not job.is_done():
            await asyncio.sleep(1)

        results = await asyncio.to_thread(splunk_results.ResultsReader, job.results())

        return {"results": [result for result in results]}

    async def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Get all enabled correlation searches."""
        saved_searches = self.service.saved_searches
        rules = []

        for search in saved_searches:
            # Check if it's a correlation search by looking for alert actions and scheduling
            is_correlation = search.content.get("action.correlationsearch.enabled", "0") == "1"

            if is_correlation:
                rules.append(search.content)

        return rules

    async def create_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new correlation search."""
        name = rule.pop("title").strip()
        search = rule.pop("search").strip()
        saved_search = await asyncio.to_thread(self.service.saved_searches.create, name=name, search=search, **rule)

        return {
            "id": saved_search.name,
            "title": saved_search.name,
            "search": saved_search.content.get("search"),
        }

    def update_rule_permissions(
        self, rule_name: str, sharing: str = "global", owner: str = "", perms_read: str = "*"
    ) -> None:
        """Update the permissions for a correlation search."""
        credentials = cast(SplunkCredentials, self.credentials)
        owner = owner or credentials.owner or ""

        rule_obj = self.service.saved_searches[rule_name]
        results = rule_obj.acl_update(sharing=sharing, owner=owner, **{"perms.read": perms_read})
        return results

    async def update_rule(self, rule_name: str, **kwargs) -> Dict[str, Any]:
        """Update an existing correlation search."""
        try:
            saved_search = self.service.saved_searches[rule_name]

            # Update the saved search properties

            await asyncio.to_thread(saved_search.update, **kwargs)

            return {
                "id": saved_search.name,
                "title": saved_search.name,
                "search": saved_search.content.get("search"),
                "updated": True,
            }
        except KeyError:
            raise ValueError(f"Rule with ID {rule_name} not found")

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a correlation search."""
        try:
            saved_search = self.service.saved_searches[rule_id]
            await asyncio.to_thread(saved_search.delete)
            return True
        except KeyError:
            raise ValueError(f"Rule with ID {rule_id} not found")
        except Exception as e:
            raise Exception(f"Failed to delete rule: {str(e)}")

    async def enable_rule(self, rule_id: str) -> bool:
        """Enable a correlation search."""
        try:
            saved_search = self.service.saved_searches[rule_id]
            await asyncio.to_thread(saved_search.enable)
            return True
        except KeyError:
            raise ValueError(f"Rule with ID {rule_id} not found")
        except Exception as e:
            raise Exception(f"Failed to enable rule: {str(e)}")

    async def disable_rule(self, rule_id: str) -> bool:
        """Disable a correlation search."""
        try:
            saved_search = self.service.saved_searches[rule_id]
            await asyncio.to_thread(saved_search.disable)
            return True
        except KeyError:
            raise ValueError(f"Rule with ID {rule_id} not found")
        except Exception as e:
            raise Exception(f"Failed to disable rule: {str(e)}")

    async def close(self) -> None:
        """Close any open connections."""
        if hasattr(self, "service"):
            # Splunk SDK doesn't have an async close method
            self.service.logout()

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to Splunk."""
        try:
            # Try to get server info as a connection test
            server_info = await asyncio.to_thread(self.service.info)
            return {
                "success": True,
                "message": f"Successfully connected to Splunk {server_info.get('version', 'unknown version')}",
            }
        except Exception as e:
            return {"success": False, "message": f"Failed to connect to Splunk: {str(e)}"}
