from typing import Any, Dict, List, Optional, cast

import aiohttp
from pydantic import Field, SecretStr

from detectiq.core.integrations.base import BaseSIEMIntegration, SIEMCredentials


class MicrosoftXDRCredentials(SIEMCredentials):
    """Microsoft XDR-specific credentials model."""

    tenant_id: str = Field(default="", description="Microsoft tenant ID")
    client_id: str = Field(default="", description="Microsoft client ID")
    client_secret: SecretStr = Field(default=SecretStr(""), description="Microsoft client secret")

    class Config:
        extra = "allow"
        arbitrary_types_allowed = True

    @property
    def is_valid(self) -> bool:
        """Check if credentials are valid."""
        return bool(self.tenant_id and self.client_id and self.client_secret and self.client_secret.get_secret_value())


class MicrosoftXDRIntegration(BaseSIEMIntegration):
    """Microsoft XDR integration implementation."""

    credentials_class = MicrosoftXDRCredentials
    integration_name = "microsoft_xdr"
    session: aiohttp.ClientSession
    token: str

    def __init__(self, credentials: Optional[MicrosoftXDRCredentials] = None) -> None:
        super().__init__(credentials)

    def _validate_credentials(self) -> None:
        """Validate Microsoft XDR credentials."""
        if not isinstance(self.credentials, MicrosoftXDRCredentials):
            raise ValueError("Invalid credentials type")

        if not self.credentials.is_valid:
            raise ValueError("Microsoft XDR requires tenant_id, client_id, and client_secret")

    async def _initialize_client(self) -> None:
        """Initialize the Microsoft XDR client with OAuth token."""
        try:
            self.token = await self._get_access_token()
            self.session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
            )
        except Exception as e:
            raise ValueError(f"Failed to initialize Microsoft XDR client: {str(e)}")

    async def _get_access_token(self) -> str:
        """Get OAuth access token."""
        # Cast credentials to correct type
        credentials = cast(MicrosoftXDRCredentials, self.credentials)

        if not credentials.client_secret:
            raise ValueError("Client secret is required for authentication")

        token_url = f"https://login.microsoftonline.com/{credentials.tenant_id}/oauth2/v2.0/token"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url,
                data={
                    "client_id": credentials.client_id,
                    "client_secret": credentials.client_secret.get_secret_value(),
                    "scope": "https://api.security.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            ) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise ValueError(
                        f"Failed to get access token: {error_data.get('error_description', 'Unknown error')}"
                    )
                data = await response.json()
                return data["access_token"]

    async def execute_search(self, query: str, **kwargs) -> Dict[str, Any]:
        """Execute an advanced hunting query."""
        url = "https://api.security.microsoft.com/api/advancedhunting/run"
        async with self.session.post(url, json={"Query": query}) as response:
            return await response.json()

    async def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Get all enabled custom detection rules."""
        url = "https://api.security.microsoft.com/api/customdetections"
        async with self.session.get(url) as response:
            data = await response.json()
            return [rule for rule in data["value"] if rule["enabled"]]

    async def create_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new detection rule."""
        url = "https://api.security.microsoft.com/api/customdetections"
        async with self.session.post(url, json=rule) as response:
            return await response.json()

    async def update_rule(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing detection rule."""
        url = f"https://api.security.microsoft.com/api/customdetections/{rule_id}"
        async with self.session.patch(url, json=rule) as response:
            return await response.json()

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a detection rule."""
        try:
            url = f"https://api.security.microsoft.com/api/customdetections/{rule_id}"
            async with self.session.delete(url) as response:
                return response.status == 204
        except Exception:
            return False

    async def enable_rule(self, rule_id: str) -> bool:
        """Enable a detection rule."""
        try:
            url = f"https://api.security.microsoft.com/api/customdetections/{rule_id}/enable"
            async with self.session.post(url) as response:
                return response.status == 200
        except Exception:
            return False

    async def disable_rule(self, rule_id: str) -> bool:
        """Disable a detection rule."""
        try:
            url = f"https://api.security.microsoft.com/api/customdetections/{rule_id}/disable"
            async with self.session.post(url) as response:
                return response.status == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the aiohttp session."""
        if hasattr(self, "session"):
            await self.session.close()

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to Microsoft XDR."""
        try:
            # Test connection by attempting to list rules
            url = "https://api.security.microsoft.com/api/customdetections"
            async with self.session.get(url) as response:
                if response.status == 200:
                    return {
                        "success": True,
                        "message": "Successfully connected to Microsoft XDR",
                    }
                return {
                    "success": False,
                    "message": f"Failed to connect: HTTP {response.status}",
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to connect to Microsoft XDR: {str(e)}",
            }
