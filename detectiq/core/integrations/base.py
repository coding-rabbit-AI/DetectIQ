from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

from pydantic import BaseModel, Field, SecretStr


class SIEMCredentials(BaseModel):
    """Base model for SIEM credentials."""

    hostname: str = Field(default="")
    url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    api_key: Optional[SecretStr] = None
    client_id: Optional[str] = None
    client_secret: Optional[SecretStr] = None
    verify_ssl: bool = True
    enabled: bool = False

    def __init__(self, **data: Any) -> None:
        # Convert string password to SecretStr if needed
        if "password" in data and data["password"] and not isinstance(data["password"], SecretStr):
            data["password"] = SecretStr(data["password"])
        super().__init__(**data)
        if self.url and not self.hostname:
            self.hostname = self.url
        elif self.hostname and not self.url:
            self.url = self.hostname

    class Config:
        extra = "allow"


class BaseSIEMIntegration(ABC):
    """Abstract base class for SIEM integrations."""

    credentials_class: Type[SIEMCredentials] = SIEMCredentials
    integration_name: str = ""

    def __init__(self, credentials: Optional[SIEMCredentials] = None) -> None:
        if not self.integration_name:
            raise ValueError("Integration name is required in subclass")

        if credentials and not isinstance(credentials, self.credentials_class):
            # Try to convert the credentials to the correct type
            try:
                credentials = self.credentials_class(**credentials.model_dump())
            except Exception as e:
                raise ValueError(
                    f"Invalid credentials type. Expected {self.credentials_class.__name__}, got {type(credentials).__name__}: {str(e)}"
                )

        self.credentials = credentials or self.credentials_class()
        self._validate_credentials()
        self._initialize_client()

    @abstractmethod
    def _validate_credentials(self) -> None:
        """Validate the provided credentials."""
        pass

    @abstractmethod
    def _initialize_client(self) -> None:
        """Initialize the SIEM client."""
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if hasattr(self, "close"):
            await self.close()

    @abstractmethod
    async def close(self) -> None:
        """Close any open connections."""
        pass

    @abstractmethod
    async def execute_search(self, query: str, **kwargs) -> Dict[str, Any]:
        """Execute a search query in the SIEM."""
        pass

    @abstractmethod
    async def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Retrieve all enabled detection rules."""
        pass

    @abstractmethod
    async def create_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new detection rule."""
        pass

    @abstractmethod
    async def update_rule(self, rule_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing detection rule."""
        pass

    @abstractmethod
    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a detection rule."""
        pass

    @abstractmethod
    async def enable_rule(self, rule_id: str) -> bool:
        """Enable a detection rule."""
        pass

    @abstractmethod
    async def disable_rule(self, rule_id: str) -> bool:
        """Disable a detection rule."""
        pass

    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the integration service."""
        pass

    def update_rule_permissions(
        self, rule_name: str, sharing: str = "global", owner: str = "", perms_read: str = "*"
    ) -> None:
        """Update the permissions for a rule object, optional."""
        pass


class RuleRepository(ABC):
    """Abstract base class for rule storage"""

    @abstractmethod
    async def save_rules(self, rules: List[Dict[str, Any]], source: str) -> None:
        """Save rules with their source"""
        pass

    @abstractmethod
    async def load_rules(self, source: str) -> List[Dict[str, Any]]:
        """Load rules for a specific source"""
        pass

    @abstractmethod
    async def sync_rules(self, source: str, rules: List[Dict[str, Any]]) -> None:
        """Sync local rules with remote source"""
        pass


class WorkflowDefinition(BaseModel):
    """Define workflow structure"""

    name: str
    description: str
    steps: List[Dict[str, Any]]
    inputs: Dict[str, Any]
    outputs: Dict[str, Any]
