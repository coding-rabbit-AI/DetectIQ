import json
import os
from pathlib import Path
from typing import Any, Optional

import keyring
from pydantic import BaseModel, Field, SecretStr

from detectiq.core.integrations.elastic import ElasticCredentials
from detectiq.core.integrations.microsoft_xdr import MicrosoftXDRCredentials
from detectiq.core.integrations.splunk import SplunkCredentials
from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class IntegrationCredentials(BaseModel):
    """Base integration credentials model."""

    hostname: str = Field(default="")
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    tenant_id: Optional[str] = None
    cloud_id: Optional[str] = None
    verify_ssl: bool = True
    enabled: bool = False

    class Config:
        extra = "allow"


class Integrations(BaseModel):
    """Integration settings model."""

    splunk: Optional[SplunkCredentials] = None
    elastic: Optional[ElasticCredentials] = None
    microsoft_xdr: Optional[MicrosoftXDRCredentials] = None

    class Config:
        arbitrary_types_allowed = True


class DetectIQSettings(BaseModel):
    """Main settings model."""

    openai_api_key: str = Field(default="")
    rule_directories: dict = Field(
        default_factory=lambda: {
            "sigma": str(DEFAULT_DIRS.SIGMA_RULE_DIR),
            "yara": str(DEFAULT_DIRS.YARA_RULE_DIR),
            "snort": str(DEFAULT_DIRS.SNORT_RULE_DIR),
        }
    )
    vector_store_directories: dict = Field(
        default_factory=lambda: {
            "sigma": str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR),
            "yara": str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR),
            "snort": str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR),
        }
    )
    log_level: str = Field(default="INFO")
    model: str = Field(default="gpt-4o")
    integrations: Integrations = Field(default_factory=Integrations)

    @property
    def RULE_DIRS(self):
        return self.rule_directories

    @property
    def VECTOR_STORE_DIRS(self):
        return self.vector_store_directories

    class Config:
        extra = "allow"


class SettingsManager:
    APP_NAME = "detectiq"
    PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
    SETTINGS_FILE = PROJECT_ROOT / "settings.json"

    def __init__(self):
        logger.debug(f"Initializing SettingsManager. Settings file: {self.SETTINGS_FILE}")
        self.settings = self._load_settings()
        if not self.SETTINGS_FILE.exists():
            self.save_settings()

    def _load_settings(self) -> DetectIQSettings:
        settings_dict = self._get_default_settings()
        if self.SETTINGS_FILE.exists():
            self._update_from_file(settings_dict)
        return DetectIQSettings(**settings_dict)

    def _get_default_settings(self) -> dict:
        return {
            "openai_api_key": keyring.get_password(self.APP_NAME, "openai_api_key") or os.getenv("OPENAI_API_KEY", ""),
            "rule_directories": {
                "sigma": str(DEFAULT_DIRS.SIGMA_RULE_DIR),
                "yara": str(DEFAULT_DIRS.YARA_RULE_DIR),
                "snort": str(DEFAULT_DIRS.SNORT_RULE_DIR),
            },
            "vector_store_directories": {
                "sigma": str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR),
                "yara": str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR),
                "snort": str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR),
            },
            "log_level": os.getenv("DETECTIQ_LOG_LEVEL", "INFO"),
            "model": os.getenv("DETECTIQ_MODEL", "gpt-4"),
            "integrations": {},
        }

    def save_settings(self):
        settings_dict = self.settings.model_dump(exclude_none=True)
        with open(self.SETTINGS_FILE, "w") as f:
            json.dump(settings_dict, f, indent=2, default=str)

    def update_settings(self, **kwargs):
        settings_dict = self.settings.model_dump()
        settings_dict.update(kwargs)
        self.settings = DetectIQSettings(**settings_dict)
        self.save_settings()

    def _update_from_file(self, settings_dict: dict) -> None:
        with open(self.SETTINGS_FILE) as f:
            file_settings = json.load(f)
            settings_dict.update(file_settings)


async def get_settings(user: Optional[Any] = None) -> SettingsManager:
    """Get settings manager instance."""
    return SettingsManager()
